use clap::{crate_version, Arg, ArgAction, Command};
use drive_v3::objects::File;
use drive_v3::{Credentials, Drive};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use libc::{EINVAL, EIO, ENOENT, ENOTSUP};
use log;
use std::cmp::min;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{Error, ErrorKind};
use std::os::unix::fs::FileExt;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use std::{env, thread, u64, vec};

mod file_downloader;
mod file_tree;
mod lfu_cache;
use file_downloader::{DownloadMessage, FileDownloader};
use file_tree::{topological_sort, FileMetadata, FileNode, FileTree, FileTreeIterator};
use lfu_cache::LFUFileCache;

const TTL: Duration = Duration::from_secs(60); // 1 minute
const DEFAULT_PARENT: &str = "My Drive";
const DEFAULT_PERMS: u16 = 0o550; // r-xr-x---
const MAX_PAGE_SIZE: i64 = 1000;
const CACHE_CAPACITY: usize = 100;
const GOOGLE_WORKSPACE_MIME_PREFIX: &str = "application/vnd.google-apps.";
const FOLDER_MIME_TYPE: &str = "application/vnd.google-apps.folder";

// https://developers.google.com/drive/api/guides/mime-types
// https://developers.google.com/drive/api/guides/ref-export-formats
fn get_app_mime_type(app_name: &str) -> &'static str {
    match app_name {
        // "document" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "document" => "application/pdf",
        "spreadsheet" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "presentation" => {
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        }
        "drawing" => "image/svg+xml",
        "script+json" => "application/vnd.google-apps.script+json",
        &_ => "application/pdf",
    }
}

struct DriveFS {
    credentials: Credentials,
    google_workspace_file_size_map: HashMap<String, u64>,
    file_tree: FileTree,
    file_cache: Arc<Mutex<LFUFileCache>>,
    file_downloader: FileDownloader,
    request_channel: Sender<DownloadMessage>,
}

fn get_all_files(drive_client: &Drive, query: String) -> Result<Vec<File>, Error> {
    let mut next_page_token = Some(String::new());
    let mut file_list: Vec<File> = vec![];

    let client = drive_client
    .files
    .list()
    .include_items_from_all_drives(false)
    .page_size(MAX_PAGE_SIZE)
    .fields(
        "nextPageToken,files(name, parents, id, size, viewedByMeTime, createdTime, modifiedTime, ownedByMe, mimeType)",
    ) // Set what fields will be returned
    //TODO: exportLinks
    .q(query);

    while let Some(ref page_token) = next_page_token {
        if let Ok(response) = client.clone().page_token(page_token).execute() {
            next_page_token = response.next_page_token;
            if let Some(files) = response.files {
                file_list.extend(files);
            } else {
                break;
            }
        }
    }

    Ok(file_list)
}

impl DriveFS {
    fn new(credentials: Credentials) -> Result<DriveFS, Error> {
        let drive_client = Drive::new(&credentials);
        let query = String::from("not trashed");
        let files = get_all_files(&drive_client, query)?;

        if files.is_empty() {
            log::error!("Fetched zero files and directories");
        }

        let root_metadata = FileMetadata {
            name: DEFAULT_PARENT.to_string(),
            size: 0,
            creation_time: UNIX_EPOCH,
            access_time: UNIX_EPOCH,
            last_modified_time: UNIX_EPOCH,
            mime_type: FOLDER_MIME_TYPE.to_string(),
        };

        let root_node = FileNode::new(String::new(), root_metadata);
        let mut file_tree = FileTree::new(0);
        file_tree.add_node(root_node, false)?;

        log::info!("API call returned {} files & folders", files.len());

        let mut id_parent_map: HashMap<String, String> = HashMap::with_capacity(files.len());
        let mut file_metadata_map: HashMap<String, FileMetadata> =
            HashMap::with_capacity(files.len());

        for file in files {
            if let Some(ref file_id) = file.id {
                file_metadata_map.insert(file_id.clone(), FileMetadata::from(&file));
                let parent = &file.parents.unwrap_or(vec![String::new()])[0];
                id_parent_map.insert(file_id.to_string(), parent.to_string());
            } else {
                log::warn!("Skipping file without ID");
            }
        }

        for file_id in topological_sort(&id_parent_map)?.iter().rev() {
            if let Some(parent) = id_parent_map.get(file_id) {
                let parent_index;
                let node_index;

                if let Some(index) = file_tree.find_node_index(&parent) {
                    parent_index = index;
                } else {
                    log::error!("Parent node not found with ID {}!", &parent);
                    parent_index = 0;
                }

                if let Some(index) = file_tree.find_node_index(&file_id) {
                    node_index = index;
                } else {
                    let file_metadata;
                    if let Some(meta) = file_metadata_map.get(file_id) {
                        file_metadata = meta.clone();
                    } else {
                        log::warn!("Metadata not found for file with ID {parent}");
                        file_metadata = FileMetadata::default(DEFAULT_PARENT.to_string());
                    }
                    let folder_node = FileNode::new(file_id.clone(), file_metadata);
                    node_index = file_tree.add_node(folder_node, false)?;
                }

                if let Some(node) = file_tree.get_node_at_mut(parent_index) {
                    node.add_child(node_index);
                } else {
                    log::warn!("Could not find node with index {parent_index} in file tree");
                }
            } else {
                log::info!("Skipping creating root level folder: {file_id}");
            }
        }

        log::info!("Found {} files and folders.", file_tree.len());

        let root = file_tree
            .get_node_at(0)
            .expect("Failed to find root node in file tree");

        log::debug!(
            "Root (ID {}, name {}) has {} child nodes",
            root.id,
            root.metadata.name,
            root.children.len()
        );

        let mut tree_iterator = FileTreeIterator::new(Some(0));

        let mut file_count = 0;
        while tree_iterator.next(&file_tree).is_some() {
            file_count += 1;
        }
        log::debug!("Iterating over file tree found {} files", file_count);

        let (request_channel, req_rx) = mpsc::channel();

        let cache: LFUFileCache;

        if let Some(home_dir) = env::home_dir() {
            let cache_dir = home_dir.join(".drivefs/cache");
            match LFUFileCache::load_state(&cache_dir) {
                Ok(c) => cache = c,
                Err(err) => {
                    log::info!(
                        "Failed to load cache state from {:?}: {}",
                        cache_dir.to_str(),
                        err
                    );
                    cache = LFUFileCache::with_capacity(&cache_dir, CACHE_CAPACITY)?
                }
            }
        } else {
            return Err(Error::new(
                ErrorKind::NotFound,
                "Failed to get user home directory",
            ));
        }

        let file_cache = Arc::new(Mutex::new(cache));

        let file_cache_clone = Arc::clone(&file_cache);
        let logical_cores = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let file_downloader =
            FileDownloader::new(logical_cores * 2, &credentials, req_rx, file_cache_clone);

        Ok(DriveFS {
            credentials,
            google_workspace_file_size_map: HashMap::new(),
            file_tree,
            file_cache,
            file_downloader,
            request_channel,
        })
    }

    fn start_bg_cache_state_worker(&self) {
        let file_cache_arc = Arc::clone(&self.file_cache);
        thread::spawn(move || loop {
            log::debug!("Saving cache state");
            if let Ok(file_cache) = file_cache_arc.lock() {
                if let Err(err) = file_cache.save_state() {
                    log::error!("Failed to save file cache state: {err}");
                };
                drop(file_cache);
                thread::sleep(Duration::from_secs(60));
            } else {
                log::error!("Failed to acquire file cache lock");
            }
        });
    }

    fn start_file_downloader_threads(&self) {
        self.file_downloader.start_workers();
    }
}

fn get_file_size(
    credentials: &Credentials,
    file_id: &String,
    mime_type: &String,
) -> Result<u64, Box<dyn std::error::Error>> {
    let base_url = format!(
        "https://www.googleapis.com/drive/v3/files/{}/export",
        file_id
    );

    let url =
        reqwest::Url::parse_with_params(base_url.as_str(), &[("mimeType", mime_type.as_str())])?;

    let res = reqwest::blocking::Client::new()
        .request(reqwest::Method::HEAD, url)
        .bearer_auth(credentials.get_access_token())
        .send()?
        .error_for_status()?;

    let content_len = res.headers().get("Content-Length").ok_or(Error::new(
        ErrorKind::NotFound,
        "No content length header set",
    ))?;

    Ok(content_len.to_str()?.parse::<u64>()?)
}

impl Filesystem for DriveFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(name_str) = name.to_str() else {
            return reply.error(EINVAL);
        };

        if let Some(parent_node) = self.file_tree.get_node_at((parent - 1) as usize) {
            for &child_index in &parent_node.children {
                let Some(child_node) = self.file_tree.get_node_at(child_index) else {
                    continue;
                };

                if child_node.metadata.name == name_str {
                    let mut file_type = FileType::RegularFile;
                    let mime_type = child_node.metadata.mime_type.clone();
                    let mut file_size = child_node.metadata.size;

                    if mime_type.starts_with(GOOGLE_WORKSPACE_MIME_PREFIX) {
                        if mime_type == FOLDER_MIME_TYPE {
                            file_type = FileType::Directory;
                        } else {
                            let file_id = child_node.id.clone();

                            if let Some(size) = self.google_workspace_file_size_map.get(&file_id) {
                                file_size = *size;
                            } else {
                                let app_name = mime_type
                                    .split(GOOGLE_WORKSPACE_MIME_PREFIX)
                                    .collect::<Vec<&str>>()[1];
                                let export_mime_type = get_app_mime_type(app_name).to_string();
                                let exported_file_size =
                                    get_file_size(&self.credentials, &file_id, &export_mime_type)
                                        .unwrap_or(10_u64.pow(6));
                                self.google_workspace_file_size_map
                                    .insert(child_node.id.clone(), exported_file_size);
                                file_size = exported_file_size;
                            }
                        }
                    }
                    if child_node.metadata.mime_type == FOLDER_MIME_TYPE {
                        file_type = FileType::Directory;
                    }
                    let node_attr = FileAttr {
                        ino: (child_index + 1) as u64,
                        size: file_size,
                        blocks: 1,
                        atime: child_node.metadata.access_time, // 1970-01-01 00:00:00
                        mtime: child_node.metadata.last_modified_time,
                        ctime: child_node.metadata.last_modified_time,
                        crtime: child_node.metadata.creation_time,
                        kind: file_type,
                        perm: DEFAULT_PERMS,
                        nlink: 0,
                        uid: 1000,
                        gid: 1000,
                        rdev: 0,
                        flags: 0,
                        blksize: 512,
                    };
                    reply.entry(&TTL, &node_attr, 0);
                    return;
                }
            }
        }
        reply.error(ENOENT)
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _: Option<u64>, reply: ReplyAttr) {
        if let Some(node) = self.file_tree.get_node_at((ino - 1) as usize) {
            let mut file_type = FileType::RegularFile;
            let mime_type = node.metadata.mime_type.clone();
            let mut file_size = node.metadata.size;

            if mime_type.starts_with(GOOGLE_WORKSPACE_MIME_PREFIX) {
                if mime_type == FOLDER_MIME_TYPE {
                    file_type = FileType::Directory;
                } else {
                    let file_id = node.id.clone();

                    if let Some(size) = self.google_workspace_file_size_map.get(&file_id) {
                        file_size = *size;
                    } else {
                        let app_name = mime_type
                            .split(GOOGLE_WORKSPACE_MIME_PREFIX)
                            .collect::<Vec<&str>>()[1];
                        let export_mime_type = get_app_mime_type(app_name).to_string();
                        let exported_file_size =
                            get_file_size(&self.credentials, &file_id, &export_mime_type)
                                .unwrap_or(10_u64.pow(6));
                        self.google_workspace_file_size_map
                            .insert(node.id.clone(), exported_file_size);
                        file_size = exported_file_size;
                    }
                }
            }

            let node_attr = FileAttr {
                ino: ino,
                size: file_size,
                blocks: 1,
                atime: node.metadata.access_time, // 1970-01-01 00:00:00
                mtime: node.metadata.last_modified_time,
                ctime: node.metadata.last_modified_time,
                crtime: node.metadata.creation_time,
                kind: file_type,
                perm: DEFAULT_PERMS,
                nlink: 0,
                uid: 1000,
                gid: 1000,
                rdev: 0,
                flags: 0,
                blksize: 512,
            };
            reply.attr(&TTL, &node_attr);
            return;
        }
        reply.error(ENOENT)
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        log::debug!("Read request for inode {ino} at offset {offset} with size {size}");
        if let Some(node) = self.file_tree.get_node_at((ino - 1) as usize) {
            let file_cache_arc = Arc::clone(&self.file_cache);
            let Ok(mut file_cache) = file_cache_arc.lock() else {
                log::error!("Failed to acquire file cache lock");
                return reply.error(EIO);
            };

            log::debug!("Acquired file cache lock");
            if let Some(cached_file) = file_cache.get(&node.id, true, offset, size) {
                if let Ok(file_metadata) = cached_file.metadata() {
                    let file_size = file_metadata.len();
                    log::debug!("Cached file size: {}, offset: {}", file_size, offset);
                    let offset = offset as u64;
                    let buf_size = min(size as usize, file_size.saturating_sub(offset) as usize);
                    let mut buffer = vec![0; buf_size];
                    if let Err(err) = cached_file.read_exact_at(&mut buffer, offset) {
                        log::error!("Failed to read bytes from cached file: {err}");
                        file_cache.invalidate_cache_entry(&node.id);
                    } else {
                        return reply.data(&buffer);
                    }
                } else {
                    log::error!("Failed to fetch metadata for cache file {}", node.id);
                    file_cache.invalidate_cache_entry(&node.id);
                };
            }

            drop(file_cache);
            log::debug!("Dropped file cache lock");

            log::debug!("Cache miss for ID {}", node.id);
            let mut file_size = node.metadata.size;
            let mime_type = node.metadata.mime_type.clone();
            if mime_type.starts_with(GOOGLE_WORKSPACE_MIME_PREFIX) {
                let app_name = mime_type
                    .split(GOOGLE_WORKSPACE_MIME_PREFIX)
                    .collect::<Vec<&str>>()[1];

                let unsupported_apps = ["folder", "drive-sdk", "shortcut"];
                if unsupported_apps.contains(&app_name) {
                    reply.error(ENOTSUP);
                    return;
                } else if let Some(&size) = self.google_workspace_file_size_map.get(&node.id) {
                    file_size = size;
                }
            }

            let (file_bytes_tx, file_bytes_rx) = mpsc::channel();
            let msg = DownloadMessage {
                file_id: node.id.clone(),
                offset,
                size,
                mime_type,
                file_size,
                response_channel: file_bytes_tx,
            };

            if let Err(err) = self.request_channel.send(msg) {
                log::error!("Failed to send request to file downloader pool: {err}");
                return reply.error(EIO);
            }

            thread::spawn(move || match file_bytes_rx.recv() {
                Ok(bytes) => {
                    log::debug!("Reply served {} bytes", bytes.len());
                    if bytes.is_empty() {
                        reply.error(libc::EIO);
                    } else {
                        reply.data(&bytes);
                    }
                }
                Err(_) => {
                    reply.error(libc::EIO);
                }
            });
        } else {
            log::error!("Replying to read request with ENOENT");
            reply.error(ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        assert!(offset >= 0, "readdir called with negative offset");

        let mut entries: Vec<(u64, FileType, String)> = Vec::new();
        let offset = offset as usize;

        if let Some(node) = self.file_tree.get_node_at((ino - 1) as usize) {
            for child_index in node.children.iter() {
                if let Some(child_node) = self.file_tree.get_node_at(*child_index) {
                    let mut file_type = FileType::RegularFile;
                    if child_node.metadata.mime_type == FOLDER_MIME_TYPE {
                        file_type = FileType::Directory;
                    }
                    entries.push((
                        (*child_index + 1) as u64,
                        file_type,
                        child_node.metadata.name.clone(),
                    ))
                } else {
                    log::error!("Could not find child at tree index: {}", child_index);
                }
            }
        } else {
            return reply.error(ENOENT);
        }

        let num_entries = entries.len();
        log::debug!("Total {} entries", num_entries);
        let mut count = 0;
        for (index, entry) in entries.iter().skip(offset).enumerate() {
            count += 1;
            let buf_full = reply.add(
                entry.0,
                (offset + index + 1) as i64,
                entry.1,
                entry.2.clone(),
            );
            if buf_full {
                log::debug!("Buffer full after returning {} entries", count,);
                break;
            }
        }

        reply.ok();
    }
}

fn main() -> Result<(), Error> {
    let matches = Command::new("gdrivefs")
        .version(crate_version!())
        .author("Harsh Sharma")
        .arg(
            Arg::new("MOUNT_POINT")
                .required(true)
                .index(1)
                .help("Act as a client, and mount FUSE at given path"),
        )
        .arg(
            Arg::new("auto-unmount")
                .long("auto-unmount")
                .action(ArgAction::SetTrue)
                .help("Automatically unmount on process exit"),
        )
        .arg(
            Arg::new("allow-root")
                .long("allow-root")
                .action(ArgAction::SetTrue)
                .help("Allow root user to access filesystem"),
        )
        .get_matches();

    let mountpoint = matches
        .get_one::<String>("MOUNT_POINT")
        .expect("Argument MOUNT_POINT is required");

    // let client_secrets_path = "src/client_secret.json";
    let stored_cred_path = "src/credentials.json";

    let scopes: [&'static str; 1] = ["https://www.googleapis.com/auth/drive"];

    env_logger::init();

    // let mut credentials =
    //     Credentials::from_client_secrets_file(&client_secrets_path, &scopes).unwrap();

    // credentials.store(&stored_cred_path).unwrap();
    let mut credentials = Credentials::from_file(stored_cred_path, &scopes)
        .expect(format!("Failed to load credentials from file {}", stored_cred_path).as_str());

    // Refresh the credentials if they have expired
    if !credentials.are_valid() {
        credentials
            .refresh()
            .expect("Failed to refresh credentials");

        // Save them so we don't have to refresh them every time
        if let Err(err) = credentials.store(&stored_cred_path) {
            log::warn!("Failed to save refreshed credentials at {stored_cred_path}: {err}");
        }
    }

    let mut options = vec![MountOption::RO, MountOption::FSName("drivefs".to_string())];
    if matches.get_flag("auto-unmount") {
        options.push(MountOption::AutoUnmount);
    }

    if matches.get_flag("allow-root") {
        options.push(MountOption::AllowRoot);
    }

    let fs = DriveFS::new(credentials)?;
    fs.start_file_downloader_threads();
    fs.start_bg_cache_state_worker();

    fuser::mount2(fs, mountpoint, &options)
}
