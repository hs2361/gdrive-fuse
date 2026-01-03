use clap::{crate_version, Arg, ArgAction, Command};
use drive_v3::objects::File;
use drive_v3::{Credentials, Drive};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use libc::{ENOENT, ENOTSUP};
use std::cmp::min;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::fs::FileExt;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use std::{thread, vec};

mod file_downloader;
mod file_tree;
mod lfu_cache;
use file_downloader::{DownloadMessage, FileDownloader};
use file_tree::{topological_sort, FileMetadata, FileNode, FileTree, FileTreeWalker};
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

fn get_all_files(drive_client: &Drive, query: String) -> Vec<File> {
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

    while next_page_token.is_some() {
        let response = client
            .clone()
            .page_token(next_page_token.unwrap())
            // .q("name = 'Test Folder' or name = 'Test Subfolder' or name = 'main.rs'")
            .execute()
            .unwrap();
        next_page_token = response.next_page_token;
        file_list.extend(response.files.unwrap());
    }

    file_list
}

impl DriveFS {
    fn new(credentials: Credentials) -> DriveFS {
        let drive_client = Drive::new(&credentials);
        let query = String::from("not trashed");
        let files = get_all_files(&drive_client, query);

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
        file_tree.add_node(root_node, false);

        println!("API call returned {} files & folders", files.len());

        let mut id_parent_map: HashMap<String, String> = HashMap::with_capacity(files.len());
        let mut file_metadata_map: HashMap<String, FileMetadata> =
            HashMap::with_capacity(files.len());

        for file in files {
            id_parent_map.insert(
                file.id.clone().unwrap(),
                file.parents.clone().unwrap_or(vec![String::new()])[0].clone(),
            );

            file_metadata_map.insert(file.id.clone().unwrap(), FileMetadata::from(&file));
        }

        for file_id in topological_sort(&id_parent_map).unwrap().iter().rev() {
            if let Some(parent) = id_parent_map.get(file_id) {
                let parent_index;
                let node_index;

                if let Some(index) = file_tree.find_node_index(&parent) {
                    parent_index = index;
                } else {
                    println!("Parent node not found with ID {}!", &parent);
                    parent_index = 0;
                }

                if let Some(index) = file_tree.find_node_index(&file_id) {
                    node_index = index;
                } else {
                    let file_metadata;
                    if let Some(meta) = file_metadata_map.get(file_id) {
                        file_metadata = meta.clone()
                    } else {
                        println!("Metadata not found for file with ID {}", &parent);
                        file_metadata = FileMetadata::default(DEFAULT_PARENT.to_string());
                    }
                    let folder_node = FileNode::new(file_id.clone(), file_metadata);
                    node_index = file_tree.add_node(folder_node, false);
                }

                file_tree
                    .get_node_at_mut(parent_index)
                    .unwrap()
                    .add_child(node_index);
            } else {
                println!("Skipping creating root level folder: {}", file_id);
            }
        }

        println!("Found {} files and folders.", file_tree.len());

        let root = file_tree.get_node_at(0).unwrap();
        println!(
            "Root (ID {}, name {}) has {} child nodes",
            root.id,
            root.metadata.name,
            root.children.len()
        );

        let mut tree_walker = FileTreeWalker::new(Some(0));

        let mut file_count = 0;
        while let Some(_) = tree_walker.next(&file_tree) {
            file_count += 1;
        }
        println!("Walking file tree found {} files", file_count);

        let (req_tx, req_rx) = mpsc::channel();

        let file_cache = Arc::new(Mutex::new(
            LFUFileCache::with_capacity("/home/harsh/.drivefs/cache/".to_string(), CACHE_CAPACITY)
                .unwrap(),
        ));

        let file_cache_clone = Arc::clone(&file_cache);
        let logical_cores = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let file_downloader =
            FileDownloader::new(logical_cores * 2, &credentials, req_rx, file_cache_clone);

        DriveFS {
            credentials,
            google_workspace_file_size_map: HashMap::new(),
            file_tree,
            file_cache,
            file_downloader,
            request_channel: req_tx,
        }
    }

    fn start_bg_cache_state_worker(&self) {
        let file_cache_arc = Arc::clone(&self.file_cache);
        thread::spawn(move || loop {
            println!("Saving cache state");
            file_cache_arc.lock().unwrap().save_state();
            thread::sleep(Duration::from_secs(60));
        });
    }

    fn start_file_downloader_threads(&self) {
        self.file_downloader.start_workers();
    }
}

fn get_file_size(credentials: &Credentials, file_id: &String, mime_type: &String) -> Option<u64> {
    let base_url = format!(
        "https://www.googleapis.com/drive/v3/files/{}/export",
        file_id
    );

    let url =
        reqwest::Url::parse_with_params(base_url.as_str(), &[("mimeType", mime_type.as_str())])
            .unwrap();

    let res = reqwest::blocking::Client::new()
        .request(reqwest::Method::HEAD, url)
        .bearer_auth(credentials.get_access_token())
        .send()
        .unwrap();

    if !res.status().is_success() {
        return None;
    }

    res.headers()
        .get("Content-Length")
        .ok_or("No content length header set")
        .ok()?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()
}

impl Filesystem for DriveFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        println!(
            "lookup for {} parent with name {}",
            parent,
            name.to_str().unwrap()
        );

        if let Some(parent_node) = self.file_tree.get_node_at((parent - 1) as usize) {
            for &child_index in &parent_node.children {
                let child_node = self.file_tree.get_node_at(child_index).unwrap();
                if child_node.metadata.name == name.to_str().unwrap() {
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
                    // println!(
                    //     "Inode {} - Size {}",
                    //     &(child_index + 1),
                    //     &child_node.metadata.size
                    // );
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
        println!("Returning ENOENT for lookup req");
        reply.error(ENOENT)
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _: Option<u64>, reply: ReplyAttr) {
        println!("getattr for {} ino", ino);
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
        println!("Returning ENOENT for getattr req");
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
        println!(
            "read for {} ino with offset: {} and size {} from thread ID {:?}, PID: {}",
            ino,
            offset,
            size,
            std::thread::current().id(),
            std::process::id()
        );
        if let Some(node) = self.file_tree.get_node_at((ino - 1) as usize) {
            let file_cache_arc = Arc::clone(&self.file_cache);
            let mut file_cache = file_cache_arc.lock().unwrap();
            if let Some(cached_file) = file_cache.get(&node.id, true, offset, size) {
                println!("Cache hit for ID {}", node.id);
                let file_size = cached_file.metadata().unwrap().len();
                println!("Cached file size: {}, offset: {}", file_size, offset);
                let offset = offset as u64;
                let buf_size = min(size as usize, (file_size - offset) as usize);
                let mut buffer = vec![0; buf_size];
                cached_file.read_exact_at(&mut buffer, offset).unwrap();
                println!("returning {} bytes from cached file", buffer.len());
                reply.data(&buffer);
                return;
            }

            drop(file_cache);

            println!("Cache miss for ID {}", node.id);
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
            self.request_channel
                .send(DownloadMessage {
                    file_id: node.id.clone(),
                    offset,
                    size,
                    mime_type,
                    file_size,
                    response_channel: file_bytes_tx,
                })
                .unwrap();

            thread::spawn(move || match file_bytes_rx.recv() {
                Ok(bytes) => {
                    println!("Reply served {} bytes", bytes.len());
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
            println!("Returning ENOENT for read req");
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
        println!("readdir for {} ino with offset {}", ino, offset);
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
                    println!("Could not find child at tree index: {}", child_index);
                }
            }
        } else {
            println!("Returning ENOENT for readdir");
            return reply.error(ENOENT);
        }

        let num_entries = entries.len();
        println!("Total {} entries", num_entries);
        let mut count = 0;
        for (index, entry) in entries.iter().skip(offset).enumerate() {
            // println!(
            //     "Inode {} - Type {:?} - Offset {} - Name {}",
            //     &entry.0,
            //     &entry.1,
            //     (offset + index + 1),
            //     &entry.2
            // );

            count += 1;
            let buf_full = reply.add(
                entry.0,
                (offset + index + 1) as i64,
                entry.1,
                entry.2.clone(),
            );
            if buf_full {
                println!("Buffer full after returning {} entries", count,);
                println!("Last inode {}, offset {}", entry.0, (index + 1));
                break;
            }
        }

        reply.ok();
    }
}

fn main() {
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

    // env_logger::init();
    let mountpoint = matches.get_one::<String>("MOUNT_POINT").unwrap();

    // let client_secrets_path = "src/client_secret.json";
    let stored_cred_path = "src/credentials.json";

    // The OAuth scopes you need
    let scopes: [&'static str; 1] = ["https://www.googleapis.com/auth/drive"];

    // let mut credentials =
    //     Credentials::from_client_secrets_file(&client_secrets_path, &scopes).unwrap();

    // credentials.store(&stored_cred_path).unwrap();
    let mut credentials = Credentials::from_file(stored_cred_path, &scopes).unwrap();
    // println!("Access token: {}", credentials.get_access_token());

    // Refresh the credentials if they have expired
    if !credentials.are_valid() {
        credentials.refresh().unwrap();
        // Save them so we don't have to refresh them every time
        credentials.store(&stored_cred_path).unwrap();
    }

    let mut options = vec![MountOption::RO, MountOption::FSName("drivefs".to_string())];
    if matches.get_flag("auto-unmount") {
        options.push(MountOption::AutoUnmount);
    }

    if matches.get_flag("allow-root") {
        options.push(MountOption::AllowRoot);
    }

    let fs = DriveFS::new(credentials);
    fs.start_file_downloader_threads();
    fs.start_bg_cache_state_worker();

    fuser::mount2(fs, mountpoint, &options).unwrap();
}
