use clap::{crate_version, Arg, ArgAction, Command};
use drive_v3::objects::File;
use drive_v3::{Credentials, Drive, Error};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use libc::{ENAVAIL, ENOENT, ENOTSUP};
use std::cmp::min;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{thread, vec};

mod filetree;
mod lfu_cache;
use filetree::{FileMetadata, FileNode, FileTree, FileTreeWalker};
use lfu_cache::LFUFileCache;

const TTL: Duration = Duration::from_secs(60); // 1 minute
const DEFAULT_PARENT: &str = "My Drive";
const DEFAULT_PERMS: u16 = 0o550; // r-xr-x---
const MAX_PAGE_SIZE: i64 = 1000;
const CACHE_CAPACITY: usize = 5;
const GOOGLE_WORKSPACE_MIME_PREFIX: &str = "application/vnd.google-apps.";

fn get_app_mime_type(app_name: &str) -> &'static str {
    match app_name {
        "document" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
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
    drive_client: Drive,
    file_tree: FileTree,
    file_cache: Arc<Mutex<LFUFileCache>>,
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
    fn new(drive_client: Drive) -> DriveFS {
        let mut query =
            String::from("mimeType = 'application/vnd.google-apps.folder' and not trashed");
        let folders = get_all_files(&drive_client, query);

        let root_metadata = FileMetadata::default(DEFAULT_PARENT.to_string());
        let root_node = FileNode::new(String::new(), root_metadata);
        let mut file_tree = FileTree::new(0);
        file_tree.add_node(root_node, false);

        let folder_metadata_map: HashMap<String, FileMetadata> = folders
            .iter()
            .map(|folder| (folder.id.clone().unwrap(), FileMetadata::from(folder)))
            .collect();

        // FIX: Some files don't have a parent?
        for folder in &folders {
            let folder_id = folder.id.clone().unwrap();
            let parent = folder.parents.clone().unwrap_or(vec![String::new()])[0].clone();

            let parent_index;
            let node_index;

            if let Some(index) = file_tree.find_node_index(&parent) {
                parent_index = index;
            } else {
                let parent_metadata;
                if let Some(meta) = folder_metadata_map.get(&parent) {
                    parent_metadata = meta.clone()
                } else {
                    println!("Metadata not found for parent with ID {}", &parent);
                    parent_metadata = FileMetadata::default(DEFAULT_PARENT.to_string());
                }
                let parent_node = FileNode::new(parent, parent_metadata);
                parent_index = file_tree.add_node(parent_node, false);
            }

            if let Some(index) = file_tree.find_node_index(&folder_id) {
                node_index = index;
            } else {
                let folder_metadata = FileMetadata::from(folder);
                let folder_node = FileNode::new(folder_id, folder_metadata);
                node_index = file_tree.add_node(folder_node, false);
            }

            file_tree
                .get_node_at_mut(parent_index)
                .unwrap()
                .add_child(node_index);
        }

        query = String::from("mimeType != 'application/vnd.google-apps.folder' and not trashed");
        let files = get_all_files(&drive_client, query);

        for file in &files {
            let file_id = file.id.clone().unwrap();
            let parent = file.parents.clone().unwrap_or(vec![String::new()])[0].clone();
            let node_index;

            let parent_index = file_tree.find_node_index(&parent).unwrap_or(0);

            if let Some(index) = file_tree.find_node_index(&file_id) {
                println!(
                    "Node {} with name {} already exists. This shouldn't happen",
                    &file_id,
                    file.name.clone().unwrap()
                );
                node_index = index;
            } else {
                let metadata = FileMetadata::from(file);
                let folder_node = FileNode::new(file_id, metadata);
                node_index = file_tree.add_node(folder_node, false);
            }
            file_tree
                .get_node_at_mut(parent_index)
                .unwrap()
                .add_child(node_index);
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

        DriveFS {
            drive_client,
            file_tree,
            file_cache: Arc::new(Mutex::new(
                LFUFileCache::with_capacity(
                    "/home/harsh/.drivefs/cache/".to_string(),
                    CACHE_CAPACITY,
                )
                .unwrap(),
            )),
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
                    if child_node.children.len() > 0 {
                        file_type = FileType::Directory;
                    }
                    // println!(
                    //     "Inode {} - Name {}",
                    //     &(child_index + 1),
                    //     &child_node.metadata.name
                    // );
                    let node_attr = FileAttr {
                        ino: (child_index + 1) as u64,
                        size: child_node.metadata.size,
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

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        // println!("getattr for {} ino", ino);
        if let Some(node) = self.file_tree.get_node_at((ino - 1) as usize) {
            let mut file_type = FileType::RegularFile;
            if node.children.len() > 0 {
                file_type = FileType::Directory;
            }
            let node_attr = FileAttr {
                ino: ino,
                size: node.metadata.size,
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
            "read for {} ino with offset: {} and size {}",
            ino, offset, size
        );
        if let Some(node) = self.file_tree.get_node_at((ino - 1) as usize) {
            let file_cache_arc = Arc::clone(&self.file_cache);
            let mut file_cache = file_cache_arc.lock().unwrap();
            if let Some(cached_file) = file_cache.get(&node.id, true) {
                println!("Cache hit for ID {}", node.id);
                let file_size = cached_file.metadata().unwrap().len();
                let offset = offset as u64;
                let buf_size = min(size as usize, (file_size - offset) as usize);
                let mut buffer = vec![0; buf_size];
                cached_file.read_exact_at(&mut buffer, offset).unwrap();
                reply.data(&buffer);
                return;
            } else {
                println!("Cache miss for ID {}", node.id);
                let download_result: Result<Vec<u8>, Error>;
                if node
                    .metadata
                    .mime_type
                    .starts_with(GOOGLE_WORKSPACE_MIME_PREFIX)
                {
                    let app_name = node
                        .metadata
                        .mime_type
                        .split(GOOGLE_WORKSPACE_MIME_PREFIX)
                        .collect::<Vec<&str>>()[1];

                    let unsupported_apps = ["folder", "drive-sdk", "shortcut"];
                    if unsupported_apps.contains(&app_name) {
                        reply.error(ENOTSUP);
                        return;
                    } else {
                        let mime_type = get_app_mime_type(app_name);
                        download_result = self
                            .drive_client
                            .files
                            .export(&node.id)
                            .mime_type(mime_type)
                            .execute();
                    }
                } else {
                    download_result = self.drive_client.files.get_media(&node.id).execute();
                }

                match download_result {
                    Ok(file_bytes) => {
                        file_cache.set(node.id.clone(), file_bytes.clone());
                        println!("Inserted cache entry for {}", node.id);
                        let start = offset as usize;
                        let end = min(start + 1 + size as usize, file_bytes.len());
                        reply.data(&file_bytes[start..end]);
                    }
                    Err(err) => {
                        println!("Failed to download file: {}", err.to_string());
                        reply.error(ENAVAIL);
                    }
                }
            }
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
                    if child_node.children.len() > 0 {
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

    let stored_cred_path = "src/credentials.json";

    // The OAuth scopes you need
    let scopes: [&'static str; 1] = ["https://www.googleapis.com/auth/drive"];

    // let mut credentials =
    //     Credentials::from_client_secrets_file(&client_secrets_path, &scopes).unwrap();

    let mut credentials = Credentials::from_file(stored_cred_path, &scopes).unwrap();

    // Refresh the credentials if they have expired
    if !credentials.are_valid() {
        credentials.refresh().unwrap();
    }

    // Save them so we don't have to refresh them every time
    credentials.store(&stored_cred_path).unwrap();

    let drive = Drive::new(&credentials);

    let mut options = vec![MountOption::RO, MountOption::FSName("drivefs".to_string())];
    if matches.get_flag("auto-unmount") {
        options.push(MountOption::AutoUnmount);
    }
    if matches.get_flag("allow-root") {
        options.push(MountOption::AllowRoot);
    }

    let fs = DriveFS::new(drive);
    fs.start_bg_cache_state_worker();
    fuser::mount2(fs, mountpoint, &options).unwrap();
}
