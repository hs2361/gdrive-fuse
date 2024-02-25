use clap::{crate_version, Arg, ArgAction, Command};
use drive_v3::objects::File;
use drive_v3::{Credentials, Drive};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use libc::{ENAVAIL, ENOENT};
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::fs::FileExt;
use std::time::{Duration, UNIX_EPOCH};
use std::vec;

mod filetree;
mod lfu_cache;
use filetree::{FileMetadata, FileNode, FileTree};
use lfu_cache::LFUFileCache;

const TTL: Duration = Duration::from_secs(60); // 1 second
const DEFAULT_PARENT: &str = "My Drive";
const MAX_PAGE_SIZE: i64 = 1000;
const CACHE_CAPACITY: usize = 5;

struct DriveFS {
    drive_client: Drive,
    file_tree: FileTree,
    file_cache: LFUFileCache,
}

fn get_all_files(drive_client: &Drive) -> Vec<File> {
    let mut next_page_token = Some(String::new());
    let mut file_list: Vec<File> = vec![];

    while next_page_token.is_some() {
        let response = drive_client
            .files
            .list()
            .include_items_from_all_drives(false)
            .page_token(next_page_token.unwrap())
            .page_size(MAX_PAGE_SIZE)
            .fields(
                "nextPageToken,files(name, parents, id, size, viewedByMeTime, createdTime, modifiedTime, trashed, owned_by_me)",
            ) // Set what fields will be returned
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
        let files = get_all_files(&drive_client);
        let mut parent_ids = HashSet::<String>::new();
        let mut parent_metadata_map = HashMap::<String, FileMetadata>::new();
        let mut id_name_map = HashMap::<String, String>::new();

        for file in &files {
            id_name_map.insert(file.id.clone().unwrap(), file.name.clone().unwrap());
            let file_parents = file.parents.clone().unwrap_or_default();
            assert!(file_parents.len() <= 1, "File has more than 1 parent");
            parent_ids.extend(file_parents);
        }

        // Hack to avoid implementing topological sort
        // ideally we should be traversing the nodes in topologically sorted order
        // so that parent directories get created first
        for file in &files {
            let file_id = &file.id.clone().unwrap();
            if parent_ids.contains(file_id) {
                parent_metadata_map.insert(file_id.to_string(), FileMetadata::from(file));
            }
        }

        let mut root_id = String::new();
        for parent in &parent_ids {
            if !id_name_map.contains_key(parent) {
                root_id = parent.clone();
                parent_ids.insert(root_id.clone());
                break;
            }
        }

        let root_metadata = FileMetadata {
            name: DEFAULT_PARENT.to_string(),
            size: 0,
            creation_time: UNIX_EPOCH,
            access_time: UNIX_EPOCH,
            last_modified_time: UNIX_EPOCH,
        };
        let root_node = FileNode::new(root_id, root_metadata);
        let mut file_tree = FileTree::new(0);
        file_tree.add_node(root_node, false);
        // println!("{}", &files.len());

        for file in &files {
            for parent in &file
                .parents
                .clone()
                .unwrap_or(vec![DEFAULT_PARENT.to_string()])
            {
                let file_id = &file.id.clone().unwrap();
                let file_name = &file.name.clone().unwrap();

                let mut this_node_exists = false;
                let mut this_node_index: usize = 0;
                if let Some(idx) = &file_tree.find_node_index(&file_id) {
                    this_node_index = *idx;
                    this_node_exists = true;
                }

                if parent_ids.contains(parent) {
                    if !this_node_exists {
                        let metadata = FileMetadata::from(file);
                        let node = FileNode::new(file_id.clone(), metadata);
                        this_node_index = file_tree.add_node(node, false);
                    }
                    if let Some(parent_node) = file_tree.find_node_mut(parent) {
                        // println!(
                        //     "Appending child node with name: {} to existing parent with name: {}",
                        //     file_name,
                        //     id_name_map
                        //         .get(parent)
                        //         .unwrap_or(&DEFAULT_PARENT.to_string())
                        // );
                        parent_node.add_child(this_node_index);
                    } else {
                        // println!(
                        //     "Could not find existing parent with ID: {} and name: {}",
                        //     parent.clone(),
                        //     id_name_map
                        //         .get(parent)
                        //         .unwrap_or(&DEFAULT_PARENT.to_string())
                        // );
                        // println!(
                        //     "Creating new parent node with name: {} and child node: {}",
                        //     id_name_map
                        //         .get(parent)
                        //         .unwrap_or(&DEFAULT_PARENT.to_string()),
                        //     file_name,
                        // );
                        let parent_name = id_name_map
                            .get(parent)
                            .unwrap_or(&DEFAULT_PARENT.to_string())
                            .clone();
                        let parent_metadata = parent_metadata_map
                            .get(parent)
                            .unwrap_or(&FileMetadata::default(parent_name))
                            .clone();
                        let mut parent_node = FileNode::new(parent.clone(), parent_metadata);
                        parent_node.add_child(this_node_index);
                        file_tree.add_node(parent_node, false);
                    }
                } else if !this_node_exists {
                    let metadata = FileMetadata::from(file);
                    let node = FileNode::new(file_id.clone(), metadata);
                    file_tree.add_node(node, true);
                    // println!(
                    //     "Added leaf node with ID: {} and name: {}",
                    //     file_id, file_name
                    // );
                }
            }
        }
        println!("Found {} files and folders", file_tree.len());

        DriveFS {
            drive_client,
            file_tree,
            file_cache: LFUFileCache::with_capacity(
                "/home/harsh/.drivefs/".to_string(),
                CACHE_CAPACITY,
            )
            .unwrap(),
        }
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
                    println!(
                        "Inode {} - Name {}",
                        &(child_index + 1),
                        &child_node.metadata.name
                    );
                    let node_attr = FileAttr {
                        ino: (child_index + 1) as u64,
                        size: child_node.metadata.size,
                        blocks: 1,
                        atime: child_node.metadata.access_time, // 1970-01-01 00:00:00
                        mtime: child_node.metadata.last_modified_time,
                        ctime: child_node.metadata.last_modified_time,
                        crtime: child_node.metadata.creation_time,
                        kind: file_type,
                        perm: 0o644,
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
        println!("getattr for {} ino", ino);
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
                perm: 0o644,
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
            if let Some(cached_file) = self.file_cache.get(&node.id, true) {
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
                let result = self.drive_client.files.get_media(node.id.clone()).execute();
                match result {
                    Ok(file_bytes) => {
                        self.file_cache.set(node.id.clone(), file_bytes.clone());
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
        let mut entries: Vec<(u64, FileType, String)> = vec![
            (1, FileType::Directory, String::from(".")),
            (1, FileType::Directory, String::from("..")),
        ];

        if let Some(node) = self.file_tree.get_node_at((ino - 1) as usize) {
            for child_index in &node.children {
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
                }
            }
        }

        for entry in entries.into_iter().skip(offset as usize) {
            // i + 1 means the index of the next entry
            println!("Inode {} - Name {}", &entry.0, &entry.2);
            if reply.add(entry.0, (entry.0 + 1) as i64, entry.1, entry.2) {
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
    fuser::mount2(DriveFS::new(drive), mountpoint, &options).unwrap();
}
