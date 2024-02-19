use clap::{crate_version, Arg, ArgAction, Command};
use drive_v3::{Credentials, Drive};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use libc::ENOENT;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH};

mod filetree;
use filetree::{FileNode, FileTree};

const TTL: Duration = Duration::from_secs(1); // 1 second

const HELLO_TXT_CONTENT: &str = "Hello World!\n";

const DEFAULT_PARENT: &str = "My Drive";

struct DriveFS {
    drive_client: Drive,
    file_tree: FileTree,
}

impl DriveFS {
    fn new(drive_client: Drive) -> DriveFS {
        let file_list = drive_client
            .files
            .list()
            .fields(
                "files(name, parents, id, size, createdTime, modifiedTime, trashed, owned_by_me)",
            ) // Set what fields will be returned
            .q("name = 'Test Folder' or name = 'Test Subfolder' or name = 'main.rs'")
            .execute()
            .unwrap();

        let files = file_list.files.unwrap();
        let mut parent_ids = HashSet::<String>::new();
        let mut id_name_map = HashMap::<String, String>::new();
        let mut file_tree_map = HashMap::<String, Vec<String>>::new();

        for file in &files {
            // file.created_time
            id_name_map.insert(file.id.clone().unwrap(), file.name.clone().unwrap());
            let file_parents = file.parents.clone().unwrap_or_default();
            assert!(file_parents.len() <= 1, "File has more than 1 parent");
            // println!(
            //     "File has name: {} with parents: {:?}",
            //     file.name.clone().unwrap(),
            //     &file_parents
            // );
            parent_ids.extend(file_parents);
        }

        let mut root_id = String::new();
        for parent in &parent_ids {
            if !id_name_map.contains_key(parent) {
                root_id = parent.clone();
                parent_ids.insert(root_id.clone());
                break;
            }
        }

        let root_node = FileNode::new(root_id, DEFAULT_PARENT.to_string());
        let mut file_tree = FileTree::new(0);
        file_tree.add_node(root_node, false);

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
                        let node = FileNode::new(file_id.clone(), file_name.clone());
                        this_node_index = file_tree.add_node(node, false);
                    }
                    if let Some(parent_node) = file_tree.find_node_mut(parent) {
                        println!(
                            "Appending child node with name: {} to existing parent with name: {}",
                            file_name,
                            id_name_map
                                .get(parent)
                                .unwrap_or(&DEFAULT_PARENT.to_string())
                        );
                        parent_node.add_child(this_node_index);
                    } else {
                        println!(
                            "Could not find existing parent with ID: {} and name: {}",
                            parent.clone(),
                            id_name_map
                                .get(parent)
                                .unwrap_or(&DEFAULT_PARENT.to_string())
                        );
                        println!(
                            "Creating new parent node with name: {} and child node: {}",
                            id_name_map
                                .get(parent)
                                .unwrap_or(&DEFAULT_PARENT.to_string()),
                            file_name,
                        );
                        let parent_name = id_name_map
                            .get(parent)
                            .unwrap_or(&DEFAULT_PARENT.to_string())
                            .clone();
                        let mut parent_node = FileNode::new(parent.clone(), parent_name);
                        parent_node.add_child(this_node_index);
                        file_tree.add_node(parent_node, false);
                    }
                } else if !this_node_exists {
                    let node = FileNode::new(file_id.clone(), file_name.clone());
                    file_tree.add_node(node, true);
                    println!(
                        "Added leaf node with ID: {} and name: {}",
                        file_id, file_name
                    );
                }
            }
        }
        println!("Found {} files and folders", file_tree.len());

        DriveFS {
            drive_client,
            file_tree,
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
                if child_node.name == name.to_str().unwrap() {
                    let mut file_type = FileType::RegularFile;
                    if child_node.children.len() > 0 {
                        file_type = FileType::Directory;
                    }
                    println!("Inode {} - Name {}", &child_index, &child_node.name);
                    let node_attr = FileAttr {
                        ino: (child_index + 1) as u64,
                        size: 1000,
                        blocks: 1,
                        atime: UNIX_EPOCH, // 1970-01-01 00:00:00
                        mtime: UNIX_EPOCH,
                        ctime: UNIX_EPOCH,
                        crtime: UNIX_EPOCH,
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
        if let Some(node) = self.file_tree.get_node_at((ino + 1) as usize) {
            let mut file_type = FileType::RegularFile;
            if node.children.len() > 0 {
                file_type = FileType::Directory;
            }
            let node_attr = FileAttr {
                ino: ino,
                size: 1000,
                blocks: 1,
                atime: UNIX_EPOCH, // 1970-01-01 00:00:00
                mtime: UNIX_EPOCH,
                ctime: UNIX_EPOCH,
                crtime: UNIX_EPOCH,
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
        _size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        if ino == 2 {
            reply.data(&HELLO_TXT_CONTENT.as_bytes()[offset as usize..]);
        } else {
            println!("read for {} ino, returning ENOENT", ino);
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
        println!("readdir for {} ino", ino);
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
                        child_node.name.clone(),
                    ))
                }
            }
        }

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            println!("Inode {} - Name {}", &entry.0, &entry.2);
            if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
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
