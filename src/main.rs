use clap::{crate_version, Arg, ArgAction, Command};
// use drive_v3::objects::File;
use drive_v3::{Credentials, Drive};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use libc::ENOENT;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH};
mod filenode;

const TTL: Duration = Duration::from_secs(1); // 1 second

const HELLO_DIR_ATTR: FileAttr = FileAttr {
    ino: 1,
    size: 0,
    blocks: 0,
    atime: UNIX_EPOCH, // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
    blksize: 512,
};

const HELLO_TXT_CONTENT: &str = "Hello World!\n";

const HELLO_TXT_ATTR: FileAttr = FileAttr {
    ino: 2,
    size: 13,
    blocks: 1,
    atime: UNIX_EPOCH, // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::RegularFile,
    perm: 0o644,
    nlink: 1,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
    blksize: 512,
};

struct DriveFS {
    drive_client: Drive,
    // inode_id_map: HashMap<String, String>,
    file_tree_map: HashMap<String, Vec<String>>,
    directory_ids: HashSet<String>,
}

impl DriveFS {
    fn new(drive_client: Drive) -> DriveFS {
        let file_list = drive_client
            .files
            .list()
            .fields(
                "files(name, parents, id, size, createdTime, modifiedTime, trashed, owned_by_me)",
            ) // Set what fields will be returned
            // .q("name = 'Test Folder'")
            .execute()
            .unwrap();

        dbg!(&file_list);

        let files = file_list.files.unwrap();
        let mut parent_ids = HashSet::<String>::new();
        let mut id_name_map = HashMap::<String, String>::new();
        let mut file_tree_map = HashMap::<String, Vec<String>>::new();

        for file in &files {
            // file.created_time
            id_name_map.insert(file.id.clone().unwrap(), file.name.clone().unwrap());
            parent_ids.extend(file.parents.clone().unwrap_or_default());
        }
        let default_parent = "root".to_string();

        for file in &files {
            // match &file.parents.clone() {
            // Some(parents) => {
            for parent in &file.parents.clone().unwrap_or(vec![default_parent.clone()]) {
                let file_name = &file.name.clone().unwrap();
                if !parent_ids.contains(parent) {
                    file_tree_map.insert(file_name.clone(), Vec::<String>::new());
                } else {
                    let parent_name = id_name_map.get(parent).unwrap_or(&default_parent);
                    if file_tree_map.contains_key(parent_name) {
                        file_tree_map
                            .get_mut(parent_name)
                            .unwrap()
                            .push(file_name.clone());
                    } else {
                        file_tree_map.insert(parent_name.clone(), vec![file_name.clone()]);
                    }
                }
            }
            // }
            // None => {}
            // }
        }

        dbg!(&file_tree_map);
        DriveFS {
            drive_client,
            file_tree_map,
            directory_ids: parent_ids,
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

        if parent == 1 && name.to_str() == Some("hello.txt") {
            reply.entry(&TTL, &HELLO_TXT_ATTR, 0);
        } else {
            println!("Returning ENOENT for lookup req");
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        println!("getattr for {} ino", ino);
        match ino {
            1 => reply.attr(&TTL, &HELLO_DIR_ATTR),
            2 => reply.attr(&TTL, &HELLO_TXT_ATTR),
            _ => reply.error(ENOENT),
        }
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
        if ino != 1 {
            println!("readdir for {} ino, returning ENOENT", ino);
            reply.error(ENOENT);
            return;
        }

        println!("readdir for {} ino", ino);

        // self.drive.

        let mut entries: Vec<(u64, FileType, String)> = vec![
            (1, FileType::Directory, String::from(".")),
            (1, FileType::Directory, String::from("..")),
        ];

        entries.extend(
            self.file_tree_map
                .iter()
                .enumerate()
                .map(|(i, (file, children))| {
                    let mut file_type = FileType::RegularFile;
                    if children.len() > 0 {
                        file_type = FileType::Directory;
                    }
                    ((i + 2) as u64, file_type, file.clone())
                }),
        );

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
    }
}

fn main() {
    let matches = Command::new("hello")
        .version(crate_version!())
        .author("Christopher Berner")
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
