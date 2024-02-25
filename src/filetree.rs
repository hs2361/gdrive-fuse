// Arena allocator based k-ary file tree implementation generalized from https://sachanganesh.com/programming/graph-tree-traversals-in-rust/
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::DateTime;
use drive_v3::objects::File;

fn rfc3339_to_system_time(date_time: &str) -> SystemTime {
    SystemTime::from(DateTime::parse_from_rfc3339(date_time).unwrap_or(DateTime::UNIX_EPOCH.into()))
}

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub name: String,
    pub size: u64,
    pub creation_time: SystemTime,
    pub access_time: SystemTime,
    pub last_modified_time: SystemTime,
}

impl FileMetadata {
    pub fn default(file_name: String) -> FileMetadata {
        FileMetadata {
            name: file_name,
            size: 0,
            creation_time: UNIX_EPOCH,
            access_time: UNIX_EPOCH,
            last_modified_time: UNIX_EPOCH,
        }
    }
}

impl From<&File> for FileMetadata {
    fn from(value: &File) -> Self {
        FileMetadata {
            name: value.name.clone().unwrap_or_default(),
            size: value
                .size
                .clone()
                .unwrap_or(String::from("0"))
                .parse::<u64>()
                .unwrap_or_default(),
            creation_time: rfc3339_to_system_time(
                value.created_time.clone().unwrap_or_default().as_str(),
            ),
            access_time: rfc3339_to_system_time(
                value.viewed_by_me_time.clone().unwrap_or_default().as_str(),
            ),
            last_modified_time: rfc3339_to_system_time(
                value.modified_time.clone().unwrap_or_default().as_str(),
            ),
        }
    }
}

#[derive(Debug)]
pub struct FileNode {
    pub id: String,
    pub metadata: FileMetadata,
    pub children: Vec<usize>,
}

impl FileNode {
    pub fn new(id: String, metadata: FileMetadata) -> Self {
        FileNode {
            id,
            metadata,
            children: vec![],
        }
    }

    pub fn add_child(&mut self, index: usize) {
        self.children.push(index);
    }

    // pub fn delete_child(&mut self, index: usize) {
    //     self.children.swap_remove(index);
    // }
}

pub struct FileTree {
    arena: Vec<Option<FileNode>>,
    root_node_index: usize,
}

impl FileTree {
    pub fn new(root_node_index: usize) -> Self {
        FileTree {
            arena: vec![],
            root_node_index,
        }
    }

    pub fn add_node(&mut self, node: FileNode, add_under_root: bool) -> usize {
        self.arena.push(Some(node));
        let child_node_index = self.arena.len() - 1;
        if add_under_root {
            self.get_node_at_mut(self.root_node_index)
                .unwrap()
                .add_child(child_node_index);
        }
        child_node_index
    }

    pub fn find_node_index(&self, id: &String) -> Option<usize> {
        for index in 0..self.arena.len() {
            if let Some(node) = &self.arena[index] {
                if node.id == *id {
                    return Some(index);
                }
            }
        }
        None
    }

    pub fn get_node_at(&self, index: usize) -> Option<&FileNode> {
        if let Some(node) = self.arena.get(index) {
            return node.as_ref();
        }
        None
    }

    pub fn get_node_at_mut(&mut self, index: usize) -> Option<&mut FileNode> {
        if let Some(node) = self.arena.get_mut(index) {
            return node.as_mut();
        }
        None
    }

    pub fn find_node(&self, id: &String) -> Option<&FileNode> {
        for node in &self.arena {
            if node.is_some() && node.as_ref().unwrap().id == *id {
                return node.as_ref();
            }
        }
        None
    }

    pub fn find_node_mut(&mut self, id: &String) -> Option<&mut FileNode> {
        for node in &mut self.arena {
            if node.is_some() && node.as_ref().unwrap().id == *id {
                return node.as_mut();
            }
        }
        None
    }

    pub fn delete_node_at(&mut self, index: usize) -> Option<FileNode> {
        match self.arena.get_mut(index) {
            Some(node) => node.take(),
            None => None,
        }
    }

    pub fn iter(&self, node_index: Option<usize>) -> FileTreeWalker {
        println!("{:?}", self.arena);
        if let Some(index) = node_index {
            FileTreeWalker::new(Some(index))
        } else {
            FileTreeWalker::new(Some(self.root_node_index.clone()))
        }
    }

    pub fn len(&self) -> usize {
        self.arena.len()
    }
}

pub struct FileTreeWalker {
    unvisited_node_indices: Vec<usize>,
}

impl FileTreeWalker {
    fn new(tree_root: Option<usize>) -> Self {
        match tree_root {
            Some(root) => FileTreeWalker {
                unvisited_node_indices: vec![root],
            },
            None => FileTreeWalker {
                unvisited_node_indices: vec![],
            },
        }
    }

    pub fn next(&mut self, file_tree: &FileTree) -> Option<usize> {
        while let Some(index) = self.unvisited_node_indices.pop() {
            if let Some(node) = file_tree.get_node_at(index) {
                self.unvisited_node_indices.extend(node.children.clone());
                return Some(index);
            }
        }
        None
    }
}
