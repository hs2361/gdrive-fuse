// Arena allocator based k-ary file tree implementation
// generalized from https://sachanganesh.com/programming/graph-tree-traversals-in-rust/
use std::{
    collections::{HashMap, VecDeque},
    io::{Error, ErrorKind},
    time::{SystemTime, UNIX_EPOCH},
};

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
    pub mime_type: String,
}

impl FileMetadata {
    pub fn default(file_name: String) -> FileMetadata {
        FileMetadata {
            name: file_name,
            size: 0,
            creation_time: UNIX_EPOCH,
            access_time: UNIX_EPOCH,
            last_modified_time: UNIX_EPOCH,
            mime_type: "text/plain".to_string(),
        }
    }
}

impl From<&File> for FileMetadata {
    fn from(file: &File) -> Self {
        FileMetadata {
            name: file.name.clone().unwrap_or_default().replace("/", "⁄"),
            size: file
                .size
                .clone()
                .unwrap_or(String::from("0"))
                .parse::<u64>()
                .unwrap_or_default(),
            creation_time: rfc3339_to_system_time(
                file.created_time.clone().unwrap_or_default().as_str(),
            ),
            access_time: rfc3339_to_system_time(
                file.viewed_by_me_time.clone().unwrap_or_default().as_str(),
            ),
            last_modified_time: rfc3339_to_system_time(
                file.modified_time.clone().unwrap_or_default().as_str(),
            ),
            mime_type: file.mime_type.clone().unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone)]
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
}

pub struct FileTree {
    arena: Vec<Option<FileNode>>,
    root_node_index: usize,
    id_index_map: HashMap<String, usize>,
}

impl FileTree {
    pub fn new(root_node_index: usize) -> Self {
        FileTree {
            arena: vec![],
            root_node_index,
            id_index_map: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: FileNode, add_under_root: bool) -> Result<usize, Error> {
        let node_id = node.id.clone();
        self.arena.push(Some(node));
        let child_node_index = self.arena.len() - 1;
        if add_under_root {
            if let Some(node) = self.get_node_at_mut(self.root_node_index) {
                node.add_child(child_node_index);
            } else {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "Failed to find root node in file tree",
                ));
            }
        }

        self.id_index_map.insert(node_id, child_node_index);
        Ok(child_node_index)
    }

    pub fn find_node_index(&self, id: &str) -> Option<usize> {
        if let Some(index) = self.id_index_map.get(id) {
            return Some(*index);
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

    pub fn len(&self) -> usize {
        self.arena.len()
    }

    pub fn num_files(&self) -> usize {
        let mut unvisited_node_indices = vec![self.root_node_index];
        let mut file_count = 0;
        while let Some(index) = unvisited_node_indices.pop() {
            if let Some(node) = self.get_node_at(index) {
                unvisited_node_indices.extend(node.children.clone());
                file_count += 1;
            }
        }
        file_count
    }
}

// Kahn's algorithm for topologically sorting a DAG
// https://www.geeksforgeeks.org/topological-sorting-indegree-based-solution/
pub fn topological_sort(id_parent_map: &HashMap<String, String>) -> Result<Vec<String>, Error> {
    let mut in_degree_map: HashMap<String, usize> = HashMap::new();

    // compute in-degrees of all vertices
    for parent in id_parent_map.values() {
        *in_degree_map.entry(parent.clone()).or_default() += 1;
    }

    // find all vertices that have no incoming edges
    let mut zero_degree_vertices: VecDeque<String> = VecDeque::new();
    for id in id_parent_map.keys() {
        if *in_degree_map.entry(id.clone()).or_default() == 0 {
            zero_degree_vertices.push_back(id.clone());
        }
    }

    // initialize result vector
    let mut topo_sorted: Vec<String> = Vec::with_capacity(id_parent_map.len());

    // keep popping vertices from the zero in-degree queue until empty
    while !zero_degree_vertices.is_empty() {
        let Some(node) = zero_degree_vertices.pop_front() else {
            return Err(Error::new(
                ErrorKind::NotFound,
                "No zero in-degree vertices found",
            ));
        };

        // This vertex is in topologically sorted order so add it to the result vector
        topo_sorted.push(node.clone());

        // We've popped the vertex off, so decrement the in-degree of its parent vertices
        if let Some(parent) = id_parent_map.get(&node) {
            if let Some(degree) = in_degree_map.get_mut(parent) {
                *degree -= 1;

                // If the parent vertex has no incoming edges, push it into the queue
                if *degree == 0 {
                    zero_degree_vertices.push_back(parent.clone());
                }
            }
        }
    }

    // The result vector should have all the vertices
    if topo_sorted.len() < id_parent_map.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Cycle detected in graph, not a DAG",
        ));
    }

    // Return the result vector
    Ok(topo_sorted)
}
