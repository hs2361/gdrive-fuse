// Arena allocator based k-ary file tree implementation generalized from https://sachanganesh.com/programming/graph-tree-traversals-in-rust/
#[derive(Debug)]
pub struct FileNode {
    id: String,
    pub name: String,
    pub children: Vec<usize>,
}

impl FileNode {
    pub fn new(id: String, name: String) -> Self {
        FileNode {
            id,
            name,
            children: vec![],
        }
    }

    pub fn add_child(&mut self, index: usize) {
        self.children.push(index);
    }

    pub fn delete_child(&mut self, index: usize) {
        self.children.swap_remove(index);
    }
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
