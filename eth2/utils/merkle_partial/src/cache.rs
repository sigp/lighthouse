use super::NodeIndex;
use std::collections::HashMap;

/// Stores the mapping of nodes to their chunks.
#[derive(Debug, Default)]
pub struct Cache {
    cache: HashMap<NodeIndex, Vec<u8>>,
}

impl Cache {
    /// Instantiate an empty `Cache`.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Gets a reference to the chunk coresponding to the node index.
    pub fn get(&self, index: NodeIndex) -> Option<&Vec<u8>> {
        self.cache.get(&index)
    }

    /// Sets the chunk for the node index and returns the old value.
    pub fn insert(&mut self, index: NodeIndex, chunk: Vec<u8>) -> Option<Vec<u8>> {
        self.cache.insert(index, chunk)
    }

    /// Retrieves a vector of set node indicies.
    pub fn nodes(&self) -> Vec<NodeIndex> {
        self.cache.keys().clone().map(|x| x.to_owned()).collect()
    }

    /// Returns `true` if the cache contains a chunk for the specified node index.
    pub fn contains_node(&self, index: NodeIndex) -> bool {
        self.cache.contains_key(&index)
    }
}

impl std::ops::Index<usize> for Cache {
    type Output = Vec<u8>;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index as u64).expect("node acessible by index")
    }
}
