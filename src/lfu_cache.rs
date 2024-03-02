// LFU file based cache implementation adapted from https://github.com/NavyaZaveri/lfu-cache
// https://ieftimov.com/posts/when-why-least-frequently-used-cache-implementation-golang/
use linked_hash_set::LinkedHashSet;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use serde_json;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::{remove_file, write, File, OpenOptions};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    value: String,
    frequency: usize,
}

impl CacheEntry {
    fn increment_frequency(&mut self) {
        self.frequency += 1;
    }
}

#[derive(Debug)]
pub struct LFUFileCache {
    cache: HashMap<Arc<String>, CacheEntry>,
    frequency_bin: HashMap<usize, LinkedHashSet<Arc<String>>>,
    capacity: usize,
    min_frequency: usize,
    cache_dir: String,
}

impl LFUFileCache {
    pub fn with_capacity(cache_dir: String, capacity: usize) -> Result<LFUFileCache, &'static str> {
        if capacity == 0 {
            return Err("Capacity cannot be 0");
        }
        Ok(LFUFileCache {
            cache: HashMap::with_capacity(capacity),
            frequency_bin: HashMap::with_capacity(capacity),
            capacity,
            min_frequency: 0,
            cache_dir,
        })
    }

    pub fn save_state(&self) {
        let file_path = Path::new(&self.cache_dir).join("cache_state.json");
        serde_json::to_writer(File::create(file_path).unwrap(), &self).unwrap();
    }

    pub fn contains(&self, key: &String) -> bool {
        return self.cache.contains_key(key);
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn remove(&mut self, key: String) -> bool {
        let file_path = Path::new(&self.cache_dir).join(key.clone());
        let key_rc = Arc::new(key);
        if let Some(value_counter) = self.cache.get(&Arc::clone(&key_rc)) {
            let count = value_counter.frequency;
            self.frequency_bin
                .entry(count)
                .or_default()
                .remove(&Arc::clone(&key_rc));
            self.cache.remove(&key_rc);
            remove_file(file_path).unwrap();
        }
        return false;
    }

    /// Returns the value associated with the given key (if it still exists)
    /// Method marked as mutable because it internally updates the frequency of the accessed key
    pub fn get(&mut self, key: &String, read_only: bool) -> Option<File> {
        let file_path = Path::new(&self.cache_dir).join(key.clone());
        let key = self.cache.get_key_value(key).map(|(r, _)| Arc::clone(r))?;
        self.update_frequency_bin(Arc::clone(&key));
        if self.cache.contains_key(&key) {
            return Some(
                OpenOptions::new()
                    .read(true)
                    .write(!read_only)
                    .open(file_path)
                    .unwrap(),
            );
        }
        None
    }

    fn update_frequency_bin(&mut self, key: Arc<String>) {
        let entry = self.cache.get_mut(&key).unwrap();
        let bin = self.frequency_bin.get_mut(&entry.frequency).unwrap();
        bin.remove(&key);
        let freq = entry.frequency;
        entry.increment_frequency();
        if freq == self.min_frequency && bin.is_empty() {
            self.min_frequency += 1;
        }
        self.frequency_bin.entry(freq + 1).or_default().insert(key);
    }

    fn evict(&mut self) {
        let least_frequently_used_keys = self.frequency_bin.get_mut(&self.min_frequency).unwrap();
        let least_recently_used = least_frequently_used_keys.pop_front().unwrap();
        self.cache.remove(&least_recently_used);
        let id: &String = least_recently_used.borrow();
        let file_path = Path::new(&self.cache_dir).join(id);
        remove_file(file_path).unwrap();
    }

    // pub fn iter(&self) -> LfuIterator {
    //     LfuIterator {
    //         values: self.cache.iter(),
    //     }
    // }

    pub fn set(&mut self, key: String, data: Vec<u8>) {
        let key_copy = key.clone();
        let file_path = Path::new(&self.cache_dir).join(&key_copy);
        let key_rc = Arc::new(key);
        if self.cache.contains_key(&key_rc) {
            write(&file_path, data).unwrap();
            self.update_frequency_bin(Arc::clone(&key_rc));
            return;
        }
        if self.len() >= self.capacity {
            self.evict();
        }
        write(&file_path, data.clone()).unwrap();
        self.cache.insert(
            Arc::clone(&key_rc),
            CacheEntry {
                value: key_copy,
                frequency: 1,
            },
        );
        self.min_frequency = 1;
        self.frequency_bin
            .entry(self.min_frequency)
            .or_default()
            .insert(key_rc);
    }
}

impl Serialize for LFUFileCache {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("LFUFileCache", 5)?;

        let serializable_freq_bin: HashMap<&usize, Vec<&Arc<String>>> = self
            .frequency_bin
            .iter()
            .map(|item| (item.0, Vec::from_iter(item.1)))
            .collect();

        state.serialize_field("cache", &self.cache)?;
        state.serialize_field("frequency_bin", &serializable_freq_bin)?;
        state.serialize_field("capacity", &self.capacity)?;
        state.serialize_field("min_frequency", &self.min_frequency)?;
        state.serialize_field("cache_dir", &self.cache_dir)?;
        state.end()
    }
}
