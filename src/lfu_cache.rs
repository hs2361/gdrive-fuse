// LFU file based cache implemenation adapted from https://github.com/NavyaZaveri/lfu-cache
use linked_hash_set::LinkedHashSet;
use std::borrow::Borrow;
use std::collections::hash_map::{IntoIter, Iter};
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::{remove_file, write, File, OpenOptions};
use std::ops::Index;
use std::path::Path;
use std::rc::Rc;

#[derive(Debug)]
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
    cache: HashMap<Rc<String>, CacheEntry>,
    frequency_bin: HashMap<usize, LinkedHashSet<Rc<String>>>,
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

    pub fn contains(&self, key: &String) -> bool {
        return self.cache.contains_key(key);
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn remove(&mut self, key: String) -> bool {
        let file_path = Path::new(&self.cache_dir).join(key.clone());
        let key_rc = Rc::new(key);
        if let Some(value_counter) = self.cache.get(&Rc::clone(&key_rc)) {
            let count = value_counter.frequency;
            self.frequency_bin
                .entry(count)
                .or_default()
                .remove(&Rc::clone(&key_rc));
            self.cache.remove(&key_rc);
            remove_file(file_path).unwrap();
        }
        return false;
    }

    /// Returns the value associated with the given key (if it still exists)
    /// Method marked as mutable because it internally updates the frequency of the accessed key
    pub fn get(&mut self, key: &String, read_only: bool) -> Option<File> {
        let file_path = Path::new(&self.cache_dir).join(key.clone());
        let key = self.cache.get_key_value(key).map(|(r, _)| Rc::clone(r))?;
        self.update_frequency_bin(Rc::clone(&key));
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

    fn update_frequency_bin(&mut self, key: Rc<String>) {
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

    pub fn iter(&self) -> LfuIterator {
        LfuIterator {
            values: self.cache.iter(),
        }
    }

    pub fn set(&mut self, key: String, data: Vec<u8>) {
        let key_copy = key.clone();
        let file_path = Path::new(&self.cache_dir).join(&key_copy);
        let key_rc = Rc::new(key);
        if self.cache.contains_key(&key_rc) {
            write(&file_path, data).unwrap();
            self.update_frequency_bin(Rc::clone(&key_rc));
            return;
        }
        if self.len() >= self.capacity {
            self.evict();
        }
        write(&file_path, data.clone()).unwrap();
        self.cache.insert(
            Rc::clone(&key_rc),
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

pub struct LfuIterator<'a> {
    values: Iter<'a, Rc<String>, CacheEntry>,
}

pub struct LfuConsumer {
    values: IntoIter<Rc<String>, CacheEntry>,
}

impl Iterator for LfuConsumer {
    type Item = (Rc<String>, String);

    fn next(&mut self) -> Option<Self::Item> {
        self.values.next().map(|(k, v)| (k, v.value))
    }
}

impl IntoIterator for LFUFileCache {
    type Item = (Rc<String>, String);
    type IntoIter = LfuConsumer;

    fn into_iter(self) -> Self::IntoIter {
        return LfuConsumer {
            values: self.cache.into_iter(),
        };
    }
}

impl<'a> Iterator for LfuIterator<'a> {
    type Item = (Rc<String>, &'a String);

    fn next(&mut self) -> Option<Self::Item> {
        self.values
            .next()
            .map(|(rc, vc)| (Rc::clone(rc), &vc.value))
    }
}

impl<'a> IntoIterator for &'a LFUFileCache {
    type Item = (Rc<String>, &'a String);

    type IntoIter = LfuIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        return self.iter();
    }
}

impl Index<String> for LFUFileCache {
    type Output = String;
    fn index(&self, index: String) -> &Self::Output {
        return self.cache.get(&Rc::new(index)).map(|x| &x.value).unwrap();
    }
}
