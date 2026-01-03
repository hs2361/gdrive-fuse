// LFU file based cache implementation adapted from https://github.com/NavyaZaveri/lfu-cache
// https://ieftimov.com/posts/when-why-least-frequently-used-cache-implementation-golang/
use linked_hash_set::LinkedHashSet;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::fs::{self, remove_file, File, OpenOptions};
use std::io::{BufReader, Error, ErrorKind, Write};
use std::path::{Path, PathBuf};
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
    cache_dir: PathBuf,
}

impl LFUFileCache {
    pub fn with_capacity(cache_dir: &PathBuf, capacity: usize) -> Result<LFUFileCache, Error> {
        if capacity == 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "Capacity cannot be 0"));
        }

        if !cache_dir.is_dir() {
            fs::create_dir_all(cache_dir)?;
        }

        Ok(LFUFileCache {
            cache: HashMap::with_capacity(capacity),
            frequency_bin: HashMap::with_capacity(capacity),
            capacity,
            min_frequency: 0,
            cache_dir: cache_dir.to_path_buf(),
        })
    }

    pub fn load_state(cache_dir: &PathBuf) -> Result<LFUFileCache, Error> {
        let file_path = Path::new(&cache_dir).join("cache_state.json");
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        // Note: We need to explicitly tell serde what type we are expecting
        let cache: LFUFileCache = serde_json::from_reader(reader)?;
        Ok(cache)
    }

    pub fn save_state(&self) -> Result<(), Error> {
        let file_path = Path::new(&self.cache_dir).join("cache_state.json");
        Ok(serde_json::to_writer(File::create(file_path)?, &self)?)
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn invalidate_cache_entry(&mut self, key: &String) {
        let file_path = Path::new(&self.cache_dir).join(key.clone());
        let Some(key) = self.cache.get_key_value(key).map(|(r, _)| Arc::clone(r)) else {
            log::warn!("Key {key} does not exist in the cache");
            return;
        };

        let path = file_path.to_str().unwrap_or_default();

        if let Err(err) = fs::remove_file(&file_path) {
            log::error!("Failed to delete cache file at path {path}: {err}")
        }

        if self.cache.remove(&key).is_none() {
            log::error!("Failed to delete cache entry for key {key}");
        }
    }

    /// Returns the value associated with the given key (if it still exists)
    /// Method marked as mutable because it internally updates the frequency of the accessed key
    pub fn get(&mut self, key: &String, read_only: bool, start: i64, size: u32) -> Option<File> {
        let file_path = Path::new(&self.cache_dir).join(key.clone());
        let key = self.cache.get_key_value(key).map(|(r, _)| Arc::clone(r))?;
        self.update_frequency_bin(Arc::clone(&key))?;
        if self.cache.contains_key(&key) {
            let Ok(file) = OpenOptions::new()
                .read(true)
                .write(!read_only)
                .open(&file_path)
            else {
                self.invalidate_cache_entry(&key);
                return None;
            };

            if let Ok(metadata) = file.metadata() {
                let file_size = metadata.len();
                let chunk_end = start as u64 + size as u64;
                if file_size >= chunk_end {
                    return Some(file);
                }
            } else {
                self.invalidate_cache_entry(&key);
            }
        }

        None
    }

    fn update_frequency_bin(&mut self, key: Arc<String>) -> Option<()> {
        let entry = self.cache.get_mut(&key)?;
        let bin = self.frequency_bin.get_mut(&entry.frequency)?;
        bin.remove(&key);
        let freq = entry.frequency;
        entry.increment_frequency();
        if freq == self.min_frequency && bin.is_empty() {
            self.min_frequency += 1;
        }
        self.frequency_bin.entry(freq + 1).or_default().insert(key);
        Some(())
    }

    fn evict(&mut self) -> Option<()> {
        let least_frequently_used_keys = self.frequency_bin.get_mut(&self.min_frequency)?;
        let least_recently_used = least_frequently_used_keys.pop_front()?;
        self.cache.remove(&least_recently_used);
        let id: &String = least_recently_used.borrow();
        let file_path = Path::new(&self.cache_dir).join(id);
        if let Err(err) = remove_file(&file_path) {
            log::error!(
                "Failed to delete file at path {}: {err}",
                &file_path.to_str().unwrap_or_default()
            );
            return None;
        }
        Some(())
    }

    pub fn set(&mut self, key: String, data: &Vec<u8>) -> Result<(), Error> {
        let key_copy = key.clone();
        let file_path = Path::new(&self.cache_dir).join(&key_copy);
        let mut fh = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)?;

        fh.write_all(&data)?;

        let key_rc = Arc::new(key);
        let key_copy = key_rc.clone();
        if self.cache.contains_key(&key_rc) {
            if self.update_frequency_bin(Arc::clone(&key_rc)).is_none() {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!("Failed to update frequency bin for key {}", key_copy),
                ));
            }
        }

        if self.len() >= self.capacity {
            if self.evict().is_none() {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!("Failed to evict cache entry for key {}", key_copy),
                ));
            }
        }

        self.cache.insert(
            Arc::clone(&key_rc),
            CacheEntry {
                value: key_copy.to_string(),
                frequency: 1,
            },
        );

        self.min_frequency = 1;
        self.frequency_bin
            .entry(self.min_frequency)
            .or_default()
            .insert(key_rc);

        Ok(())
    }
}

impl Serialize for LFUFileCache {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("LFUFileCache", 5)?;

        // Convert HashMap<usize, LinkedHashSet<Arc<String>>> to HashMap<usize, Vec<Arc<String>>>
        // for serialization, as LinkedHashSet doesn't implement the Serialize trait itself
        let serializable_freq_bin: HashMap<&usize, Vec<&Arc<String>>> = self
            .frequency_bin
            .iter()
            .map(|(k, v)| (k, v.iter().collect()))
            .collect();

        state.serialize_field("cache", &self.cache)?;
        state.serialize_field("frequency_bin", &serializable_freq_bin)?;
        state.serialize_field("capacity", &self.capacity)?;
        state.serialize_field("min_frequency", &self.min_frequency)?;
        state.serialize_field("cache_dir", &self.cache_dir)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for LFUFileCache {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum CacheField {
            Cache,
            FrequencyBin,
            Capacity,
            MinFrequency,
            CacheDir,
        }

        impl<'de> Deserialize<'de> for CacheField {
            fn deserialize<D>(deserializer: D) -> Result<CacheField, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = CacheField;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str(
                            "`cache`, `frequency_bin`, `capacity`, `min_frequency`, or `cache_dir`",
                        )
                    }

                    fn visit_str<E>(self, value: &str) -> Result<CacheField, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "cache" => Ok(CacheField::Cache),
                            "frequency_bin" => Ok(CacheField::FrequencyBin),
                            "capacity" => Ok(CacheField::Capacity),
                            "min_frequency" => Ok(CacheField::MinFrequency),
                            "cache_dir" => Ok(CacheField::CacheDir),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct LFUFileCacheVisitor;

        impl<'de> Visitor<'de> for LFUFileCacheVisitor {
            type Value = LFUFileCache;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct LFUFileCache")
            }

            fn visit_map<V>(self, mut map: V) -> Result<LFUFileCache, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut cache: Option<HashMap<Arc<String>, CacheEntry>> = None;
                let mut frequency_bin_vec: Option<HashMap<usize, Vec<String>>> = None; // Intermediate storage
                let mut capacity = None;
                let mut min_frequency = None;
                let mut cache_dir = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        CacheField::Cache => {
                            if cache.is_some() {
                                return Err(de::Error::duplicate_field("cache"));
                            }
                            cache = Some(map.next_value()?);
                        }
                        CacheField::FrequencyBin => {
                            if frequency_bin_vec.is_some() {
                                return Err(de::Error::duplicate_field("frequency_bin"));
                            }
                            // Deserialize as Vec<String> because Arc<String> deserialization
                            // might not automatically dedup with the keys in 'cache' yet.
                            frequency_bin_vec = Some(map.next_value()?);
                        }
                        CacheField::Capacity => {
                            if capacity.is_some() {
                                return Err(de::Error::duplicate_field("capacity"));
                            }
                            capacity = Some(map.next_value()?);
                        }
                        CacheField::MinFrequency => {
                            if min_frequency.is_some() {
                                return Err(de::Error::duplicate_field("min_frequency"));
                            }
                            min_frequency = Some(map.next_value()?);
                        }
                        CacheField::CacheDir => {
                            if cache_dir.is_some() {
                                return Err(de::Error::duplicate_field("cache_dir"));
                            }
                            cache_dir = Some(map.next_value()?);
                        }
                    }
                }

                let cache = cache.ok_or_else(|| de::Error::missing_field("cache"))?;
                let frequency_bin_vec =
                    frequency_bin_vec.ok_or_else(|| de::Error::missing_field("frequency_bin"))?;
                let capacity = capacity.ok_or_else(|| de::Error::missing_field("capacity"))?;
                let min_frequency =
                    min_frequency.ok_or_else(|| de::Error::missing_field("min_frequency"))?;
                let cache_dir = cache_dir.ok_or_else(|| de::Error::missing_field("cache_dir"))?;

                // Reconstruct LinkedHashSet and ensure Arcs point to the same memory
                // The 'cache' map already holds Arc<String>. We want to reuse those Arcs
                // in the frequency_bin so we don't have duplicate strings in memory.
                let mut frequency_bin: HashMap<usize, LinkedHashSet<Arc<String>>> = HashMap::new();

                for (freq, keys) in frequency_bin_vec {
                    let mut set = LinkedHashSet::new();
                    for key_str in keys {
                        // We must find the Arc<String> that already exists in the cache map
                        // to maintain the structural integrity (same Arc pointer).
                        // If it's not in 'cache', the data is inconsistent, but we handle it safely.
                        if let Some((existing_arc, _)) = cache.get_key_value(&key_str) {
                            set.insert(Arc::clone(existing_arc));
                        } else {
                            // If strictly consistent, this shouldn't happen.
                            // However, if it does, we create a new Arc.
                            let new_arc = Arc::new(key_str);
                            set.insert(new_arc);
                        }
                    }
                    frequency_bin.insert(freq, set);
                }

                Ok(LFUFileCache {
                    cache,
                    frequency_bin,
                    capacity,
                    min_frequency,
                    cache_dir,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "cache",
            "frequency_bin",
            "capacity",
            "min_frequency",
            "cache_dir",
        ];
        deserializer.deserialize_struct("LFUFileCache", FIELDS, LFUFileCacheVisitor)
    }
}
