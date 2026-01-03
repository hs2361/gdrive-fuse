use drive_v3::Credentials;
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, RANGE};
use std::cmp::min;
use std::collections::HashMap;
use std::error::Error;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::lfu_cache::LFUFileCache;

const GOOGLE_WORKSPACE_MIME_PREFIX: &str = "application/vnd.google-apps.";
const CHUNK_SIZE: u64 = 10 * 1024 * 1024; // 10MB chunks for background download

// https://developers.google.com/drive/api/guides/mime-types
// https://developers.google.com/drive/api/guides/ref-export-formats
fn get_app_mime_type(app_name: &str) -> &'static str {
    match app_name {
        "document" => "application/pdf",
        "spreadsheet" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "presentation" => {
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        }
        "drawing" => "image/svg+xml",
        "script+json" => "application/vnd.google-apps.script+json",
        &_ => "application/pdf",
    }
}

fn download_drive_file_range(
    client: &Client,
    file_id: &str,
    access_token: &str,
    offset: i64,
    length: u32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // Calculate end position (Range header uses inclusive end)
    let end = offset + (length as i64) - 1;

    let url = format!(
        "https://www.googleapis.com/drive/v3/files/{}?alt=media",
        file_id
    );

    let response = client
        .get(&url)
        .header(AUTHORIZATION, format!("Bearer {}", access_token))
        .header(RANGE, format!("bytes={}-{}", offset, end))
        .send()?;

    let status = response.status();
    if !status.is_success() && status.as_u16() != 206 {
        return Err(format!(
            "Request failed with status {}: {}",
            status,
            response.text().unwrap_or_default()
        )
        .into());
    }

    let bytes = response.bytes()?.to_vec();
    Ok(bytes)
}

fn export_drive_file_range(
    client: &Client,
    file_id: &str,
    access_token: &str,
    export_mime_type: &str,
    offset: i64,
    length: u32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let end = offset + (length as i64) - 1;

    let url = format!(
        "https://www.googleapis.com/drive/v3/files/{}/export?mimeType={}",
        file_id, export_mime_type
    );

    let response = client
        .get(&url)
        .header(AUTHORIZATION, format!("Bearer {}", access_token))
        .header(RANGE, format!("bytes={}-{}", offset, end))
        .send()?;

    let status = response.status();
    if !status.is_success() && status.as_u16() != 206 {
        return Err(format!(
            "Request failed with status {}: {}",
            status,
            response.text().unwrap_or_default()
        )
        .into());
    }

    let bytes = response.bytes()?.to_vec();
    Ok(bytes)
}

pub struct DownloadMessage {
    pub file_id: String,
    pub offset: i64,
    pub size: u32,
    pub mime_type: String,
    pub file_size: u64,
    pub response_channel: Sender<Vec<u8>>,
}

/// Tracks the download state for a single file
struct FileDownloadState {
    /// Whether a background download is currently in progress
    background_in_progress: bool,
    /// How many bytes have been cached so far
    cached_bytes: u64,
}

impl FileDownloadState {
    fn new() -> Self {
        FileDownloadState {
            background_in_progress: false,
            cached_bytes: 0,
        }
    }
}

pub struct FileDownloader {
    n_threads: usize,
    file_download_states: Arc<Mutex<HashMap<String, Arc<Mutex<FileDownloadState>>>>>,
    access_token: Arc<String>,
    http_client: Arc<Client>,
    request_channel: Arc<Mutex<Receiver<DownloadMessage>>>,
    file_cache: Arc<Mutex<LFUFileCache>>,
}

struct FileStreamer {
    pub file_id: String,
    pub access_token: String,
    pub mime_type: String,
    pub file_size: u64,
}

impl FileStreamer {
    fn next(&self, client: &Client, start: u64) -> Result<Vec<u8>, Box<dyn Error>> {
        let is_workspace_file = self.mime_type.starts_with(GOOGLE_WORKSPACE_MIME_PREFIX);

        let current_offset = start;
        let chunk_size = min(CHUNK_SIZE, self.file_size.saturating_sub(current_offset));

        if chunk_size == 0 {
            return Ok(Vec::new());
        }

        let chunk = if is_workspace_file {
            let app_name = self
                .mime_type
                .split(GOOGLE_WORKSPACE_MIME_PREFIX)
                .nth(1)
                .unwrap_or("document");
            let export_mime_type = get_app_mime_type(app_name);

            export_drive_file_range(
                client,
                self.file_id.as_str(),
                self.access_token.as_str(),
                export_mime_type,
                current_offset as i64,
                chunk_size as u32,
            )?
        } else {
            download_drive_file_range(
                client,
                self.file_id.as_str(),
                self.access_token.as_str(),
                current_offset as i64,
                chunk_size as u32,
            )?
        };

        let new_offset = current_offset + chunk.len() as u64;
        println!(
            "Downloaded chunk: {} bytes, progress: {}/{} bytes ({:.1}%)",
            chunk.len(),
            new_offset,
            self.file_size,
            (new_offset as f64 / self.file_size as f64) * 100.0
        );

        Ok(chunk)
    }
}

/// Get or create the per-file state lock
fn get_file_state(
    file_states: &Arc<Mutex<HashMap<String, Arc<Mutex<FileDownloadState>>>>>,
    file_id: &str,
) -> Arc<Mutex<FileDownloadState>> {
    let mut states = file_states.lock().unwrap();
    states
        .entry(file_id.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(FileDownloadState::new())))
        .clone()
}

impl FileDownloader {
    pub fn new(
        n_threads: usize,
        credentials: &Credentials,
        request_channel: Receiver<DownloadMessage>,
        file_cache: Arc<Mutex<LFUFileCache>>,
    ) -> FileDownloader {
        let request_channel = Arc::new(Mutex::new(request_channel));
        let access_token = Arc::new(credentials.access_token.access_token.clone());
        let http_client = Arc::new(Client::new());
        let file_download_states = Arc::new(Mutex::new(HashMap::new()));

        FileDownloader {
            n_threads,
            file_download_states,
            access_token,
            http_client,
            request_channel,
            file_cache,
        }
    }

    /// Clean up file state after background download completes
    fn cleanup_file_state(
        file_states: &Arc<Mutex<HashMap<String, Arc<Mutex<FileDownloadState>>>>>,
        file_id: &str,
    ) {
        let mut states = file_states.lock().unwrap();
        states.remove(file_id);
    }

    pub fn start_workers(&self) {
        for thread_id in 0..self.n_threads {
            let file_states = Arc::clone(&self.file_download_states);
            let rx_mutex = Arc::clone(&self.request_channel);
            let http_client = Arc::clone(&self.http_client);
            let access_token = Arc::clone(&self.access_token);
            let file_cache_mutex = Arc::clone(&self.file_cache);

            thread::spawn(move || {
                loop {
                    // Receive the next download request
                    let download_msg = {
                        let rx = rx_mutex.lock().unwrap();
                        rx.recv().unwrap()
                    };

                    let file_id = download_msg.file_id.clone();
                    let mime_type = download_msg.mime_type.clone();
                    let is_workspace_file = mime_type.starts_with(GOOGLE_WORKSPACE_MIME_PREFIX);

                    println!(
                        "Worker {} processing file {} (MIME: {}, workspace: {})",
                        thread_id, file_id, mime_type, is_workspace_file
                    );

                    // Get the per-file state lock (short global lock)
                    let file_state = get_file_state(&file_states, &file_id);

                    // Download the requested range (no lock held during network I/O)
                    let range_result = if is_workspace_file {
                        let app_name = mime_type
                            .split(GOOGLE_WORKSPACE_MIME_PREFIX)
                            .nth(1)
                            .unwrap_or("document");
                        let export_mime_type = get_app_mime_type(app_name);

                        export_drive_file_range(
                            &http_client,
                            &file_id,
                            &access_token,
                            export_mime_type,
                            download_msg.offset,
                            download_msg.size,
                        )
                    } else {
                        download_drive_file_range(
                            &http_client,
                            &file_id,
                            &access_token,
                            download_msg.offset,
                            download_msg.size,
                        )
                    };

                    match range_result {
                        Ok(requested_bytes) => {
                            let num_bytes = requested_bytes.len();

                            // Send the requested bytes immediately to unblock the client
                            download_msg
                                .response_channel
                                .send(requested_bytes.clone())
                                .unwrap();

                            println!(
                                "Worker {} sent {} bytes for immediate response",
                                thread_id, num_bytes
                            );

                            // Now acquire the per-file lock to coordinate caching
                            let should_start_background = {
                                let mut state = file_state.lock().unwrap();

                                if state.background_in_progress {
                                    // Another thread is already downloading this file
                                    // Don't cache these bytes as they might overlap or cause issues
                                    println!(
                                        "Worker {} skipping cache - background download already in progress for {}",
                                        thread_id, file_id
                                    );
                                    false
                                } else {
                                    // We're the first - cache the bytes and start background download
                                    {
                                        let mut file_cache = file_cache_mutex.lock().unwrap();
                                        file_cache.set(file_id.clone(), &requested_bytes);
                                    }
                                    state.cached_bytes =
                                        (download_msg.offset as u64) + (num_bytes as u64);
                                    state.background_in_progress = true;
                                    true
                                }
                            };

                            if !should_start_background {
                                continue;
                            }

                            // Check if we've already downloaded the whole file
                            let end_offset = (download_msg.offset as u64) + (num_bytes as u64);
                            if end_offset >= download_msg.file_size {
                                println!(
                                    "Worker {} file {} fully downloaded with initial request",
                                    thread_id, file_id
                                );
                                Self::cleanup_file_state(&file_states, &file_id);
                                continue;
                            }

                            println!(
                                "Worker {} starting background download from byte {} to {}",
                                thread_id, end_offset, download_msg.file_size
                            );

                            let streamer = FileStreamer {
                                file_id: file_id.clone(),
                                access_token: access_token.to_string(),
                                mime_type,
                                file_size: download_msg.file_size,
                            };

                            let mut current_offset = end_offset;

                            while current_offset < download_msg.file_size {
                                match streamer.next(&http_client, current_offset) {
                                    Ok(chunk_bytes) => {
                                        if chunk_bytes.is_empty() {
                                            break;
                                        }

                                        let chunk_len = chunk_bytes.len() as u64;

                                        // Cache the chunk and update state
                                        {
                                            let mut cache = file_cache_mutex.lock().unwrap();
                                            cache.set(file_id.clone(), &chunk_bytes);
                                        }

                                        {
                                            let mut state = file_state.lock().unwrap();
                                            state.cached_bytes = current_offset + chunk_len;
                                        }

                                        current_offset += chunk_len;
                                    }
                                    Err(err) => {
                                        println!(
                                            "Worker {} failed to download chunk for {}: {}",
                                            thread_id, file_id, err
                                        );
                                        break;
                                    }
                                }
                            }

                            println!(
                                "Worker {} completed background download for {}",
                                thread_id, file_id
                            );

                            // Clean up the file state now that download is complete
                            Self::cleanup_file_state(&file_states, &file_id);
                        }
                        Err(err) => {
                            println!(
                                "Worker {} failed to download range for {}: {}",
                                thread_id, file_id, err
                            );
                            // Send empty vec to unblock the waiting read operation
                            download_msg.response_channel.send(Vec::new()).unwrap();
                        }
                    }
                }
            });
        }
    }
}
