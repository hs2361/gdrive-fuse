use fuser::ReplyData;
use libc::EIO;
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, RANGE};
use std::sync::RwLock;
use std::{
    cmp::min,
    collections::HashMap,
    io::{Error, ErrorKind},
    sync::mpsc::Receiver,
    sync::{Arc, Mutex},
    thread,
};

use crate::credential_store::CredentialStore;
use crate::lfu_cache::LFUFileCache;

const GOOGLE_WORKSPACE_MIME_PREFIX: &str = "application/vnd.google-apps.";
const CHUNK_SIZE: u64 = 10 * 1024 * 1024; // 10MB chunks for background download

// https://developers.google.com/drive/api/guides/mime-types
// https://developers.google.com/drive/api/guides/ref-export-formats
pub fn get_app_mime_type(app_name: &str) -> &'static str {
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
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
    pub reply: ReplyData,
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
    credential_store: Arc<CredentialStore>,
    http_client: Arc<Client>,
    request_channel: Arc<Mutex<Receiver<DownloadMessage>>>,
    file_cache: Arc<RwLock<LFUFileCache>>,
}

struct FileStreamer {
    pub file_id: String,
    pub mime_type: String,
    pub file_size: u64,
}

impl FileStreamer {
    fn next(&self, client: &Client, access_token: &str, start: u64) -> Result<Vec<u8>, Error> {
        let is_workspace_file = self.mime_type.starts_with(GOOGLE_WORKSPACE_MIME_PREFIX);

        let current_offset = start;
        let chunk_size = min(CHUNK_SIZE, self.file_size.saturating_sub(current_offset));

        if chunk_size == 0 {
            return Ok(Vec::new());
        }

        let chunk_res = if is_workspace_file {
            let app_name = self
                .mime_type
                .split(GOOGLE_WORKSPACE_MIME_PREFIX)
                .nth(1)
                .unwrap_or("document");
            let export_mime_type = get_app_mime_type(app_name);

            export_drive_file_range(
                client,
                self.file_id.as_str(),
                &access_token,
                export_mime_type,
                current_offset as i64,
                chunk_size as u32,
            )
        } else {
            download_drive_file_range(
                client,
                self.file_id.as_str(),
                &access_token,
                current_offset as i64,
                chunk_size as u32,
            )
        };

        match chunk_res {
            Ok(chunk) => {
                let new_offset = current_offset + chunk.len() as u64;
                log::debug!(
                    "Downloaded chunk: {} bytes, progress: {}/{} bytes ({:.1}%)",
                    chunk.len(),
                    new_offset,
                    self.file_size,
                    (new_offset as f64 / self.file_size as f64) * 100.0
                );

                Ok(chunk)
            }

            Err(err) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to download chunk: {err}"),
                ));
            }
        }
    }
}

/// Get or create the per-file state lock
fn get_file_state(
    file_states: &Arc<Mutex<HashMap<String, Arc<Mutex<FileDownloadState>>>>>,
    file_id: &str,
) -> Result<Arc<Mutex<FileDownloadState>>, Error> {
    let Ok(mut states) = file_states.lock() else {
        return Err(Error::new(
            ErrorKind::Other,
            "Failed to acquire file states lock",
        ));
    };

    Ok(states
        .entry(file_id.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(FileDownloadState::new())))
        .clone())
}

/// Clean up file state after background download completes
fn cleanup_file_state(
    file_states: &Arc<Mutex<HashMap<String, Arc<Mutex<FileDownloadState>>>>>,
    file_id: &str,
) -> Result<(), Error> {
    let Ok(mut states) = file_states.lock() else {
        return Err(Error::new(
            ErrorKind::Other,
            "Failed to acquire file states lock",
        ));
    };

    states.remove(file_id);
    Ok(())
}

impl FileDownloader {
    pub fn new(
        n_threads: usize,
        credential_store: Arc<CredentialStore>,
        request_channel: Receiver<DownloadMessage>,
        file_cache: Arc<RwLock<LFUFileCache>>,
    ) -> FileDownloader {
        let request_channel = Arc::new(Mutex::new(request_channel));
        let http_client = Arc::new(Client::new());
        let file_download_states = Arc::new(Mutex::new(HashMap::new()));

        FileDownloader {
            n_threads,
            file_download_states,
            credential_store,
            http_client,
            request_channel,
            file_cache,
        }
    }

    pub fn start_workers(&self) {
        for thread_id in 0..self.n_threads {
            let file_states = Arc::clone(&self.file_download_states);
            let rx_mutex = Arc::clone(&self.request_channel);
            let http_client = Arc::clone(&self.http_client);
            let credential_store = Arc::clone(&self.credential_store);
            let file_cache_mutex = Arc::clone(&self.file_cache);

            thread::spawn(move || {
                loop {
                    // Receive the next download request
                    let Ok(rx_mutex) = rx_mutex.lock() else {
                        log::error!("Failed to acquire rx lock");
                        continue;
                    };

                    let Ok(download_msg) = rx_mutex.recv() else {
                        log::error!("Failed to receive download request");
                        continue;
                    };
                    drop(rx_mutex);

                    let file_id = download_msg.file_id.clone();
                    let mime_type = download_msg.mime_type.clone();
                    let is_workspace_file = mime_type.starts_with(GOOGLE_WORKSPACE_MIME_PREFIX);

                    log::debug!(
                        "Worker {thread_id} processing file {file_id} (MIME: {mime_type}, workspace: {is_workspace_file})",
                    );

                    // Get the per-file state lock
                    let Ok(file_state) = get_file_state(&file_states, &file_id) else {
                        log::error!("Failed to get file download state");
                        download_msg.reply.error(EIO);
                        continue;
                    };

                    let access_token = credential_store.get_credentials().access_token.access_token;

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
                            download_msg.reply.data(&requested_bytes);
                            log::debug!(
                                "Worker {thread_id} sent {num_bytes} bytes for immediate response",
                            );

                            // Acquire the per-file lock to coordinate caching
                            let mut should_start_background = false;

                            let Ok(mut state) = file_state.lock() else {
                                log::debug!("Failed to acquire file state lock");
                                continue;
                            };

                            if state.background_in_progress {
                                // Another thread is already downloading this file
                                // Don't cache these bytes as they might overlap or cause issues
                                log::debug!(
                                        "Worker {thread_id} skipping cache - background download already in progress for {file_id}",
                                    );
                            } else {
                                // Cache the bytes and start background download
                                let Ok(mut file_cache) = file_cache_mutex.write() else {
                                    log::error!("Failed to acquire file cache lock");
                                    continue;
                                };

                                if let Err(err) = file_cache.set(file_id.clone(), &requested_bytes)
                                {
                                    log::error!("Failed to cache initial response: {err}");
                                    continue;
                                };
                                drop(file_cache);
                                state.cached_bytes =
                                    (download_msg.offset as u64) + (num_bytes as u64);
                                state.background_in_progress = true;
                                should_start_background = true;
                            }

                            drop(state);
                            if !should_start_background {
                                continue;
                            }

                            // Check if we've already downloaded the whole file
                            let end_offset = (download_msg.offset as u64) + (num_bytes as u64);
                            if end_offset >= download_msg.file_size {
                                log::debug!(
                                    "Worker {thread_id} file {file_id} fully downloaded with initial request",
                                );
                                if cleanup_file_state(&file_states, &file_id).is_err() {
                                    log::error!("Failed to cleanup file state");
                                };
                                continue;
                            }

                            log::debug!(
                                "Worker {} starting background download from byte {} to {}",
                                thread_id,
                                end_offset,
                                download_msg.file_size
                            );

                            let streamer = FileStreamer {
                                file_id: file_id.clone(),
                                mime_type,
                                file_size: download_msg.file_size,
                            };

                            let mut current_offset = end_offset;

                            while current_offset < download_msg.file_size {
                                match streamer.next(&http_client, &access_token, current_offset) {
                                    Ok(chunk_bytes) => {
                                        if chunk_bytes.is_empty() {
                                            break;
                                        }

                                        let chunk_len = chunk_bytes.len() as u64;

                                        // Cache the chunk and update state
                                        let Ok(mut cache) = file_cache_mutex.write() else {
                                            log::error!(
                                                "Worker {thread_id} failed to acquire file cache lock",
                                            );
                                            break;
                                        };

                                        if let Err(err) = cache.set(file_id.clone(), &chunk_bytes) {
                                            log::error!(
                                                "Worker {thread_id} failed to cache chunk: {err}",
                                            );
                                            break;
                                        }
                                        drop(cache);

                                        let Ok(mut state) = file_state.lock() else {
                                            log::error!(
                                                "Worker {thread_id} failed to acquire file state lock",
                                            );
                                            break;
                                        };
                                        state.cached_bytes = current_offset + chunk_len;

                                        current_offset += chunk_len;
                                    }
                                    Err(err) => {
                                        log::error!(
                                            "Worker {} failed to download chunk for {}: {}",
                                            thread_id,
                                            file_id,
                                            err
                                        );
                                        break;
                                    }
                                }
                            }

                            log::debug!(
                                "Worker {thread_id} completed background download for {file_id}",
                            );

                            // Clean up the file state now that download is complete
                            if cleanup_file_state(&file_states, &file_id).is_err() {
                                log::error!("Failed to cleanup file state");
                            };
                        }
                        Err(err) => {
                            log::debug!(
                                "Worker {thread_id} failed to download range for {file_id}: {err}",
                            );
                            // Send error to client
                            download_msg.reply.error(EIO);
                        }
                    }
                }
            });
        }
    }
}
