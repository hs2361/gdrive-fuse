use drive_v3::Credentials;
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, RANGE};
use std::cmp::min;
use std::collections::HashSet;
use std::error::Error;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::lfu_cache::LFUFileCache;

const GOOGLE_WORKSPACE_MIME_PREFIX: &str = "application/vnd.google-apps.";
const CHUNK_SIZE: u64 = 10 * 1024 * 1024; // 5MB chunks for background download

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

    // Construct the Drive API endpoint for file download
    let url = format!(
        "https://www.googleapis.com/drive/v3/files/{}?alt=media",
        file_id
    );

    // Build and send the request with Range header
    let response = client
        .get(&url)
        .header(AUTHORIZATION, format!("Bearer {}", access_token))
        .header(RANGE, format!("bytes={}-{}", offset, end))
        .send()?;

    // Check if the request was successful
    let status = response.status();
    if !status.is_success() && status.as_u16() != 206 {
        return Err(format!(
            "Request failed with status {}: {}",
            status,
            response.text().unwrap_or_default()
        )
        .into());
    }

    // Read the response body into bytes
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
    // Calculate end position (Range header uses inclusive end)
    let end = offset + (length as i64) - 1;

    // Construct the Drive API endpoint for file export
    let url = format!(
        "https://www.googleapis.com/drive/v3/files/{}/export?mimeType={}",
        file_id, export_mime_type
    );

    // Build and send the request with Range header
    let response = client
        .get(&url)
        .header(AUTHORIZATION, format!("Bearer {}", access_token))
        .header(RANGE, format!("bytes={}-{}", offset, end))
        .send()?;

    // Check if the request was successful
    let status = response.status();
    if !status.is_success() && status.as_u16() != 206 {
        return Err(format!(
            "Request failed with status {}: {}",
            status,
            response.text().unwrap_or_default()
        )
        .into());
    }

    // Read the response body into bytes
    let bytes = response.bytes()?.to_vec();

    Ok(bytes)
}

pub struct DownloadMessage {
    pub file_id: String,
    pub offset: i64,
    pub size: u32,
    pub mime_type: String,
    pub file_size: u64,
}

pub struct FileDownloader {
    n_threads: usize,
    downloading_files: Arc<Mutex<HashSet<String>>>,
    access_token: Arc<String>,
    http_client: Arc<Client>,
    request_channel: Arc<Mutex<Receiver<DownloadMessage>>>,
    file_bytes_channel: Arc<Mutex<Sender<Vec<u8>>>>,
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

        let mut current_offset = start + 1;

        let chunk_size = min(CHUNK_SIZE, self.file_size - current_offset);

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

        current_offset += chunk.len() as u64;

        println!(
            "Downloaded chunk: {} bytes, progress: {}/{} bytes ({:.1}%)",
            chunk.len(),
            current_offset,
            self.file_size,
            (current_offset as f64 / self.file_size as f64) * 100.0
        );

        Ok(chunk)
    }
}

impl FileDownloader {
    pub fn new(
        n_threads: usize,
        credentials: &Credentials,
        request_channel: Receiver<DownloadMessage>,
        file_bytes_channel: Sender<Vec<u8>>,
        file_cache: Arc<Mutex<LFUFileCache>>,
    ) -> FileDownloader {
        let request_channel = Arc::new(Mutex::new(request_channel));
        let file_bytes_channel = Arc::new(Mutex::new(file_bytes_channel));
        let access_token = Arc::new(credentials.access_token.access_token.clone());
        let http_client = Arc::new(Client::new());
        let downloading_files = Arc::new(Mutex::new(HashSet::new()));

        FileDownloader {
            n_threads,
            downloading_files,
            access_token,
            http_client,
            request_channel,
            file_bytes_channel,
            file_cache,
        }
    }

    pub fn start_workers(&self) {
        for thread_id in 0..self.n_threads {
            let downloading_files_mutex = Arc::clone(&self.downloading_files);
            let rx_mutex = Arc::clone(&self.request_channel);
            let tx_mutex = Arc::clone(&self.file_bytes_channel);
            let http_client = Arc::clone(&self.http_client);
            let access_token = Arc::clone(&self.access_token);
            let file_cache_mutex = Arc::clone(&self.file_cache);

            thread::spawn(move || {
                loop {
                    let rx = rx_mutex.lock().unwrap();
                    let download_msg = rx.recv().unwrap();
                    drop(rx);

                    let file_id = download_msg.file_id.clone();
                    let mime_type = download_msg.mime_type.clone();
                    let is_workspace_file = mime_type.starts_with(GOOGLE_WORKSPACE_MIME_PREFIX);

                    println!(
                        "Worker {} processing file {} (MIME: {}, workspace: {})",
                        thread_id, file_id, mime_type, is_workspace_file
                    );

                    // Download the requested range first to serve it immediately
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
                            // Send the requested bytes immediately
                            let num_bytes = requested_bytes.len();
                            let tx = tx_mutex.lock().unwrap();
                            println!(
                                "Worker {} sent {} bytes for immediate response",
                                thread_id, num_bytes
                            );
                            tx.send(requested_bytes.clone()).unwrap();
                            drop(tx);

                            // Check if the file is being downloaded by another thread
                            let mut downloading_files = downloading_files_mutex.lock().unwrap();
                            if downloading_files.contains(&file_id) {
                                continue;
                            }

                            // Cache the downloaded bytes
                            let mut file_cache = file_cache_mutex.lock().unwrap();
                            file_cache.set(file_id.clone(), &requested_bytes);
                            downloading_files.insert(file_id.clone());
                            drop(file_cache);

                            // Now download the rest of the file in the background
                            let mut end_offset =
                                (download_msg.offset as u64) + (num_bytes as u64) - 1;

                            if (download_msg.file_size - end_offset) <= 0 {
                                downloading_files.remove(&download_msg.file_id);
                                continue;
                            }

                            drop(downloading_files);

                            println!(
                                "Worker {} starting background download from byte {} to {}",
                                thread_id,
                                end_offset + 1,
                                download_msg.file_size
                            );

                            let streamer = FileStreamer {
                                file_id: file_id.clone(),
                                access_token: access_token.to_string(),
                                mime_type,
                                file_size: download_msg.file_size,
                            };

                            while end_offset < download_msg.file_size {
                                match streamer.next(&http_client, end_offset) {
                                    Ok(chunk_bytes) => {
                                        let mut cache = file_cache_mutex.lock().unwrap();
                                        cache.set(file_id.clone(), &chunk_bytes);
                                        end_offset += chunk_bytes.len() as u64;
                                    }
                                    Err(err) => {
                                        println!(
                                            "Worker {} failed to download remaining bytes for {}: {}",
                                            thread_id, file_id, err
                                        );
                                        break;
                                    }
                                }
                            }

                            let mut downloading_files = downloading_files_mutex.lock().unwrap();
                            downloading_files.remove(&download_msg.file_id);
                        }
                        Err(err) => {
                            println!(
                                "Worker {} failed to download range for {}: {}",
                                thread_id, file_id, err
                            );
                            // Send empty vec to unblock the waiting read operation
                            let tx = tx_mutex.lock().unwrap();
                            tx.send(Vec::new()).unwrap();
                        }
                    }
                }
            });
        }
    }
}
