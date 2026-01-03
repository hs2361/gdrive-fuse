use std::{
    env,
    io::{Error, ErrorKind},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use drive_v3::Credentials;

const SCOPES: [&str; 1] = ["https://www.googleapis.com/auth/drive"];
const CREDENTIAL_REFRESH_INTERVAL: Duration = Duration::from_mins(30);

pub struct CredentialStore {
    credentials: Arc<Mutex<Credentials>>,
    stored_cred_file: PathBuf,
}

impl CredentialStore {
    pub fn new() -> Result<CredentialStore, Error> {
        if let Some(home_dir) = env::home_dir() {
            let mut credentials: Credentials;
            let credentials_dir = home_dir.join(".drivefs");
            let stored_cred_file = credentials_dir.join("credentials.json");

            match Credentials::from_file(&stored_cred_file, &SCOPES) {
                Ok(cred) => {
                    credentials = cred;
                    if !credentials.are_valid() {
                        // Refresh the credentials if they have expired
                        if let Err(err) = credentials.refresh() {
                            log::warn!("Failed to refresh credentials: {err}");
                        };
                    }
                }

                Err(err) => {
                    log::warn!(
                        "Failed to load credentials from {}: {err}",
                        &stored_cred_file.to_str().unwrap_or_default()
                    );

                    log::warn!("Falling back to client secret file");

                    let client_secrets_file = credentials_dir.join("client_secret.json");

                    match Credentials::from_client_secrets_file(&client_secrets_file, &SCOPES) {
                        Ok(cred) => credentials = cred,

                        Err(err) => {
                            return Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                "Failed to load credentials from client secret file at {}: {err}",
                                client_secrets_file.to_str().unwrap_or_default()
                            ),
                            ));
                        }
                    }
                }
            }

            // Save them so we don't have to refresh them every time
            if let Err(err) = credentials.store(&stored_cred_file) {
                log::warn!(
                    "Failed to save refreshed credentials at {}: {err}",
                    stored_cred_file.to_str().unwrap_or_default()
                );
            };

            return Ok(CredentialStore {
                credentials: Arc::new(Mutex::new(credentials)),
                stored_cred_file,
            });
        }

        Err(Error::new(
            ErrorKind::NotFound,
            "Failed to get user home directory",
        ))
    }

    pub fn get_credentials(&self) -> Credentials {
        let cred_mutex = Arc::clone(&self.credentials);
        let cred = cred_mutex.lock().unwrap();
        cred.clone()
    }

    pub fn refresh_credentials(&self) {
        let credentials = Arc::clone(&self.credentials);
        let stored_cred_file = self.stored_cred_file.clone();
        thread::spawn(move || loop {
            log::debug!("Refreshing credentials");
            if let Ok(mut cred) = credentials.lock() {
                if let Err(err) = cred.refresh() {
                    log::error!("Failed to refresh credentials {err}");
                };
                if let Err(err) = cred.store(&stored_cred_file) {
                    log::warn!(
                        "Failed to save refreshed credentials at {}: {err}",
                        stored_cred_file.to_str().unwrap_or_default()
                    );
                };
                drop(cred);
                thread::sleep(CREDENTIAL_REFRESH_INTERVAL);
            } else {
                log::error!("Failed to acquire credentials lock");
            }
        });
    }
}
