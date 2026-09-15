#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpdaterError {
    #[error("update check failed: {0}")]
    CheckFailed(String),
    #[error("no update available")]
    NoUpdateAvailable,
    #[error("update download failed: {0}")]
    DownloadFailed(String),
    #[error("update verification failed: {0}")]
    VerificationFailed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub version: String,
    pub download_url: String,
    pub sha256: String,
    pub release_notes: String,
    pub minimum_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub manifest: Option<UpdateManifest>,
}

pub struct Updater {
    current_version: String,
    #[allow(dead_code)]
    manifest_url: String,
}

impl Updater {
    #[must_use]
    pub fn new(current_version: &str, manifest_url: &str) -> Self {
        Self {
            current_version: current_version.to_owned(),
            manifest_url: manifest_url.to_owned(),
        }
    }

    pub fn check_for_update(&self) -> Result<UpdateCheckResult, UpdaterError> {
        Ok(UpdateCheckResult {
            current_version: self.current_version.clone(),
            latest_version: None,
            update_available: false,
            manifest: None,
        })
    }

    pub fn download_update(&self, _manifest: &UpdateManifest) -> Result<Vec<u8>, UpdaterError> {
        Err(UpdaterError::DownloadFailed(
            "updater is disabled in this build".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updater_initializes() {
        let updater = Updater::new("1.0.0", "https://example.com/manifest.json");
        let result = updater.check_for_update().unwrap();
        assert_eq!(result.current_version, "1.0.0");
        assert!(!result.update_available);
    }

    #[test]
    fn download_fails_when_disabled() {
        let updater = Updater::new("1.0.0", "https://example.com/manifest.json");
        let manifest = UpdateManifest {
            version: "1.1.0".to_owned(),
            download_url: "https://example.com/download".to_owned(),
            sha256: "abc123".to_owned(),
            release_notes: "Test".to_owned(),
            minimum_version: "1.0.0".to_owned(),
        };
        assert!(updater.download_update(&manifest).is_err());
    }
}
