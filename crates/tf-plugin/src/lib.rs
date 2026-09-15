#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("plugin manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("plugin requires capability not granted: {0}")]
    MissingCapability(String),
    #[error("plugin execution failed: {0}")]
    ExecutionFailed(String),
    #[error("plugin not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ReadArtifact,
    WriteArtifact,
    ReadCase,
    WriteCase,
    ReadEvidence,
    WriteEvidence,
    ReadFindings,
    WriteFindings,
    NetworkAccess,
    FileSystemRead,
    FileSystemWrite,
    ExecuteCommand,
}

impl Capability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadArtifact => "read_artifact",
            Self::WriteArtifact => "write_artifact",
            Self::ReadCase => "read_case",
            Self::WriteCase => "write_case",
            Self::ReadEvidence => "read_evidence",
            Self::WriteEvidence => "write_evidence",
            Self::ReadFindings => "read_findings",
            Self::WriteFindings => "write_findings",
            Self::NetworkAccess => "network_access",
            Self::FileSystemRead => "filesystem_read",
            Self::FileSystemWrite => "filesystem_write",
            Self::ExecuteCommand => "execute_command",
        }
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::ReadArtifact => "read_artifact",
            Self::WriteArtifact => "write_artifact",
            Self::ReadCase => "read_case",
            Self::WriteCase => "write_case",
            Self::ReadEvidence => "read_evidence",
            Self::WriteEvidence => "write_evidence",
            Self::ReadFindings => "read_findings",
            Self::WriteFindings => "write_findings",
            Self::NetworkAccess => "network_access",
            Self::FileSystemRead => "filesystem_read",
            Self::FileSystemWrite => "filesystem_write",
            Self::ExecuteCommand => "execute_command",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub required_capabilities: Vec<Capability>,
    pub entry_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub manifest: PluginManifest,
    pub granted_capabilities: Vec<Capability>,
    pub enabled: bool,
}

pub struct PluginSandbox {
    granted: Vec<Capability>,
}

impl PluginSandbox {
    #[must_use]
    pub fn new(granted: Vec<Capability>) -> Self {
        Self { granted }
    }

    pub fn check_capability(&self, required: &Capability) -> Result<(), PluginError> {
        if self.granted.contains(required) {
            Ok(())
        } else {
            Err(PluginError::MissingCapability(required.name().to_owned()))
        }
    }

    pub fn check_all_capabilities(&self, required: &[Capability]) -> Result<(), PluginError> {
        for cap in required {
            self.check_capability(cap)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_as_str_roundtrip() {
        assert_eq!(Capability::ReadArtifact.as_str(), "read_artifact");
        assert_eq!(Capability::NetworkAccess.as_str(), "network_access");
    }

    #[test]
    fn sandbox_allows_granted_capability() {
        let sandbox = PluginSandbox::new(vec![Capability::ReadArtifact, Capability::ReadCase]);
        assert!(sandbox.check_capability(&Capability::ReadArtifact).is_ok());
        assert!(sandbox.check_capability(&Capability::ReadCase).is_ok());
    }

    #[test]
    fn sandbox_rejects_ungranted_capability() {
        let sandbox = PluginSandbox::new(vec![Capability::ReadArtifact]);
        assert!(sandbox
            .check_capability(&Capability::WriteArtifact)
            .is_err());
    }

    #[test]
    fn sandbox_checks_all_capabilities() {
        let sandbox = PluginSandbox::new(vec![Capability::ReadArtifact, Capability::ReadCase]);
        assert!(sandbox
            .check_all_capabilities(&[Capability::ReadArtifact, Capability::ReadCase])
            .is_ok());
        assert!(sandbox
            .check_all_capabilities(&[Capability::ReadArtifact, Capability::WriteArtifact])
            .is_err());
    }
}
