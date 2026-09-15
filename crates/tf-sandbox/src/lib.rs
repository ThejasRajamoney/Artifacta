#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("Windows Sandbox is not available on this system")]
    NotAvailable,
    #[error("Windows Sandbox feature is not enabled")]
    FeatureDisabled,
    #[error("failed to launch sandbox: {0}")]
    LaunchFailed(String),
    #[error("sandbox operation timed out")]
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxStatus {
    Available,
    NotAvailable,
    FeatureDisabled,
}

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub executable_path: String,
    pub arguments: Vec<String>,
    pub timeout_ms: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            executable_path: String::new(),
            arguments: Vec::new(),
            timeout_ms: 30_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SandboxResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

pub fn check_sandbox_availability() -> SandboxStatus {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        match Command::new("powershell")
            .args(["-Command", "Get-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' | Select-Object -ExpandProperty State"])
            .output()
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.trim() == "Enabled" {
                    SandboxStatus::Available
                } else {
                    SandboxStatus::FeatureDisabled
                }
            }
            Err(_) => SandboxStatus::NotAvailable,
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        SandboxStatus::NotAvailable
    }
}

pub fn launch_sandboxed(config: &SandboxConfig) -> Result<SandboxResult, SandboxError> {
    let status = check_sandbox_availability();
    match status {
        SandboxStatus::NotAvailable => return Err(SandboxError::NotAvailable),
        SandboxStatus::FeatureDisabled => return Err(SandboxError::FeatureDisabled),
        SandboxStatus::Available => {}
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let mut cmd = Command::new(&config.executable_path);
        cmd.args(&config.arguments);

        let child = cmd
            .spawn()
            .map_err(|e| SandboxError::LaunchFailed(e.to_string()))?;

        let output = child
            .wait_with_output()
            .map_err(|e| SandboxError::LaunchFailed(e.to_string()))?;

        Ok(SandboxResult {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            timed_out: false,
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = config;
        Err(SandboxError::NotAvailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_empty_executable() {
        let config = SandboxConfig::default();
        assert!(config.executable_path.is_empty());
        assert!(config.arguments.is_empty());
        assert_eq!(config.timeout_ms, 30_000);
    }

    #[test]
    fn sandbox_status_is_debuggable() {
        let status = SandboxStatus::Available;
        let _ = format!("{:?}", status);
    }
}
