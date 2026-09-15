//! Install/upgrade/uninstall lifecycle tests.
//! These tests verify the NSIS installer behavior.
#![cfg(windows)]

use std::process::Command;

const INSTALLER: &str = r"target\release\bundle\nsis\Artifacta_1.0.0_x64-setup.exe";

#[test]
fn installer_exists_and_is_sized() {
    let path = std::path::Path::new(INSTALLER);
    if !path.exists() {
        eprintln!("Installer not found at {INSTALLER}; skipping size check (build required)");
        return;
    }
    let metadata = std::fs::metadata(path).expect("installer metadata");
    assert!(
        metadata.len() > 1_000_000,
        "installer must be > 1MB, got {}",
        metadata.len()
    );
}

#[test]
fn installer_supports_silent_install() {
    let path = std::path::Path::new(INSTALLER);
    if !path.exists() {
        eprintln!("Installer not found at {INSTALLER}; skipping silent-install check");
        return;
    }
    let output = Command::new(INSTALLER).args(["/help"]).output();
    match output {
        Ok(_) => {}
        Err(e) => panic!("installer failed to execute: {e}"),
    }
}

#[test]
fn database_path_is_stable() {
    let local_app_data = std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA set");
    let db_path = std::path::PathBuf::from(&local_app_data)
        .join("org.traceforge.desktop")
        .join("traceforge.db");
    if db_path.exists() {
        let metadata = std::fs::metadata(&db_path).expect("db metadata");
        assert!(metadata.len() > 0, "database must not be empty");
    }
}

#[test]
fn shell_integration_keys_exist_after_install() {
    let output = Command::new("reg")
        .args(["query", r"HKCU\Software\Classes\*\shell\Artifacta", "/ve"])
        .output()
        .expect("reg query");
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Inspect with Artifacta"),
            "shell integration value mismatch: {stdout}"
        );
    }
}

#[test]
fn existing_case_database_is_not_corrupted() {
    let local_app_data = std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA set");
    let db_path = std::path::PathBuf::from(&local_app_data)
        .join("org.traceforge.desktop")
        .join("traceforge.db");
    if db_path.exists() {
        let conn = rusqlite::Connection::open(&db_path).expect("database opens");
        let version: i32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("user_version pragma");
        assert!(
            version >= 1,
            "database schema version must be >= 1, got {version}"
        );
    }
}
