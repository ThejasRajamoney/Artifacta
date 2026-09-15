#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

fn startup_analysis_path(arguments: &[OsString]) -> Option<PathBuf> {
    match arguments {
        [flag, path] if flag == OsStr::new("--analyze") && !path.is_empty() => {
            Some(PathBuf::from(path))
        }
        _ => None,
    }
}

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [argument] if argument == OsStr::new("--pe-worker") => {
            std::process::exit(tf_pe::run_worker());
        }
        [argument] if argument == OsStr::new("--yara-worker") => {
            std::process::exit(tf_yara::run_worker());
        }
        [argument] if argument == OsStr::new("--pe-broker") => {
            std::process::exit(tf_pe::run_broker());
        }
        [argument] if argument == OsStr::new("--yara-broker") => {
            std::process::exit(tf_yara::run_broker());
        }
        [argument] if argument == OsStr::new("--cleanup-appcontainers") => {
            tf_pe::cleanup_appcontainer_profile();
            tf_yara::cleanup_appcontainer_profile();
            std::process::exit(0);
        }
        _ => {}
    }

    artifacta_desktop_lib::run(startup_analysis_path(&arguments));
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::startup_analysis_path;

    #[test]
    fn analyze_startup_syntax_is_exact() {
        assert_eq!(
            startup_analysis_path(&[
                OsString::from("--analyze"),
                OsString::from(r"C:\samples\item.exe"),
            ]),
            Some(PathBuf::from(r"C:\samples\item.exe"))
        );
        assert_eq!(startup_analysis_path(&[]), None);
        assert_eq!(startup_analysis_path(&[OsString::from("item.exe")]), None);
        assert_eq!(
            startup_analysis_path(&[
                OsString::from("--analyze"),
                OsString::from("item.exe"),
                OsString::from("extra"),
            ]),
            None
        );
        assert_eq!(
            startup_analysis_path(&[OsString::from("--analyze"), OsString::new()]),
            None
        );
    }

    #[test]
    fn analyze_startup_handles_unicode_and_special_characters() {
        assert_eq!(
            startup_analysis_path(&[
                OsString::from("--analyze"),
                OsString::from(r"C:\Users\Test\path with spaces\file.exe"),
            ]),
            Some(PathBuf::from(r"C:\Users\Test\path with spaces\file.exe"))
        );
        assert_eq!(
            startup_analysis_path(&[
                OsString::from("--analyze"),
                OsString::from(r"C:\Samples\тест\файл.exe"),
            ]),
            Some(PathBuf::from(r"C:\Samples\тест\файл.exe"))
        );
        assert_eq!(
            startup_analysis_path(&[
                OsString::from("--analyze"),
                OsString::from(r"C:\Samples\日本語\ファイル.exe"),
            ]),
            Some(PathBuf::from(r"C:\Samples\日本語\ファイル.exe"))
        );
        assert_eq!(
            startup_analysis_path(&[
                OsString::from("--analyze"),
                OsString::from(r"C:\path (1)\file (copy).exe"),
            ]),
            Some(PathBuf::from(r"C:\path (1)\file (copy).exe"))
        );
        assert_eq!(
            startup_analysis_path(&[
                OsString::from("--analyze"),
                OsString::from(r"C:\path&special!file.exe"),
            ]),
            Some(PathBuf::from(r"C:\path&special!file.exe"))
        );
    }
}
