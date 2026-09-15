use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root")
}

fn collect_files(root: &Path, output: &mut Vec<PathBuf>, include: fn(&Path) -> bool) {
    let mut entries = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            let skipped = path.file_name().is_some_and(|name| {
                matches!(
                    name.to_str(),
                    Some("node_modules" | "target" | "dist" | "gen" | ".git")
                )
            });
            if !skipped {
                collect_files(&path, output, include);
            }
        } else if include(&path) {
            output.push(path);
        }
    }
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_files(&root.join("crates"), &mut files, |path| {
        path.extension().is_some_and(|extension| extension == "rs")
            && path
                .components()
                .any(|component| component.as_os_str() == "src")
    });
    collect_files(
        &root.join("apps/desktop/src-tauri/src"),
        &mut files,
        |path| path.extension().is_some_and(|extension| extension == "rs"),
    );
    files
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn call_arguments<'a>(source: &'a str, marker: &str) -> Vec<&'a str> {
    let mut arguments = Vec::new();
    let mut remaining = source;
    while let Some(index) = remaining.find(marker) {
        let after_marker = &remaining[index + marker.len()..];
        if let Some(end) = after_marker.find(')') {
            arguments.push(&after_marker[..end]);
            remaining = &after_marker[end + 1..];
        } else {
            break;
        }
    }
    arguments
}

#[test]
fn artifact_paths_are_not_process_or_library_inputs() {
    let root = workspace_root();
    let native_execution_apis = [
        "CreateProcessA(",
        "CreateProcessW(",
        "ShellExecuteA(",
        "ShellExecuteW(",
        "ShellExecuteExA(",
        "ShellExecuteExW(",
        "LoadLibraryA(",
        "LoadLibraryW(",
        "LoadLibraryExA(",
        "LoadLibraryExW(",
    ];
    let artifact_path_terms = [
        "artifact_path",
        "immutable_path",
        "source_path",
        "stored_path",
        "request.artifact",
        "artifact.path",
    ];
    let mut violations = Vec::new();

    for path in rust_sources(&root) {
        let source = read(&path);
        for api in native_execution_apis {
            let documented_worker_creation = api == "CreateProcessW("
                && path
                    .file_name()
                    .is_some_and(|name| name == "job_windows.rs");
            if source.contains(api) && !documented_worker_creation {
                violations.push(format!("{} directly references {api}", path.display()));
            }
        }
        for marker in [
            "Command::new(",
            ".arg(",
            ".args(",
            ".raw_arg(",
            ".env(",
            ".envs(",
        ] {
            for argument in call_arguments(&source, marker) {
                if artifact_path_terms
                    .iter()
                    .any(|term| argument.contains(term))
                {
                    violations.push(format!(
                        "{} passes an artifact path through {marker}{argument})",
                        path.display()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "artifact execution/library-load source policy violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn renderer_capabilities_and_csp_match_the_reviewed_snapshot() {
    let root = workspace_root();
    let capability: Value = serde_json::from_str(&read(
        &root.join("apps/desktop/src-tauri/capabilities/main.json"),
    ))
    .expect("capability JSON");
    assert_eq!(capability["identifier"], "main");
    assert_eq!(capability["windows"], json!(["main"]));
    assert_eq!(capability["platforms"], json!(["windows"]));
    assert_eq!(
        capability["permissions"],
        json!([
            "core:app:default",
            "core:event:default",
            "core:window:default"
        ])
    );
    assert!(capability.get("remote").is_none());

    let config: Value =
        serde_json::from_str(&read(&root.join("apps/desktop/src-tauri/tauri.conf.json")))
            .expect("Tauri config JSON");
    assert_eq!(config["app"]["security"]["capabilities"], json!(["main"]));
    assert_eq!(
        config["app"]["security"]["csp"],
        "default-src 'self'; connect-src ipc: http://ipc.localhost; img-src 'self' asset: data:; style-src 'self' 'unsafe-inline'; font-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'"
    );
    assert_eq!(config["bundle"]["createUpdaterArtifacts"], false);
    assert_eq!(config["bundle"]["licenseFile"], "../../../LICENSE");
    assert_eq!(config["bundle"]["windows"]["allowDowngrades"], false);
    assert_eq!(
        config["bundle"]["windows"]["nsis"]["installerHooks"],
        "windows/installer-hooks.nsh"
    );
    assert!(config.get("plugins").is_none());
}

#[test]
fn intake_and_installer_never_grant_renderer_paths_or_default_associations() {
    let root = workspace_root();
    let frontend = read(&root.join("apps/desktop/src/App.tsx"));
    assert!(!frontend.contains("onDragDropEvent"));
    assert!(!frontend.contains("@tauri-apps/api/webview"));
    assert!(frontend.contains("analyze_intake_batch"));
    assert!(!frontend.contains("analyze_intake_batch\", { path"));

    let hooks = read(&root.join("apps/desktop/src-tauri/windows/installer-hooks.nsh"));
    assert!(hooks.contains("HKCU"));
    assert!(hooks.contains("SystemFileAssociations"));
    assert!(hooks.contains("Inspect with Artifacta"));
    assert!(hooks.contains("--analyze"));
    assert!(hooks.contains("NSIS_HOOK_PREUNINSTALL"));
    assert!(hooks.contains("--cleanup-appcontainers"));
    assert!(hooks.contains("ExecWait"));
    assert!(!hooks.contains("Software\\Classes\\.exe"));
    assert!(!hooks.contains("ShellExecute"));
    assert!(hooks.contains("Software\\Classes\\*\\shell\\Artifacta"));
    assert!(hooks.contains("$\\\"%1$\\\""));
    assert!(hooks.contains("DeleteRegKey HKCU \"Software\\Classes\\*\\shell\\Artifacta\""));
}

#[test]
fn production_sources_and_direct_dependencies_have_no_network_client() {
    let root = workspace_root();
    let rust_client_markers = [
        "std::net::",
        "tokio::net::",
        "reqwest::",
        "ureq::",
        "hyper::",
        "TcpStream::",
        "UdpSocket::",
        "WinHttpOpen(",
        "InternetOpenA(",
        "InternetOpenW(",
        "URLDownloadToFileA(",
        "URLDownloadToFileW(",
        "WSAStartup(",
        "windows_sys::Win32::Networking",
    ];
    let frontend_client_markers = [
        "fetch(",
        "fetch (",
        "XMLHttpRequest",
        "WebSocket",
        "EventSource",
        "navigator.sendBeacon",
        "@tauri-apps/plugin-http",
        "@tauri-apps/plugin-shell",
        "@tauri-apps/plugin-updater",
    ];
    let forbidden_dependencies = [
        "reqwest",
        "ureq",
        "hyper",
        "isahc",
        "curl",
        "surf",
        "awc",
        "tungstenite",
        "tokio-tungstenite",
        "tauri-plugin-http",
        "tauri-plugin-shell",
        "tauri-plugin-updater",
    ];
    let mut violations = Vec::new();

    for path in rust_sources(&root) {
        let source = read(&path);
        let source = source
            .split_once("#[cfg(test)]")
            .map_or(source.as_str(), |(production, _)| production);
        for marker in rust_client_markers {
            if source.contains(marker) {
                violations.push(format!("{} contains {marker}", path.display()));
            }
        }
    }

    let mut frontend = Vec::new();
    collect_files(&root.join("apps/desktop/src"), &mut frontend, |path| {
        matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("ts" | "tsx" | "js" | "jsx")
        ) && !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.contains(".test."))
    });
    for path in frontend {
        let source = read(&path);
        for marker in frontend_client_markers {
            if source.contains(marker) {
                violations.push(format!("{} contains {marker}", path.display()));
            }
        }
    }

    let mut manifests = Vec::new();
    collect_files(&root, &mut manifests, |path| {
        path.file_name().is_some_and(|name| name == "Cargo.toml")
    });
    for path in manifests {
        let manifest = read(&path);
        for line in manifest.lines().map(str::trim_start) {
            for dependency in forbidden_dependencies {
                let direct_key = line
                    .strip_prefix(dependency)
                    .is_some_and(|suffix| suffix.starts_with([' ', '=']));
                let quoted_key = line
                    .strip_prefix(&format!("\"{dependency}\""))
                    .is_some_and(|suffix| suffix.starts_with([' ', '=']));
                let renamed_package = line.contains(&format!("package = \"{dependency}\""))
                    || line.contains(&format!("package=\"{dependency}\""));
                if direct_key || quoted_key || renamed_package {
                    violations.push(format!(
                        "{} directly depends on {dependency}",
                        path.display()
                    ));
                }
            }
        }
    }

    let mut package_manifests = Vec::new();
    collect_files(&root, &mut package_manifests, |path| {
        path.file_name().is_some_and(|name| name == "package.json")
    });
    for path in package_manifests {
        let manifest: Value = serde_json::from_str(&read(&path)).expect("package manifest JSON");
        for dependency in forbidden_dependencies {
            if manifest["dependencies"].get(dependency).is_some() {
                violations.push(format!(
                    "{} directly depends on {dependency}",
                    path.display()
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "network-client source/direct-dependency policy violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn yara_runtime_has_no_wasi_filesystem_dependency() {
    let lockfile = read(&workspace_root().join("Cargo.lock"));
    assert!(
        !lockfile.contains("\nname = \"wasmtime-wasi\"\n"),
        "YARA runtime must not gain the filesystem component affected by RUSTSEC-2026-0269"
    );
    assert!(
        !lockfile.contains("\nname = \"cap-std\"\n"),
        "YARA runtime must not gain cap-std filesystem access"
    );
}

#[test]
fn private_acquisition_fields_are_skipped_and_absent_from_renderer_views() {
    let root = workspace_root();
    let model = read(&root.join("crates/tf-model/src/lib.rs"));
    assert!(model.contains("#[serde(skip_serializing)]\n    pub store_path: String"));
    assert!(model.contains("#[serde(skip_serializing)]\n    pub source_path: Option<String>"));

    let renderer_view = read(&root.join("apps/desktop/src-tauri/src/lib.rs"));
    let view_start = renderer_view
        .find("struct CaseAnalysisView")
        .expect("case view");
    let conversion_start = renderer_view[view_start..]
        .find("impl From<CaseAnalysis>")
        .map(|offset| view_start + offset)
        .expect("case view conversion");
    let public_view = &renderer_view[view_start..conversion_start];
    for private_field in ["store_path", "source_path", "artifact_path", "parameters"] {
        assert!(
            !public_view.contains(private_field),
            "renderer CaseAnalysisView exposes private field {private_field}"
        );
    }
}

#[cfg(windows)]
#[test]
fn worker_containment_uses_documented_appcontainer_creation_attributes() {
    let root = workspace_root();
    for crate_name in ["tf-pe", "tf-yara"] {
        let path = root.join(format!("crates/{crate_name}/src/job_windows.rs"));
        let source = read(&path);
        for forbidden in [
            "NtSetInformationProcess",
            "SetThreadToken",
            "CreateAppContainerToken",
        ] {
            assert!(
                !source.contains(forbidden),
                "{crate_name} must not use undocumented or fallback token mutation: {forbidden}"
            );
        }
        for required in [
            "CreateProcessW",
            "SECURITY_CAPABILITIES",
            "PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES",
            "PROC_THREAD_ATTRIBUTE_JOB_LIST",
            "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
            "CapabilityCount: 0",
            "EXTENDED_STARTUPINFO_PRESENT",
            "CreateAppContainerProfile",
            "DeriveAppContainerSidFromAppContainerName",
            "GetAppContainerFolderPath",
        ] {
            assert!(
                source.contains(required),
                "{crate_name} is missing {required}"
            );
        }
        assert!(source.contains(&format!("Artifacta.{crate_name}.worker")));
    }
}
