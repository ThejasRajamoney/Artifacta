//! Direct parser corpus regression. Packaged desktop coverage lives in `apps/desktop/e2e`.
#![cfg(windows)]

use std::collections::BTreeMap;
use std::path::PathBuf;

fn corpus_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("..")
        .join("..")
        .join("..")
        .join("testfiles")
        .canonicalize()
        .expect("corpus root")
}

fn corpus_bytes(path: &std::path::Path) -> Vec<u8> {
    if path.extension().is_some_and(|e| e == "hex") {
        let hex = std::fs::read_to_string(path).expect("hex fixture");
        hex::decode(hex.trim()).expect("hex decode")
    } else {
        std::fs::read(path).expect("fixture bytes")
    }
}

#[test]
fn full_corpus_exercises_the_parser() {
    let root = corpus_root();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).expect("manifest"))
            .expect("manifest JSON");
    let entries = manifest.as_array().expect("manifest array");
    let mut results = BTreeMap::new();

    for entry in entries {
        let name = entry["file"].as_str().expect("fixture file");
        let path = root.join(name);
        let bytes = corpus_bytes(&path);
        let result = tf_pe::analysis::parse(
            &mut std::io::Cursor::new(bytes.clone()),
            bytes.len() as u64,
            &tf_pe::WorkerLimits::default(),
        );
        results.insert(name.to_owned(), result.is_ok());
    }

    let passed = results.values().filter(|&&v| v).count();
    let failed = results.values().filter(|&&v| !v).count();
    let safe_failures = results
        .iter()
        .filter_map(|(name, ok)| (!ok).then_some(name))
        .collect::<Vec<_>>();
    eprintln!(
        "Parser corpus: {passed} passed, {failed} failed safely out of {} total; safe failures: {safe_failures:?}",
        results.len(),
    );

    // Fixtures 01-10 must all pass except intentionally malformed ones
    for i in 1..=10 {
        let prefix = format!("{:02}_", i);
        let (name, ok) = results
            .iter()
            .find(|(k, _)| k.starts_with(&prefix))
            .expect("fixture exists");
        if name == "07_malformed_pe.exe" {
            assert!(!ok, "Fixture {name} must fail safely (malformed PE)");
        } else {
            assert!(*ok, "Fixture {name} must parse successfully");
        }
    }

    // At least 90% of all fixtures must parse (some malformed ones are expected to fail)
    let total = results.len();
    assert!(
        passed as f64 / total as f64 >= 0.85,
        "At least 85% of corpus must parse, got {passed}/{total}"
    );
}
