#![no_main]

use libfuzzer_sys::fuzz_target;
use tf_report::IntegrityManifest;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<IntegrityManifest>(data);
    let _ = tf_report::verify_manifest(data, data, None);
});
