#![no_main]

use libfuzzer_sys::fuzz_target;
use tf_model::{Edge, Entity, Evidence, EvidenceEvent, Finding};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<Evidence>(data);
    let _ = serde_json::from_slice::<Finding>(data);
    let _ = serde_json::from_slice::<Entity>(data);
    let _ = serde_json::from_slice::<Edge>(data);
    let _ = serde_json::from_slice::<EvidenceEvent>(data);
});
