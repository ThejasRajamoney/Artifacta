#![no_main]

use libfuzzer_sys::fuzz_target;
use tf_protocol::{
    WorkerRecord, WorkerRequest, YaraWorkerRecord, YaraWorkerRequest, decode_ndjson,
};

fuzz_target!(|data: &[u8]| {
    let _ = decode_ndjson::<WorkerRequest>(data);
    let _ = decode_ndjson::<WorkerRecord>(data);
    let _ = decode_ndjson::<YaraWorkerRequest>(data);
    let _ = decode_ndjson::<YaraWorkerRecord>(data);
});
