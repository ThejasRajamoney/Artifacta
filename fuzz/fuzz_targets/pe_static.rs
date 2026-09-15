#![no_main]

use std::io::Write;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Bound disk and parser work while still covering all PE/string/IOC paths.
    if data.len() > 2 * 1024 * 1024 {
        return;
    }
    let mut file = tempfile::NamedTempFile::new().expect("fuzz scratch file");
    file.write_all(data).expect("write fuzz input");
    let _ = tf_pe::parse_file_for_dev(file.path());
});
