use std::path::Path;

use serde_json::{Value, json};

fn main() {
    let path = std::env::args_os().nth(1).unwrap_or_else(|| {
        eprintln!("usage: pe_contract <inert-pe-file>");
        std::process::exit(2);
    });
    let path = Path::new(&path);
    let records = if path.extension().is_some_and(|extension| extension == "hex") {
        std::fs::read(path)
            .map_err(|error| error.to_string())
            .and_then(|encoded| decode_hex(&encoded))
            .and_then(tf_pe::parse_bytes_for_dev)
    } else {
        tf_pe::parse_file_for_dev(path)
    }
    .unwrap_or_else(|error| {
        eprintln!("parser rejected input: {error}");
        std::process::exit(1);
    });
    let header = records
        .iter()
        .find(|record| record["kind"] == "pe.header")
        .map(|record| &record["value"])
        .expect("successful PE parse has a header");
    let sections = records
        .iter()
        .filter(|record| record["kind"] == "pe.section")
        .map(|record| {
            let value = &record["value"];
            json!({
                "name": value["name"],
                "virtual_address": value["virtual_address"],
                "virtual_size": value["virtual_size"],
                "raw_offset": value["raw_offset"],
                "raw_size": value["raw_size"],
            })
        })
        .collect::<Vec<_>>();
    let imports = records
        .iter()
        .filter(|record| record["kind"] == "pe.import")
        .map(|record| {
            let value = &record["value"];
            json!({
                "dll": value["dll"],
                "function": value["function"],
                "ordinal": value["ordinal"],
            })
        })
        .collect::<Vec<_>>();
    let output: Value = json!({
        "pe_kind": header["pe_kind"],
        "machine": header["machine"],
        "entry_point_rva": header["entry_point_rva"],
        "image_base": header["image_base"],
        "sections": sections,
        "imports": imports,
    });
    println!("{}", serde_json::to_string_pretty(&output).expect("JSON"));
}

fn decode_hex(encoded: &[u8]) -> Result<Vec<u8>, String> {
    let digits = encoded
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if !digits.len().is_multiple_of(2) {
        return Err("hex fixture has an odd number of digits".to_owned());
    }
    digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok(high << 4 | low)
        })
        .collect()
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("hex fixture contains a non-hex character".to_owned()),
    }
}
