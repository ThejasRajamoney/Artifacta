//! Bounds-checked PE parsing over file offsets and mapped RVAs.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};

use md5::Md5;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tf_model::ObservationClass;
use tf_protocol::WorkerLimits;

use crate::WorkerFailure;

const MAX_SECTIONS: u16 = 96;
const MAX_IMPORT_DLLS: usize = 4_096;
const MAX_IMPORTS: usize = 65_536;
const MAX_EXPORTS: usize = 65_536;
const MAX_RESOURCES: usize = 16_384;
const MAX_RESOURCE_DEPTH: u8 = 3;
const MAX_DEBUG_ENTRIES: usize = 1_024;
const MAX_TLS_CALLBACKS: usize = 4_096;
const MAX_DELAY_IMPORT_DLLS: usize = 4_096;
const MAX_DELAY_IMPORTS: usize = 65_536;
const MAX_RELOCATIONS: usize = 65_536;
const MAX_RUNTIME_FUNCTIONS: usize = 65_536;
const MAX_RICH_ENTRIES: usize = 4_096;
const MAX_TYPED_RESOURCE_BYTES: u32 = 1024 * 1024;
const MAX_VERSION_STRINGS: usize = 256;
const MAX_NAME_BYTES: usize = 1_024;
const MAX_DEBUG_DATA_BYTES: u32 = 1024 * 1024;
const MAX_STRINGS: usize = 20_000;
const MAX_INDICATORS: usize = 10_000;
const MAX_STRING_CHARS: usize = 1_024;
const MIN_STRING_CHARS: usize = 4;
const HIGH_ENTROPY_STRING_SECTION_THRESHOLD: f64 = 7.2;
const ENTROPY_MIN_SECTION_SIZE_BYTES: u64 = 1;
const ENTROPY_DECIMAL_PLACES: u32 = 6;
const ENTROPY_ROUNDING_SCALE: f64 = 1_000_000.0;

pub(crate) fn provenance_parameters(limits: &WorkerLimits) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "worker_limits".to_owned(),
            json!({
                "wall_time_ms": limits.wall_time_ms,
                "memory_bytes": limits.memory_bytes,
                "max_records": limits.max_records,
                "max_message_bytes": limits.max_message_bytes,
                "max_total_result_bytes": limits.max_total_result_bytes,
                "max_strings": limits.max_strings,
                "max_indicators": limits.max_indicators,
            }),
        ),
        (
            "parser_limits".to_owned(),
            json!({
                "max_sections": MAX_SECTIONS,
                "max_import_dlls": MAX_IMPORT_DLLS,
                "max_imports": MAX_IMPORTS,
                "max_exports": MAX_EXPORTS,
                "max_resources": MAX_RESOURCES,
                "max_resource_depth": MAX_RESOURCE_DEPTH,
                "max_debug_entries": MAX_DEBUG_ENTRIES,
                "max_tls_callbacks": MAX_TLS_CALLBACKS,
                "max_delay_import_dlls": MAX_DELAY_IMPORT_DLLS,
                "max_delay_imports": MAX_DELAY_IMPORTS,
                "max_relocations": MAX_RELOCATIONS,
                "max_runtime_functions": MAX_RUNTIME_FUNCTIONS,
                "max_rich_entries": MAX_RICH_ENTRIES,
                "max_typed_resource_bytes": MAX_TYPED_RESOURCE_BYTES,
                "max_version_strings": MAX_VERSION_STRINGS,
                "max_name_bytes": MAX_NAME_BYTES,
                "max_debug_data_bytes": MAX_DEBUG_DATA_BYTES,
                "max_strings": MAX_STRINGS,
                "max_indicators": MAX_INDICATORS,
                "max_string_chars": MAX_STRING_CHARS,
                "min_string_chars": MIN_STRING_CHARS,
            }),
        ),
        (
            "effective_max_strings".to_owned(),
            json!(limits.max_strings.min(MAX_STRINGS as u32)),
        ),
        (
            "effective_max_indicators".to_owned(),
            json!(limits.max_indicators.min(MAX_INDICATORS as u32)),
        ),
        (
            "section_entropy_algorithm".to_owned(),
            json!("shannon_base2_per_byte"),
        ),
        (
            "section_entropy_min_size_bytes".to_owned(),
            json!(ENTROPY_MIN_SECTION_SIZE_BYTES),
        ),
        (
            "section_entropy_decimal_places".to_owned(),
            json!(ENTROPY_DECIMAL_PLACES),
        ),
        (
            "string_high_entropy_section_threshold".to_owned(),
            json!(HIGH_ENTROPY_STRING_SECTION_THRESHOLD),
        ),
    ])
}

#[derive(Debug)]
pub struct EvidenceDraft {
    pub kind: String,
    pub class: ObservationClass,
    pub locator: BTreeMap<String, Value>,
    pub value: Value,
    pub preview_text: Option<String>,
}

impl EvidenceDraft {
    pub(crate) fn observed(kind: &str, locator: BTreeMap<String, Value>, value: Value) -> Self {
        Self {
            kind: kind.to_owned(),
            class: ObservationClass::Observed,
            locator,
            value,
            preview_text: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Directory {
    pub(crate) rva: u32,
    pub(crate) size: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct Section {
    pub(crate) name: String,
    pub(crate) virtual_size: u32,
    pub(crate) virtual_address: u32,
    pub(crate) raw_size: u32,
    pub(crate) raw_offset: u32,
    pub(crate) entropy: Option<f64>,
}

#[derive(Debug)]
pub(crate) struct Image {
    pub(crate) pe64: bool,
    pub(crate) machine: u16,
    pub(crate) image_base: u64,
    pub(crate) size_of_headers: u32,
    pub(crate) pe_offset: u64,
    pub(crate) checksum_offset: u64,
    pub(crate) security_directory_offset: u64,
    pub(crate) sections: Vec<Section>,
    pub(crate) directories: [Directory; 16],
}

impl Section {
    pub(crate) fn raw_range(&self) -> (u32, u32) {
        (self.raw_offset, self.raw_size)
    }
}

impl Image {
    fn rva_to_offset(&self, rva: u32, size: u64, file_len: u64) -> Result<u64, WorkerFailure> {
        if rva < self.size_of_headers {
            let offset = u64::from(rva);
            checked_range(file_len, offset, size, "header RVA")?;
            return Ok(offset);
        }
        for section in &self.sections {
            let span = section.virtual_size.max(section.raw_size);
            let Some(relative) = rva.checked_sub(section.virtual_address) else {
                continue;
            };
            if relative >= span
                || u64::from(relative).saturating_add(size) > u64::from(section.raw_size)
            {
                continue;
            }
            let offset = u64::from(section.raw_offset)
                .checked_add(u64::from(relative))
                .ok_or_else(|| WorkerFailure::invalid_pe("RVA mapping overflowed"))?;
            checked_range(file_len, offset, size, "mapped RVA")?;
            return Ok(offset);
        }
        Err(WorkerFailure::invalid_pe(format!(
            "RVA 0x{rva:08x} is not backed by file data"
        )))
    }
}

struct Reader<'a, R> {
    file: &'a mut R,
    len: u64,
}

impl<R: Read + Seek> Reader<'_, R> {
    fn array<const N: usize>(
        &mut self,
        offset: u64,
        label: &str,
    ) -> Result<[u8; N], WorkerFailure> {
        checked_range(self.len, offset, N as u64, label)?;
        self.file.seek(SeekFrom::Start(offset))?;
        let mut bytes = [0_u8; N];
        self.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn bytes(&mut self, offset: u64, size: usize, label: &str) -> Result<Vec<u8>, WorkerFailure> {
        checked_range(self.len, offset, size as u64, label)?;
        self.file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0_u8; size];
        self.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn u16(&mut self, offset: u64, label: &str) -> Result<u16, WorkerFailure> {
        Ok(u16::from_le_bytes(self.array(offset, label)?))
    }

    fn u32(&mut self, offset: u64, label: &str) -> Result<u32, WorkerFailure> {
        Ok(u32::from_le_bytes(self.array(offset, label)?))
    }

    fn u64(&mut self, offset: u64, label: &str) -> Result<u64, WorkerFailure> {
        Ok(u64::from_le_bytes(self.array(offset, label)?))
    }

    fn c_string(&mut self, offset: u64, label: &str) -> Result<String, WorkerFailure> {
        let available = self.len.saturating_sub(offset).min(MAX_NAME_BYTES as u64);
        checked_range(self.len, offset, 1, label)?;
        self.file.seek(SeekFrom::Start(offset))?;
        let mut value = Vec::new();
        for _ in 0..available {
            let mut byte = [0_u8; 1];
            self.file.read_exact(&mut byte)?;
            if byte[0] == 0 {
                return Ok(String::from_utf8_lossy(&value).into_owned());
            }
            value.push(byte[0]);
        }
        Err(WorkerFailure::invalid_pe(format!(
            "{label} is unterminated or exceeds {MAX_NAME_BYTES} bytes"
        )))
    }
}

pub fn parse<R: Read + Seek>(
    file: &mut R,
    length: u64,
    limits: &WorkerLimits,
) -> Result<Vec<EvidenceDraft>, WorkerFailure> {
    let mut reader = Reader { file, len: length };
    let (image, mut records) = parse_headers(&mut reader)?;
    let mut rich = Vec::new();
    parse_rich_header(&mut reader, &image, &mut rich)?;
    records.splice(1..1, rich);
    let imports = parse_imports(&mut reader, &image, &mut records)?;
    emit_imphash(&imports, &mut records);
    parse_delay_imports(&mut reader, &image, &mut records)?;
    parse_exports(&mut reader, &image, &mut records)?;
    parse_resources(&mut reader, &image, &mut records)?;
    parse_debug(&mut reader, &image, &mut records)?;
    parse_tls(&mut reader, &image, &mut records)?;
    parse_relocations(&mut reader, &image, &mut records)?;
    parse_load_config(&mut reader, &image, &mut records)?;
    parse_runtime_functions(&mut reader, &image, &mut records)?;
    parse_clr(&mut reader, &image, &mut records)?;
    parse_overlay(&mut reader, &image, &mut records)?;
    crate::authenticode::parse(reader.file, length, &image, &mut records)?;
    extract_strings_and_indicators(&mut reader, &image, limits, &mut records)?;
    Ok(records)
}

fn parse_headers<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
) -> Result<(Image, Vec<EvidenceDraft>), WorkerFailure> {
    if reader.len < 90 || reader.array::<2>(0, "DOS signature")? != *b"MZ" {
        return Err(WorkerFailure::invalid_pe(
            "DOS signature is missing or truncated",
        ));
    }
    let pe_offset = u64::from(reader.u32(0x3c, "PE header offset")?);
    if pe_offset < 64 || reader.array::<4>(pe_offset, "PE signature")? != *b"PE\0\0" {
        return Err(WorkerFailure::invalid_pe(
            "PE signature or offset is invalid",
        ));
    }
    let coff_offset = checked_add(pe_offset, 4, "COFF header")?;
    let coff = reader.array::<20>(coff_offset, "COFF header")?;
    let machine = le_u16(&coff, 0);
    let section_count = le_u16(&coff, 2);
    let timestamp = le_u32(&coff, 4);
    let optional_size = le_u16(&coff, 16);
    let characteristics = le_u16(&coff, 18);
    if section_count > MAX_SECTIONS {
        return Err(WorkerFailure::Coded {
            code: "section_limit",
            message: format!("PE declares more than {MAX_SECTIONS} sections"),
        });
    }
    let optional_offset = checked_add(pe_offset, 24, "optional header")?;
    checked_range(
        reader.len,
        optional_offset,
        u64::from(optional_size),
        "optional header",
    )?;
    if optional_size < 72 {
        return Err(WorkerFailure::invalid_pe("optional header is truncated"));
    }
    let optional = reader.array::<72>(optional_offset, "optional header")?;
    let magic = le_u16(&optional, 0);
    let (pe64, pe_kind, image_base, directory_offset, number_offset) = match magic {
        0x10b => (
            false,
            "pe32",
            u64::from(le_u32(&optional, 28)),
            96_u64,
            92_u64,
        ),
        0x20b => (true, "pe64", le_u64(&optional, 24), 112_u64, 108_u64),
        _ => {
            return Err(WorkerFailure::invalid_pe(
                "optional header is not PE32 or PE32+",
            ));
        }
    };
    if u64::from(optional_size) < directory_offset {
        return Err(WorkerFailure::invalid_pe(
            "optional header data directories are truncated",
        ));
    }
    let number_of_directories = if u64::from(optional_size) >= number_offset + 4 {
        reader
            .u32(optional_offset + number_offset, "data directory count")?
            .min(16)
    } else {
        0
    };
    let mut directories = [Directory::default(); 16];
    for index in 0..number_of_directories {
        let relative = directory_offset + u64::from(index) * 8;
        if relative + 8 > u64::from(optional_size) {
            return Err(WorkerFailure::invalid_pe(
                "declared data directory is truncated",
            ));
        }
        directories[index as usize] = Directory {
            rva: reader.u32(optional_offset + relative, "data directory RVA")?,
            size: reader.u32(optional_offset + relative + 4, "data directory size")?,
        };
    }

    let section_table = checked_add(optional_offset, u64::from(optional_size), "section table")?;
    checked_range(
        reader.len,
        section_table,
        u64::from(section_count) * 40,
        "section table",
    )?;
    let mut sections = Vec::with_capacity(usize::from(section_count));
    let mut records = Vec::with_capacity(usize::from(section_count) + 1);
    records.push(EvidenceDraft::observed(
        "pe.header",
        BTreeMap::from([("file_offset".to_owned(), json!(pe_offset))]),
        json!({
            "pe_kind": pe_kind,
            "machine": machine,
            "section_count": section_count,
            "coff_timestamp": timestamp,
            "characteristics": characteristics,
            "entry_point_rva": le_u32(&optional, 16),
            "image_base": image_base,
            "section_alignment": le_u32(&optional, 32),
            "file_alignment": le_u32(&optional, 36),
            "size_of_image": le_u32(&optional, 56),
            "size_of_headers": le_u32(&optional, 60),
            "subsystem": le_u16(&optional, 68),
            "dll_characteristics": le_u16(&optional, 70),
            "number_of_data_directories": number_of_directories,
        }),
    ));
    for index in 0..section_count {
        let offset = section_table + u64::from(index) * 40;
        let bytes = reader.array::<40>(offset, "section header")?;
        let name_end = bytes[..8].iter().position(|byte| *byte == 0).unwrap_or(8);
        let name: String = bytes[..name_end]
            .iter()
            .map(|byte| {
                if byte.is_ascii_graphic() {
                    char::from(*byte)
                } else {
                    '?'
                }
            })
            .collect();
        let section = Section {
            name: name.clone(),
            virtual_size: le_u32(&bytes, 8),
            virtual_address: le_u32(&bytes, 12),
            raw_size: le_u32(&bytes, 16),
            raw_offset: le_u32(&bytes, 20),
            entropy: None,
        };
        if section.raw_size != 0 {
            let raw_offset = u64::from(section.raw_offset);
            let raw_size = u64::from(section.raw_size);
            if raw_offset > reader.len || raw_size > reader.len - raw_offset {
                return Err(WorkerFailure::invalid_section_bounds(format!(
                    "section {index} ({name}) raw range 0x{raw_offset:x}+0x{raw_size:x} lies outside the {:#x}-byte artifact",
                    reader.len
                )));
            }
        }
        let entropy = if u64::from(section.raw_size) < ENTROPY_MIN_SECTION_SIZE_BYTES {
            None
        } else {
            Some(section_entropy(
                reader,
                u64::from(section.raw_offset),
                u64::from(section.raw_size),
            )?)
        };
        let mut section = section;
        section.entropy = entropy;
        records.push(EvidenceDraft::observed(
            "pe.section",
            BTreeMap::from([
                ("file_offset".to_owned(), json!(offset)),
                ("section_index".to_owned(), json!(index)),
            ]),
            json!({
                "index": index,
                "name": name,
                "virtual_size": section.virtual_size,
                "virtual_address": section.virtual_address,
                "raw_size": section.raw_size,
                "raw_offset": section.raw_offset,
                "characteristics": le_u32(&bytes, 36),
                "entropy": entropy,
            }),
        ));
        sections.push(section);
    }
    let image = Image {
        pe64,
        machine,
        image_base,
        size_of_headers: le_u32(&optional, 60),
        pe_offset,
        checksum_offset: optional_offset + 64,
        security_directory_offset: optional_offset + directory_offset + 4 * 8,
        sections,
        directories,
    };
    Ok((image, records))
}

fn parse_rich_header<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let end = image.pe_offset.min(reader.len);
    let stub_len = usize::try_from(end).unwrap_or(usize::MAX).min(1024 * 1024);
    let stub = reader.bytes(0, stub_len, "DOS stub")?;
    let rich = stub[64.min(stub.len())..]
        .windows(4)
        .rposition(|window| window == b"Rich")
        .map(|offset| offset + 64)
        .filter(|offset| offset + 8 <= stub.len());
    let Some(rich_relative) = rich else {
        records.push(EvidenceDraft::observed(
            "pe.rich_header",
            BTreeMap::new(),
            json!({"present": false}),
        ));
        return Ok(());
    };
    let key = le_u32(&stub, rich_relative + 4);
    let mut dans = None;
    let mut cursor = rich_relative;
    while cursor >= 4 {
        cursor -= 4;
        if le_u32(&stub, cursor) ^ key == u32::from_le_bytes(*b"DanS") {
            dans = Some(cursor);
            break;
        }
    }
    let Some(dans_relative) = dans else {
        records.push(EvidenceDraft::observed(
            "pe.rich_header",
            BTreeMap::from([("file_offset".to_owned(), json!(rich_relative as u64))]),
            json!({"present": true, "structural_status": "dans_marker_not_found", "xor_key": key}),
        ));
        return Ok(());
    };
    let entries_start = dans_relative.saturating_add(16);
    let pair_bytes = rich_relative.saturating_sub(entries_start);
    let entry_count = (pair_bytes / 8).min(MAX_RICH_ENTRIES);
    let mut entries = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let offset = entries_start + index * 8;
        let compid = le_u32(&stub, offset) ^ key;
        let count = le_u32(&stub, offset + 4) ^ key;
        entries.push(json!({
            "index": index,
            "product_id": compid >> 16,
            "build_number": compid & 0xffff,
            "use_count": count,
        }));
    }
    let checksum = rich_checksum(&stub, dans_relative, image.pe_offset, &entries);
    records.push(EvidenceDraft::observed(
        "pe.rich_header",
        BTreeMap::from([("file_offset".to_owned(), json!(dans_relative as u64))]),
        json!({
            "present": true,
            "structural_status": if pair_bytes.is_multiple_of(8) { "parsed" } else { "misaligned_entries" },
            "rich_file_offset": rich_relative as u64,
            "xor_key": key,
            "decoded_entry_count": pair_bytes / 8,
            "entries_emitted": entries.len(),
            "entries": entries,
            "checksum_context": {
                "stored_xor_key": key,
                "calculated": checksum,
                "matches": checksum == key,
                "algorithm": "rich_header_checksum",
            }
        }),
    ));
    Ok(())
}

fn rich_checksum(stub: &[u8], dans_relative: usize, pe_offset: u64, entries: &[Value]) -> u32 {
    let mut checksum = u32::try_from(pe_offset).unwrap_or(u32::MAX);
    for (file_offset, byte) in stub[..dans_relative].iter().enumerate() {
        if (0x3c..0x40).contains(&file_offset) {
            continue;
        }
        checksum = checksum.wrapping_add(u32::from(*byte).rotate_left((file_offset & 31) as u32));
    }
    for entry in entries {
        let compid = (entry["product_id"].as_u64().unwrap_or(0) as u32) << 16
            | entry["build_number"].as_u64().unwrap_or(0) as u32;
        let count = entry["use_count"].as_u64().unwrap_or(0) as u32;
        checksum = checksum.wrapping_add(compid.rotate_left(count & 31));
    }
    checksum
}

#[derive(Debug)]
struct ImportKey {
    dll: String,
    symbol: String,
}

fn parse_imports<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    records: &mut Vec<EvidenceDraft>,
) -> Result<Vec<ImportKey>, WorkerFailure> {
    let directory = image.directories[1];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(Vec::new());
    }
    if directory.size < 20 {
        return Err(WorkerFailure::invalid_pe("import directory is truncated"));
    }
    let descriptor_count =
        (usize::try_from(directory.size / 20).unwrap_or(usize::MAX)).min(MAX_IMPORT_DLLS);
    let table = image.rva_to_offset(directory.rva, u64::from(directory.size), reader.len)?;
    let pointer_size = if image.pe64 { 8_u64 } else { 4_u64 };
    let ordinal_flag = if image.pe64 { 1_u64 << 63 } else { 1_u64 << 31 };
    let mut imports = 0_usize;
    let mut keys = Vec::new();
    for descriptor_index in 0..descriptor_count {
        let offset = table + descriptor_index as u64 * 20;
        let descriptor = reader.array::<20>(offset, "import descriptor")?;
        if descriptor.iter().all(|byte| *byte == 0) {
            break;
        }
        let lookup_rva = le_u32(&descriptor, 0);
        let name_rva = le_u32(&descriptor, 12);
        let iat_rva = le_u32(&descriptor, 16);
        let dll_offset = image.rva_to_offset(name_rva, 1, reader.len)?;
        let dll = reader.c_string(dll_offset, "import DLL name")?;
        let thunk_rva = if lookup_rva == 0 { iat_rva } else { lookup_rva };
        for thunk_index in 0..MAX_IMPORTS.saturating_sub(imports) {
            let relative = (thunk_index as u64)
                .checked_mul(pointer_size)
                .ok_or_else(|| WorkerFailure::invalid_pe("import thunk offset overflowed"))?;
            let current_rva = u64::from(thunk_rva)
                .checked_add(relative)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| WorkerFailure::invalid_pe("import thunk RVA overflowed"))?;
            let current_iat = u64::from(iat_rva)
                .checked_add(relative)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| WorkerFailure::invalid_pe("IAT RVA overflowed"))?;
            let thunk_offset = image.rva_to_offset(current_rva, pointer_size, reader.len)?;
            let thunk = if image.pe64 {
                reader.u64(thunk_offset, "import thunk")?
            } else {
                u64::from(reader.u32(thunk_offset, "import thunk")?)
            };
            if thunk == 0 {
                break;
            }
            let (name, ordinal, hint) = if thunk & ordinal_flag != 0 {
                (None, Some((thunk & 0xffff) as u16), None)
            } else {
                let name_rva = u32::try_from(thunk)
                    .map_err(|_| WorkerFailure::invalid_pe("import name RVA exceeds 32 bits"))?;
                let name_offset = image.rva_to_offset(name_rva, 3, reader.len)?;
                (
                    Some(reader.c_string(name_offset + 2, "import function name")?),
                    None,
                    Some(reader.u16(name_offset, "import hint")?),
                )
            };
            records.push(EvidenceDraft::observed(
                "pe.import",
                BTreeMap::from([
                    ("descriptor_file_offset".to_owned(), json!(offset)),
                    ("thunk_index".to_owned(), json!(thunk_index)),
                ]),
                json!({
                    "dll": dll.clone(),
                    "function": name.clone(),
                    "ordinal": ordinal,
                    "hint": hint,
                    "iat_rva": current_iat,
                    "thunk_rva": current_rva,
                }),
            ));
            keys.push(ImportKey {
                dll: dll.clone(),
                symbol: name.unwrap_or_else(|| format!("ord{}", ordinal.unwrap_or_default())),
            });
            imports += 1;
        }
        if imports == MAX_IMPORTS {
            break;
        }
    }
    Ok(keys)
}

fn emit_imphash(imports: &[ImportKey], records: &mut Vec<EvidenceDraft>) {
    let mut digest = Md5::new();
    let mut canonical_length = 0_u64;
    for (index, import) in imports.iter().enumerate() {
        if index != 0 {
            digest.update(b",");
            canonical_length += 1;
        }
        let dll = import.dll.to_ascii_lowercase();
        let dll = dll.rsplit_once('.').map_or(dll.as_str(), |(stem, _)| stem);
        let value = format!("{dll}.{}", import.symbol.to_ascii_lowercase());
        canonical_length = canonical_length.saturating_add(value.len() as u64);
        digest.update(value.as_bytes());
    }
    records.push(EvidenceDraft::observed(
        "pe.imphash",
        BTreeMap::new(),
        json!({
            "algorithm": "pefile_compatible_md5",
            "import_count": imports.len(),
            "canonical_length": canonical_length,
            "value": format!("{:x}", digest.finalize()),
        }),
    ));
}

fn parse_delay_imports<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let directory = image.directories[13];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(());
    }
    if directory.size < 32 || !directory.size.is_multiple_of(32) {
        return Err(WorkerFailure::invalid_pe(
            "delay import directory is truncated or misaligned",
        ));
    }
    let table = image.rva_to_offset(directory.rva, u64::from(directory.size), reader.len)?;
    let descriptor_count = (directory.size as usize / 32).min(MAX_DELAY_IMPORT_DLLS);
    let pointer_size = if image.pe64 { 8_u64 } else { 4_u64 };
    let ordinal_flag = if image.pe64 { 1_u64 << 63 } else { 1_u64 << 31 };
    let mut total = 0_usize;
    for descriptor_index in 0..descriptor_count {
        let descriptor_offset = table + descriptor_index as u64 * 32;
        let descriptor = reader.array::<32>(descriptor_offset, "delay import descriptor")?;
        if descriptor.iter().all(|byte| *byte == 0) {
            break;
        }
        let rva_based = le_u32(&descriptor, 0) & 1 != 0;
        let to_rva = |value: u32| -> Result<u32, WorkerFailure> {
            if value == 0 || rva_based {
                Ok(value)
            } else {
                u64::from(value)
                    .checked_sub(image.image_base)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| WorkerFailure::invalid_pe("delay import VA is below image base"))
            }
        };
        let name_rva = to_rva(le_u32(&descriptor, 4))?;
        let iat_rva = to_rva(le_u32(&descriptor, 12))?;
        let int_rva = to_rva(le_u32(&descriptor, 16))?;
        let dll = reader.c_string(
            image.rva_to_offset(name_rva, 1, reader.len)?,
            "delay import DLL",
        )?;
        for thunk_index in 0..MAX_DELAY_IMPORTS.saturating_sub(total) {
            let relative = thunk_index as u64 * pointer_size;
            let thunk_rva = u64::from(int_rva)
                .checked_add(relative)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| WorkerFailure::invalid_pe("delay import thunk overflowed"))?;
            let thunk_offset = image.rva_to_offset(thunk_rva, pointer_size, reader.len)?;
            let thunk = if image.pe64 {
                reader.u64(thunk_offset, "delay import thunk")?
            } else {
                u64::from(reader.u32(thunk_offset, "delay import thunk")?)
            };
            if thunk == 0 {
                break;
            }
            let (function, ordinal, hint) = if thunk & ordinal_flag != 0 {
                (None, Some((thunk & 0xffff) as u16), None)
            } else {
                let name_rva = to_rva(u32::try_from(thunk).map_err(|_| {
                    WorkerFailure::invalid_pe("delay import name exceeds 32 bits")
                })?)?;
                let name_offset = image.rva_to_offset(name_rva, 3, reader.len)?;
                (
                    Some(reader.c_string(name_offset + 2, "delay import function")?),
                    None,
                    Some(reader.u16(name_offset, "delay import hint")?),
                )
            };
            records.push(EvidenceDraft::observed(
                "pe.delay_import",
                BTreeMap::from([
                    (
                        "descriptor_file_offset".to_owned(),
                        json!(descriptor_offset),
                    ),
                    ("thunk_index".to_owned(), json!(thunk_index)),
                ]),
                json!({
                    "dll": dll.clone(),
                    "function": function,
                    "ordinal": ordinal,
                    "hint": hint,
                    "iat_rva": u64::from(iat_rva) + relative,
                    "thunk_rva": thunk_rva,
                    "attributes": le_u32(&descriptor, 0),
                    "module_handle_rva": to_rva(le_u32(&descriptor, 8))?,
                    "bound_iat_rva": to_rva(le_u32(&descriptor, 20))?,
                    "unload_iat_rva": to_rva(le_u32(&descriptor, 24))?,
                    "timestamp": le_u32(&descriptor, 28),
                }),
            ));
            total += 1;
        }
    }
    Ok(())
}

fn parse_exports<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let directory = image.directories[0];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(());
    }
    if directory.size < 40 {
        return Err(WorkerFailure::invalid_pe("export directory is truncated"));
    }
    let offset = image.rva_to_offset(directory.rva, 40, reader.len)?;
    let header = reader.array::<40>(offset, "export directory")?;
    let ordinal_base = le_u32(&header, 16);
    let function_count = usize::try_from(le_u32(&header, 20))
        .unwrap_or(usize::MAX)
        .min(MAX_EXPORTS);
    let name_count = usize::try_from(le_u32(&header, 24))
        .unwrap_or(usize::MAX)
        .min(MAX_EXPORTS);
    let functions_rva = le_u32(&header, 28);
    let names_rva = le_u32(&header, 32);
    let ordinals_rva = le_u32(&header, 36);
    let mut names = BTreeMap::<usize, String>::new();
    for index in 0..name_count {
        let name_pointer = image.rva_to_offset(
            names_rva
                .checked_add((index as u32).saturating_mul(4))
                .ok_or_else(|| WorkerFailure::invalid_pe("export name table overflowed"))?,
            4,
            reader.len,
        )?;
        let name_rva = reader.u32(name_pointer, "export name RVA")?;
        let ordinal_pointer = image.rva_to_offset(
            ordinals_rva
                .checked_add((index as u32).saturating_mul(2))
                .ok_or_else(|| WorkerFailure::invalid_pe("export ordinal table overflowed"))?,
            2,
            reader.len,
        )?;
        let ordinal_index = usize::from(reader.u16(ordinal_pointer, "export ordinal index")?);
        if ordinal_index < function_count {
            let name_offset = image.rva_to_offset(name_rva, 1, reader.len)?;
            names.insert(ordinal_index, reader.c_string(name_offset, "export name")?);
        }
    }
    for index in 0..function_count {
        let pointer_rva = functions_rva
            .checked_add((index as u32).saturating_mul(4))
            .ok_or_else(|| WorkerFailure::invalid_pe("export address table overflowed"))?;
        let pointer = image.rva_to_offset(pointer_rva, 4, reader.len)?;
        let function_rva = reader.u32(pointer, "export function RVA")?;
        if function_rva == 0 {
            continue;
        }
        let forwarded = function_rva >= directory.rva
            && function_rva < directory.rva.saturating_add(directory.size);
        let forwarder = if forwarded {
            let string_offset = image.rva_to_offset(function_rva, 1, reader.len)?;
            Some(reader.c_string(string_offset, "export forwarder")?)
        } else {
            None
        };
        records.push(EvidenceDraft::observed(
            "pe.export",
            BTreeMap::from([("address_table_index".to_owned(), json!(index))]),
            json!({
                "name": names.remove(&index),
                "ordinal": ordinal_base.saturating_add(index as u32),
                "rva": function_rva,
                "forwarder": forwarder,
            }),
        ));
    }
    Ok(())
}

fn parse_resources<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let directory = image.directories[2];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(());
    }
    if directory.size < 16 {
        return Err(WorkerFailure::invalid_pe("resource directory is truncated"));
    }
    let base = image.rva_to_offset(directory.rva, u64::from(directory.size), reader.len)?;
    let mut visited = BTreeSet::new();
    let mut path = Vec::new();
    let mut resource_count = 0_usize;
    let mut typed = Vec::new();
    walk_resources(
        reader,
        image,
        base,
        directory.size,
        0,
        0,
        &mut path,
        &mut visited,
        &mut resource_count,
        &mut typed,
        records,
    )?;
    for resource in typed.iter().filter(|resource| resource.kind == 24) {
        parse_manifest(reader, resource, records)?;
    }
    for resource in typed.iter().filter(|resource| resource.kind == 16) {
        parse_version_info(reader, resource, records)?;
    }
    Ok(())
}

struct TypedResource {
    kind: u32,
    path: Vec<Value>,
    file_offset: u64,
    size: u32,
}

#[allow(clippy::too_many_arguments)]
fn walk_resources<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    base: u64,
    directory_size: u32,
    relative: u32,
    depth: u8,
    path: &mut Vec<Value>,
    visited: &mut BTreeSet<u32>,
    resource_count: &mut usize,
    typed: &mut Vec<TypedResource>,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    if depth > MAX_RESOURCE_DEPTH || *resource_count >= MAX_RESOURCES {
        return Ok(());
    }
    if !visited.insert(relative) {
        return Err(WorkerFailure::invalid_pe(
            "resource directory cycle detected",
        ));
    }
    let directory_offset = resource_relative(base, directory_size, relative, 16)?;
    let header = reader.array::<16>(directory_offset, "resource directory")?;
    let count = usize::from(le_u16(&header, 12)) + usize::from(le_u16(&header, 14));
    if count > MAX_RESOURCES {
        return Err(WorkerFailure::invalid_pe(
            "resource directory entry cap exceeded",
        ));
    }
    resource_relative(base, directory_size, relative, 16 + count as u32 * 8)?;
    for index in 0..count {
        let entry_offset = directory_offset + 16 + index as u64 * 8;
        let entry = reader.array::<8>(entry_offset, "resource entry")?;
        let name_field = le_u32(&entry, 0);
        let data_field = le_u32(&entry, 4);
        let component = if name_field & 0x8000_0000 != 0 {
            let string_relative = name_field & 0x7fff_ffff;
            let string_offset = resource_relative(base, directory_size, string_relative, 2)?;
            let declared_chars = usize::from(reader.u16(string_offset, "resource name length")?);
            let full_size = declared_chars
                .checked_mul(2)
                .and_then(|size| size.checked_add(2))
                .and_then(|size| u32::try_from(size).ok())
                .ok_or_else(|| WorkerFailure::invalid_pe("resource name size overflowed"))?;
            resource_relative(base, directory_size, string_relative, full_size)?;
            let chars = declared_chars.min(256);
            let bytes = reader.bytes(string_offset + 2, chars * 2, "resource name")?;
            let (pairs, _) = bytes.as_chunks::<2>();
            json!({"name": String::from_utf16_lossy(&pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect::<Vec<_>>())})
        } else {
            json!({"id": name_field & 0xffff})
        };
        path.push(component);
        let target = data_field & 0x7fff_ffff;
        if data_field & 0x8000_0000 != 0 {
            walk_resources(
                reader,
                image,
                base,
                directory_size,
                target,
                depth + 1,
                path,
                visited,
                resource_count,
                typed,
                records,
            )?;
        } else {
            let data_offset = resource_relative(base, directory_size, target, 16)?;
            let data = reader.array::<16>(data_offset, "resource data entry")?;
            let data_rva = le_u32(&data, 0);
            let size = le_u32(&data, 4);
            let file_offset = image.rva_to_offset(data_rva, u64::from(size), reader.len)?;
            records.push(EvidenceDraft::observed(
                "pe.resource",
                BTreeMap::from([("directory_file_offset".to_owned(), json!(entry_offset))]),
                json!({
                    "path": path,
                    "data_rva": data_rva,
                    "file_offset": file_offset,
                    "size": size,
                    "code_page": le_u32(&data, 8),
                }),
            ));
            if let Some(kind) = path
                .first()
                .and_then(|component| component.get("id"))
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .filter(|kind| matches!(kind, 16 | 24))
            {
                typed.push(TypedResource {
                    kind,
                    path: path.clone(),
                    file_offset,
                    size,
                });
            }
            *resource_count += 1;
        }
        path.pop();
        if *resource_count >= MAX_RESOURCES {
            break;
        }
    }
    visited.remove(&relative);
    Ok(())
}

fn parse_manifest<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    resource: &TypedResource,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let retained = resource.size.min(MAX_TYPED_RESOURCE_BYTES);
    let bytes = reader.bytes(resource.file_offset, retained as usize, "manifest resource")?;
    let (encoding, text) = if bytes.starts_with(&[0xff, 0xfe]) {
        let units: Vec<_> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .take(MAX_TYPED_RESOURCE_BYTES as usize / 2)
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        ("utf16le", String::from_utf16_lossy(&units))
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        let units: Vec<_> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .take(MAX_TYPED_RESOURCE_BYTES as usize / 2)
            .map(|pair| u16::from_be_bytes(*pair))
            .collect();
        ("utf16be", String::from_utf16_lossy(&units))
    } else {
        ("utf8_or_ansi", String::from_utf8_lossy(&bytes).into_owned())
    };
    records.push(EvidenceDraft::observed(
        "pe.manifest",
        BTreeMap::from([("file_offset".to_owned(), json!(resource.file_offset))]),
        json!({
            "resource_path": resource.path,
            "size": resource.size,
            "encoding": encoding,
            "text": text,
            "truncated": retained != resource.size,
        }),
    ));
    Ok(())
}

fn parse_version_info<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    resource: &TypedResource,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let retained = resource.size.min(MAX_TYPED_RESOURCE_BYTES);
    let bytes = reader.bytes(
        resource.file_offset,
        retained as usize,
        "VERSIONINFO resource",
    )?;
    let mut emitted = 0_usize;
    let parsed = version_block(&bytes, 0, 0, &mut emitted);
    records.push(EvidenceDraft::observed(
        "pe.version_info",
        BTreeMap::from([("file_offset".to_owned(), json!(resource.file_offset))]),
        match parsed {
            Some((_, value)) => json!({
                "resource_path": resource.path,
                "size": resource.size,
                "structural_status": "parsed",
                "metadata": value,
                "truncated": retained != resource.size,
            }),
            None => json!({
                "resource_path": resource.path,
                "size": resource.size,
                "structural_status": "malformed",
                "truncated": retained != resource.size,
            }),
        },
    ));
    Ok(())
}

fn version_block(
    bytes: &[u8],
    offset: usize,
    depth: u8,
    emitted: &mut usize,
) -> Option<(usize, Value)> {
    if depth > 4 || *emitted >= MAX_VERSION_STRINGS || offset.checked_add(6)? > bytes.len() {
        return None;
    }
    let length = usize::from(le_u16(bytes, offset));
    let value_length = usize::from(le_u16(bytes, offset + 2));
    let value_type = le_u16(bytes, offset + 4);
    let end = offset.checked_add(length)?;
    if length < 6 || end > bytes.len() {
        return None;
    }
    let (key, key_end) = utf16_z(bytes, offset + 6, end)?;
    let value_offset = align4(key_end);
    if value_offset > end {
        return None;
    }
    let value_bytes = if value_type == 1 {
        value_length.checked_mul(2)?
    } else {
        value_length
    };
    let value_end = value_offset.checked_add(value_bytes)?.min(end);
    let value = if key == "VS_VERSION_INFO"
        && value_end.saturating_sub(value_offset) >= 52
        && le_u32(bytes, value_offset) == 0xfeef04bd
    {
        Some(json!({
            "signature": "feef04bd",
            "struct_version": format!("{}.{}", le_u32(bytes, value_offset + 4) >> 16, le_u32(bytes, value_offset + 4) & 0xffff),
            "file_version": format!("{}.{}.{}.{}", le_u32(bytes, value_offset + 8) >> 16, le_u32(bytes, value_offset + 8) & 0xffff, le_u32(bytes, value_offset + 12) >> 16, le_u32(bytes, value_offset + 12) & 0xffff),
            "product_version": format!("{}.{}.{}.{}", le_u32(bytes, value_offset + 16) >> 16, le_u32(bytes, value_offset + 16) & 0xffff, le_u32(bytes, value_offset + 20) >> 16, le_u32(bytes, value_offset + 20) & 0xffff),
            "file_flags_mask": le_u32(bytes, value_offset + 24),
            "file_flags": le_u32(bytes, value_offset + 28),
            "file_os": le_u32(bytes, value_offset + 32),
            "file_type": le_u32(bytes, value_offset + 36),
            "file_subtype": le_u32(bytes, value_offset + 40),
            "file_date_high": le_u32(bytes, value_offset + 44),
            "file_date_low": le_u32(bytes, value_offset + 48),
        }))
    } else if value_type == 1 && value_end > value_offset {
        Some(json!(utf16_text(&bytes[value_offset..value_end])))
    } else if value_end > value_offset {
        Some(json!(hex_bytes(
            &bytes[value_offset..value_end.min(value_offset + 64)]
        )))
    } else {
        None
    };
    *emitted += 1;
    let mut children = Vec::new();
    let mut child = align4(value_end);
    while child < end && children.len() < MAX_VERSION_STRINGS {
        let Some((next, parsed)) = version_block(bytes, child, depth + 1, emitted) else {
            break;
        };
        if next <= child {
            break;
        }
        children.push(parsed);
        child = align4(next);
    }
    Some((
        end,
        json!({"key": key, "value": value, "children": children}),
    ))
}

fn utf16_z(bytes: &[u8], mut offset: usize, end: usize) -> Option<(String, usize)> {
    let mut units = Vec::new();
    while offset.checked_add(2)? <= end && units.len() <= MAX_NAME_BYTES {
        let unit = le_u16(bytes, offset);
        offset += 2;
        if unit == 0 {
            return Some((String::from_utf16_lossy(&units), offset));
        }
        units.push(unit);
    }
    None
}

fn utf16_text(bytes: &[u8]) -> String {
    let units: Vec<_> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|unit| *unit != 0)
        .take(MAX_NAME_BYTES)
        .collect();
    String::from_utf16_lossy(&units)
}

fn align4(value: usize) -> usize {
    value.saturating_add(3) & !3
}

fn resource_relative(
    base: u64,
    directory_size: u32,
    relative: u32,
    size: u32,
) -> Result<u64, WorkerFailure> {
    if relative > directory_size || size > directory_size - relative {
        return Err(WorkerFailure::invalid_pe(
            "resource-relative range is out of bounds",
        ));
    }
    checked_add(base, u64::from(relative), "resource-relative offset")
}

fn parse_debug<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let directory = image.directories[6];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(());
    }
    if !directory.size.is_multiple_of(28) {
        return Err(WorkerFailure::invalid_pe(
            "debug directory size is not entry-aligned",
        ));
    }
    let count = usize::try_from(directory.size / 28)
        .unwrap_or(usize::MAX)
        .min(MAX_DEBUG_ENTRIES);
    let table = image.rva_to_offset(directory.rva, u64::from(directory.size), reader.len)?;
    for index in 0..count {
        let offset = table + index as u64 * 28;
        let entry = reader.array::<28>(offset, "debug directory entry")?;
        let data_size = le_u32(&entry, 16);
        let data_rva = le_u32(&entry, 20);
        let raw_pointer = le_u32(&entry, 24);
        let data_offset = if raw_pointer != 0 {
            checked_range(
                reader.len,
                u64::from(raw_pointer),
                u64::from(data_size),
                "debug data",
            )?;
            Some(u64::from(raw_pointer))
        } else if data_rva != 0 {
            Some(image.rva_to_offset(data_rva, u64::from(data_size), reader.len)?)
        } else {
            None
        };
        let codeview = if le_u32(&entry, 12) == 2 && data_size <= MAX_DEBUG_DATA_BYTES {
            data_offset
                .map(|position| parse_codeview(reader, position, data_size))
                .transpose()?
        } else {
            None
        };
        records.push(EvidenceDraft::observed(
            "pe.debug",
            BTreeMap::from([("file_offset".to_owned(), json!(offset))]),
            json!({
                "index": index,
                "characteristics": le_u32(&entry, 0),
                "timestamp": le_u32(&entry, 4),
                "major_version": le_u16(&entry, 8),
                "minor_version": le_u16(&entry, 10),
                "type": le_u32(&entry, 12),
                "size": data_size,
                "data_rva": data_rva,
                "file_offset": data_offset,
                "codeview": codeview,
            }),
        ));
    }
    Ok(())
}

fn parse_codeview<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    offset: u64,
    size: u32,
) -> Result<Value, WorkerFailure> {
    if size < 4 {
        return Ok(json!({"format": "truncated"}));
    }
    let bytes = reader.bytes(offset, size as usize, "CodeView data")?;
    if bytes.starts_with(b"RSDS") && bytes.len() >= 24 {
        let guid = format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
            le_u32(&bytes, 4),
            le_u16(&bytes, 8),
            le_u16(&bytes, 10),
            bytes[12],
            bytes[13],
            bytes[14..20]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        return Ok(json!({
            "format": "rsds",
            "guid": guid,
            "age": le_u32(&bytes, 20),
            "pdb_path": bounded_nul_text(&bytes[24..]),
        }));
    }
    if bytes.starts_with(b"NB10") && bytes.len() >= 16 {
        return Ok(json!({
            "format": "nb10",
            "offset": le_u32(&bytes, 4),
            "timestamp": le_u32(&bytes, 8),
            "age": le_u32(&bytes, 12),
            "pdb_path": bounded_nul_text(&bytes[16..]),
        }));
    }
    Ok(json!({"format": "unknown", "signature": hex_bytes(&bytes[..4])}))
}

fn parse_tls<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let directory = image.directories[9];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(());
    }
    let header_size = if image.pe64 { 40_u64 } else { 24_u64 };
    if u64::from(directory.size) < header_size {
        return Err(WorkerFailure::invalid_pe("TLS directory is truncated"));
    }
    let offset = image.rva_to_offset(directory.rva, header_size, reader.len)?;
    let callback_va = if image.pe64 {
        reader.u64(offset + 24, "TLS callback array VA")?
    } else {
        u64::from(reader.u32(offset + 12, "TLS callback array VA")?)
    };
    if callback_va == 0 {
        return Ok(());
    }
    let callback_rva = callback_va
        .checked_sub(image.image_base)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| WorkerFailure::invalid_pe("TLS callback array VA is below image base"))?;
    let pointer_size = if image.pe64 { 8_u64 } else { 4_u64 };
    for index in 0..MAX_TLS_CALLBACKS {
        let item_rva = u64::from(callback_rva)
            .checked_add(index as u64 * pointer_size)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| WorkerFailure::invalid_pe("TLS callback table overflowed"))?;
        let item_offset = image.rva_to_offset(item_rva, pointer_size, reader.len)?;
        let callback_va = if image.pe64 {
            reader.u64(item_offset, "TLS callback VA")?
        } else {
            u64::from(reader.u32(item_offset, "TLS callback VA")?)
        };
        if callback_va == 0 {
            break;
        }
        let rva = callback_va
            .checked_sub(image.image_base)
            .and_then(|value| u32::try_from(value).ok());
        records.push(EvidenceDraft::observed(
            "pe.tls_callback",
            BTreeMap::from([
                ("table_file_offset".to_owned(), json!(item_offset)),
                ("index".to_owned(), json!(index)),
            ]),
            json!({"va": callback_va, "rva": rva}),
        ));
    }
    Ok(())
}

fn parse_relocations<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let directory = image.directories[5];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(());
    }
    let table = image.rva_to_offset(directory.rva, u64::from(directory.size), reader.len)?;
    let mut relative = 0_u32;
    let mut emitted = 0_usize;
    let mut block_index = 0_usize;
    while relative < directory.size && emitted < MAX_RELOCATIONS {
        if directory.size - relative < 8 {
            return Err(WorkerFailure::invalid_pe(
                "base relocation block header is truncated",
            ));
        }
        let block_offset = table + u64::from(relative);
        let page_rva = reader.u32(block_offset, "base relocation page RVA")?;
        let block_size = reader.u32(block_offset + 4, "base relocation block size")?;
        if block_size < 8 || !block_size.is_multiple_of(2) || block_size > directory.size - relative
        {
            return Err(WorkerFailure::invalid_pe(
                "base relocation block size is invalid",
            ));
        }
        let count = usize::try_from((block_size - 8) / 2).unwrap_or(usize::MAX);
        for entry_index in 0..count.min(MAX_RELOCATIONS - emitted) {
            let entry_offset = block_offset + 8 + entry_index as u64 * 2;
            let entry = reader.u16(entry_offset, "base relocation entry")?;
            let relocation_type = entry >> 12;
            let offset = u32::from(entry & 0x0fff);
            records.push(EvidenceDraft::observed(
                "pe.relocation",
                BTreeMap::from([
                    ("file_offset".to_owned(), json!(entry_offset)),
                    ("block_index".to_owned(), json!(block_index)),
                    ("entry_index".to_owned(), json!(entry_index)),
                ]),
                json!({
                    "page_rva": page_rva,
                    "offset": offset,
                    "rva": page_rva.checked_add(offset),
                    "type": relocation_type,
                    "type_name": relocation_type_name(relocation_type, image.machine),
                    "is_padding": relocation_type == 0,
                }),
            ));
            emitted += 1;
        }
        relative = relative
            .checked_add(block_size)
            .ok_or_else(|| WorkerFailure::invalid_pe("base relocation directory overflowed"))?;
        block_index += 1;
    }
    Ok(())
}

fn relocation_type_name(kind: u16, machine: u16) -> &'static str {
    match (kind, machine) {
        (0, _) => "absolute",
        (1, _) => "high",
        (2, _) => "low",
        (3, _) => "highlow",
        (4, _) => "highadj",
        (10, _) => "dir64",
        (5, 0x01c0) | (5, 0x01c4) => "arm_mov32",
        (7, 0xaa64) => "arm64_pagebase_rel21",
        _ => "unknown",
    }
}

fn parse_load_config<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let directory = image.directories[10];
    let dll_characteristics = reader.u16(image.checksum_offset + 6, "DLL characteristics")?;
    let mut value = json!({
        "present": false,
        "mitigations": {
            "aslr": dll_characteristics & 0x0040 != 0,
            "dep": dll_characteristics & 0x0100 != 0,
            "high_entropy_va": image.pe64 && dll_characteristics & 0x0020 != 0,
            "force_integrity": dll_characteristics & 0x0080 != 0,
            "no_seh": dll_characteristics & 0x0400 != 0,
            "cfg_declared": dll_characteristics & 0x4000 != 0,
            "cfg_instrumented": Value::Null,
            "safe_seh_applicable": !image.pe64 && image.machine == 0x014c,
            "safe_seh": Value::Null,
        }
    });
    if directory.rva == 0 || directory.size == 0 {
        records.push(EvidenceDraft::observed(
            "pe.load_config",
            BTreeMap::new(),
            value,
        ));
        return Ok(());
    }
    let offset = image.rva_to_offset(directory.rva, 4, reader.len)?;
    let declared_size = reader.u32(offset, "load config size")?;
    let retained = declared_size.min(directory.size).min(320);
    if retained < 4 {
        return Err(WorkerFailure::invalid_pe(
            "load config directory is truncated",
        ));
    }
    let bytes = reader.bytes(offset, retained as usize, "load config directory")?;
    let (seh_table, seh_count, guard_check, guard_dispatch, guard_table, guard_count, guard_flags) =
        if image.pe64 {
            (
                field_u64(&bytes, 96),
                field_u64(&bytes, 104),
                field_u64(&bytes, 112),
                field_u64(&bytes, 120),
                field_u64(&bytes, 128),
                field_u64(&bytes, 136),
                field_u32(&bytes, 144),
            )
        } else {
            (
                field_u32(&bytes, 64).map(u64::from),
                field_u32(&bytes, 68).map(u64::from),
                field_u32(&bytes, 72).map(u64::from),
                field_u32(&bytes, 76).map(u64::from),
                field_u32(&bytes, 80).map(u64::from),
                field_u32(&bytes, 84).map(u64::from),
                field_u32(&bytes, 88),
            )
        };
    let safe_seh_applicable = !image.pe64 && image.machine == 0x014c;
    let safe_seh = if safe_seh_applicable {
        seh_table
            .zip(seh_count)
            .map(|(table, count)| table != 0 && count != 0)
    } else {
        None
    };
    value = json!({
        "present": true,
        "declared_size": declared_size,
        "directory_size": directory.size,
        "retained_size": retained,
        "seh_handler_table_va": seh_table,
        "seh_handler_count": seh_count,
        "guard_cf_check_function_va": guard_check,
        "guard_cf_dispatch_function_va": guard_dispatch,
        "guard_cf_function_table_va": guard_table,
        "guard_cf_function_count": guard_count,
        "guard_flags": guard_flags,
        "mitigations": {
            "aslr": dll_characteristics & 0x0040 != 0,
            "dep": dll_characteristics & 0x0100 != 0,
            "high_entropy_va": image.pe64 && dll_characteristics & 0x0020 != 0,
            "force_integrity": dll_characteristics & 0x0080 != 0,
            "no_seh": dll_characteristics & 0x0400 != 0,
            "cfg_declared": dll_characteristics & 0x4000 != 0,
            "cfg_instrumented": guard_flags.map(|flags| flags & 0x100 != 0),
            "safe_seh_applicable": safe_seh_applicable,
            "safe_seh": safe_seh,
        }
    });
    records.push(EvidenceDraft::observed(
        "pe.load_config",
        BTreeMap::from([("file_offset".to_owned(), json!(offset))]),
        value,
    ));
    Ok(())
}

fn field_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    (offset.checked_add(4)? <= bytes.len()).then(|| le_u32(bytes, offset))
}

fn field_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    (offset.checked_add(8)? <= bytes.len()).then(|| le_u64(bytes, offset))
}

fn parse_runtime_functions<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let directory = image.directories[3];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(());
    }
    let entry_size = match image.machine {
        0x8664 => 12_u32,
        0xaa64 => 8_u32,
        _ => {
            let offset =
                image.rva_to_offset(directory.rva, u64::from(directory.size), reader.len)?;
            records.push(EvidenceDraft::observed(
                "pe.runtime_function",
                BTreeMap::from([("file_offset".to_owned(), json!(offset))]),
                json!({"structural_status": "unsupported_machine", "machine": image.machine, "directory_size": directory.size}),
            ));
            return Ok(());
        }
    };
    if !directory.size.is_multiple_of(entry_size) {
        return Err(WorkerFailure::invalid_pe(
            "exception directory size is not entry-aligned",
        ));
    }
    let table = image.rva_to_offset(directory.rva, u64::from(directory.size), reader.len)?;
    let count = usize::try_from(directory.size / entry_size)
        .unwrap_or(usize::MAX)
        .min(MAX_RUNTIME_FUNCTIONS);
    for index in 0..count {
        let offset = table + index as u64 * u64::from(entry_size);
        let bytes = reader.bytes(offset, entry_size as usize, "runtime function")?;
        let value = if image.machine == 0x8664 {
            json!({
                "index": index,
                "machine": image.machine,
                "begin_rva": le_u32(&bytes, 0),
                "end_rva": le_u32(&bytes, 4),
                "unwind_info_rva": le_u32(&bytes, 8),
            })
        } else {
            json!({
                "index": index,
                "machine": image.machine,
                "begin_rva": le_u32(&bytes, 0),
                "unwind_data": le_u32(&bytes, 4),
            })
        };
        records.push(EvidenceDraft::observed(
            "pe.runtime_function",
            BTreeMap::from([
                ("file_offset".to_owned(), json!(offset)),
                ("index".to_owned(), json!(index)),
            ]),
            value,
        ));
    }
    Ok(())
}

fn parse_clr<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let directory = image.directories[14];
    if directory.rva == 0 || directory.size == 0 {
        records.push(EvidenceDraft::observed(
            "pe.clr",
            BTreeMap::new(),
            json!({"present": false, "metadata_present": false}),
        ));
        return Ok(());
    }
    let offset = image.rva_to_offset(directory.rva, 24, reader.len)?;
    let header = reader.array::<24>(offset, "CLR header")?;
    let header_size = le_u32(&header, 0);
    if header_size < 24 || u64::from(header_size) > u64::from(directory.size) {
        return Err(WorkerFailure::invalid_pe("CLR header size is invalid"));
    }
    let metadata_rva = le_u32(&header, 8);
    let metadata_size = le_u32(&header, 12);
    let (metadata_offset, metadata_signature, metadata_version) = if metadata_rva != 0
        && metadata_size >= 16
    {
        let metadata_offset =
            image.rva_to_offset(metadata_rva, u64::from(metadata_size), reader.len)?;
        let root = reader.array::<16>(metadata_offset, "CLR metadata root")?;
        let signature = hex_bytes(&root[..4]);
        let version_len = usize::try_from(le_u32(&root, 12))
            .unwrap_or(usize::MAX)
            .min(1024);
        let version =
            if root[..4] == *b"BSJB" && 16_u64 + version_len as u64 <= u64::from(metadata_size) {
                Some(bounded_nul_text(&reader.bytes(
                    metadata_offset + 16,
                    version_len,
                    "CLR metadata version",
                )?))
            } else {
                None
            };
        (Some(metadata_offset), Some(signature), version)
    } else {
        (None, None, None)
    };
    let flags = le_u32(&header, 16);
    let entry_point = le_u32(&header, 20);
    let native_entry_point = flags & 0x10 != 0;
    records.push(EvidenceDraft::observed(
        "pe.clr",
        BTreeMap::from([("file_offset".to_owned(), json!(offset))]),
        json!({
            "present": true,
            "header_size": header_size,
            "runtime_major": le_u16(&header, 4),
            "runtime_minor": le_u16(&header, 6),
            "metadata_rva": metadata_rva,
            "metadata_size": metadata_size,
            "metadata_present": metadata_offset.is_some(),
            "metadata_file_offset": metadata_offset,
            "metadata_signature": metadata_signature,
            "metadata_version": metadata_version,
            "flags": flags,
            "entry_point_token_or_rva": entry_point,
            "entry_point": if native_entry_point {
                json!({"kind": "native_rva", "rva": entry_point, "display": format!("0x{entry_point:08X}")})
            } else {
                json!({
                    "kind": "managed_token",
                    "token": entry_point,
                    "table_id": entry_point >> 24,
                    "row_id": entry_point & 0x00ff_ffff,
                    "display": format!("0x{entry_point:08X}"),
                })
            },
        }),
    ));
    Ok(())
}

fn parse_overlay<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let mut offset = u64::from(image.size_of_headers).min(reader.len);
    for section in &image.sections {
        let (raw_offset, raw_size) = section.raw_range();
        let end = u64::from(raw_offset)
            .checked_add(u64::from(raw_size))
            .ok_or_else(|| WorkerFailure::invalid_pe("section raw range overflowed"))?;
        if raw_size != 0 {
            checked_range(
                reader.len,
                u64::from(raw_offset),
                u64::from(raw_size),
                "section data",
            )?;
            offset = offset.max(end);
        }
    }
    offset = offset.min(reader.len);
    let certificate_offset = u64::from(image.directories[4].rva);
    let certificate_size = u64::from(image.directories[4].size);
    let certificate_end = certificate_offset.checked_add(certificate_size);
    let certificate_excluded = certificate_offset >= offset
        && certificate_size != 0
        && certificate_end.is_some_and(|end| end <= reader.len);
    let segments = if certificate_excluded {
        let certificate_end = certificate_end.expect("validated certificate end");
        [
            (offset, certificate_offset - offset),
            (certificate_end, reader.len - certificate_end),
        ]
    } else {
        [(offset, reader.len - offset), (reader.len, 0)]
    };
    let size = segments.iter().map(|(_, size)| size).sum::<u64>();
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    for (segment_offset, segment_size) in segments {
        reader.file.seek(SeekFrom::Start(segment_offset))?;
        let mut remaining = segment_size;
        while remaining != 0 {
            let count = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
            reader.file.read_exact(&mut buffer[..count])?;
            digest.update(&buffer[..count]);
            remaining -= count as u64;
        }
    }
    records.push(EvidenceDraft::observed(
        "pe.overlay",
        BTreeMap::from([("file_offset".to_owned(), json!(offset))]),
        json!({
            "present": size != 0,
            "offset": offset,
            "size": size,
            "sha256": (size != 0).then(|| format!("{:x}", digest.finalize())),
            "includes_certificate_table_when_table_is_after_sections": false,
            "certificate_table_excluded": certificate_excluded,
            "certificate_table_offset": certificate_excluded.then_some(certificate_offset),
            "certificate_table_size": certificate_excluded.then_some(certificate_size),
            "segments": segments.iter().filter(|(_, size)| *size != 0).map(|(offset, size)| json!({"offset": offset, "size": size})).collect::<Vec<_>>(),
        }),
    ));
    Ok(())
}

#[derive(Default)]
struct StringState {
    offset: u64,
    chars: Vec<u8>,
    length: u64,
}

impl StringState {
    fn push(&mut self, offset: u64, byte: u8) {
        if self.length == 0 {
            self.offset = offset;
        }
        if self.chars.len() < MAX_STRING_CHARS {
            self.chars.push(byte);
        }
        self.length += 1;
    }

    fn take(&mut self) -> Option<(u64, String, u64, bool)> {
        let result = (self.length >= MIN_STRING_CHARS as u64).then(|| {
            (
                self.offset,
                String::from_utf8_lossy(&self.chars).into_owned(),
                self.length,
                self.length > self.chars.len() as u64,
            )
        });
        self.chars.clear();
        self.length = 0;
        result
    }
}

fn extract_strings_and_indicators<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    image: &Image,
    limits: &WorkerLimits,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let max_strings = usize::try_from(limits.max_strings)
        .unwrap_or(usize::MAX)
        .min(MAX_STRINGS);
    let max_indicators = usize::try_from(limits.max_indicators)
        .unwrap_or(usize::MAX)
        .min(MAX_INDICATORS);
    if max_strings == 0 {
        return Ok(());
    }
    reader.file.seek(SeekFrom::Start(0))?;
    let mut ascii = StringState::default();
    let mut wide = [StringState::default(), StringState::default()];
    let mut previous: Option<(u64, u8)> = None;
    let mut buffer = [0_u8; 64 * 1024];
    let mut absolute = 0_u64;
    let mut found = Vec::new();
    while found.len() < max_strings {
        let count = reader.file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        for byte in &buffer[..count] {
            if byte.is_ascii_graphic() || *byte == b' ' {
                ascii.push(absolute, *byte);
            } else if let Some(value) = ascii.take() {
                found.push((value, "ascii"));
            }
            if let Some((low_offset, low)) = previous {
                let parity = (low_offset & 1) as usize;
                if low.is_ascii_graphic() || low == b' ' {
                    if *byte == 0 {
                        wide[parity].push(low_offset, low);
                    } else if let Some(value) = wide[parity].take() {
                        found.push((value, "utf16le"));
                    }
                } else if let Some(value) = wide[parity].take() {
                    found.push((value, "utf16le"));
                }
            }
            previous = Some((absolute, *byte));
            absolute += 1;
            if found.len() >= max_strings {
                break;
            }
        }
    }
    if found.len() < max_strings {
        if let Some(value) = ascii.take() {
            found.push((value, "ascii"));
        }
        for state in &mut wide {
            if found.len() < max_strings
                && let Some(value) = state.take()
            {
                found.push((value, "utf16le"));
            }
        }
    }
    found.truncate(max_strings);
    found.sort_by_key(|((offset, _, _, _), encoding)| (*offset, *encoding));
    let mut indicator_records = Vec::new();
    let mut seen = BTreeSet::new();
    for ((offset, text, length, truncated), encoding) in found {
        let section = image.sections.iter().find(|section| {
            let start = u64::from(section.raw_offset);
            let end = start.saturating_add(u64::from(section.raw_size));
            offset >= start && offset < end
        });
        let high_entropy_section = section
            .and_then(|section| section.entropy)
            .is_some_and(|entropy| entropy >= HIGH_ENTROPY_STRING_SECTION_THRESHOLD);
        let category = string_category(&text);
        let interesting = category != "raw" || !high_entropy_section;
        records.push(EvidenceDraft {
            kind: "pe.string".to_owned(),
            class: ObservationClass::Observed,
            locator: BTreeMap::from([
                ("file_offset".to_owned(), json!(offset)),
                ("encoding".to_owned(), json!(encoding)),
            ]),
            value: json!({
                "text": text,
                "encoding": encoding,
                "length_chars": length,
                "truncated": truncated,
                "analyst_category": category,
                "interesting": interesting,
                "section_name": section.map(|section| section.name.as_str()),
                "section_entropy": section.and_then(|section| section.entropy),
                "high_entropy_section": high_entropy_section,
            }),
            preview_text: Some(text.clone()),
        });
        if indicator_records.len() < max_indicators {
            recognize_indicators(
                offset,
                encoding,
                &text,
                max_indicators,
                &mut seen,
                &mut indicator_records,
            );
        }
    }
    records.extend(indicator_records);
    Ok(())
}

fn recognize_indicators(
    offset: u64,
    encoding: &str,
    text: &str,
    max: usize,
    seen: &mut BTreeSet<(String, String)>,
    output: &mut Vec<EvidenceDraft>,
) {
    let mut candidates = Vec::<(&str, String)>::new();
    for token in text.split(|character: char| {
        character.is_ascii_whitespace()
            || matches!(character, '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']')
    }) {
        let token = token.trim_matches(|character: char| matches!(character, ',' | ';' | ':'));
        let lower = token.to_ascii_lowercase();
        if (lower.starts_with("http://") || lower.starts_with("https://"))
            && token.len() <= MAX_NAME_BYTES
        {
            candidates.push(("url", token.to_owned()));
        }
        let from_url = lower.starts_with("http://") || lower.starts_with("https://");
        let host = lower
            .strip_prefix("http://")
            .or_else(|| lower.strip_prefix("https://"))
            .and_then(|rest| rest.split(['/', ':', '?', '#']).next())
            .unwrap_or(lower.trim_end_matches('.'));
        if is_ipv4(host) {
            candidates.push(("ipv4", host.to_owned()));
        } else if is_domain_with_context(host, from_url) {
            candidates.push(("domain", host.to_owned()));
        }
        if is_windows_path(token) {
            candidates.push(("windows_path", token.to_owned()));
        }
        if is_registry_key(&lower) {
            candidates.push(("registry_key", token.to_owned()));
        }
    }
    let lower = text.to_ascii_lowercase();
    if [
        "cmd.exe",
        "powershell",
        "pwsh",
        "rundll32",
        "regsvr32",
        "wscript",
        "cscript",
        "mshta",
        "certutil",
    ]
    .iter()
    .any(|command| lower.contains(command))
    {
        candidates.push(("command", text.to_owned()));
    }
    for (category, value) in candidates {
        if output.len() == max {
            break;
        }
        let canonical = match category {
            "domain" | "registry_key" => value.to_ascii_lowercase(),
            "url" => canonical_url(&value),
            _ => value.clone(),
        };
        if !seen.insert((category.to_owned(), canonical.clone())) {
            continue;
        }
        output.push(EvidenceDraft {
            kind: "pe.indicator".to_owned(),
            class: ObservationClass::Inferred,
            locator: BTreeMap::from([
                ("source_file_offset".to_owned(), json!(offset)),
                ("source_encoding".to_owned(), json!(encoding)),
            ]),
            value: json!({"category": category, "value": value, "canonical_value": canonical}),
            preview_text: Some(value),
        });
    }
}

fn canonical_url(value: &str) -> String {
    let Some((scheme, rest)) = value.split_once("://") else {
        return value.to_owned();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    format!(
        "{}://{}{}",
        scheme.to_ascii_lowercase(),
        rest[..authority_end].to_ascii_lowercase(),
        &rest[authority_end..]
    )
}

fn is_ipv4(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u8>().is_ok()
        })
}

fn is_domain(value: &str) -> bool {
    is_domain_with_context(value, false)
}

fn is_domain_with_context(value: &str, from_url: bool) -> bool {
    if value.len() > 253 || value.contains("..") || value.parse::<f64>().is_ok() {
        return false;
    }
    let labels: Vec<_> = value.split('.').collect();
    let known_tld = labels.last().is_some_and(|label| {
        const TLDS: &[&str] = &[
            "app", "au", "biz", "ca", "ch", "cloud", "co", "com", "de", "dev", "edu", "es",
            "example", "fr", "gov", "info", "invalid", "io", "it", "jp", "me", "net", "nl", "no",
            "online", "org", "ru", "se", "site", "test", "tv", "uk", "us", "xyz",
        ];
        label.len() >= 2
            && label.bytes().all(|byte| byte.is_ascii_alphabetic())
            && (from_url || TLDS.contains(label))
    });
    labels.len() >= 2
        && known_tld
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn string_category(value: &str) -> &'static str {
    let lower = value.to_ascii_lowercase();
    if [
        "cmd.exe",
        "powershell",
        "pwsh",
        "rundll32",
        "regsvr32",
        "wscript",
        "cscript",
        "mshta",
        "certutil",
    ]
    .iter()
    .any(|command| lower.contains(command))
    {
        return "commands";
    }
    if is_windows_path(value) || is_registry_key(&lower) {
        return "paths_registry";
    }
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || is_ipv4(lower.trim_end_matches('.'))
        || is_domain(lower.trim_end_matches('.'))
    {
        return "urls_domains_ips";
    }
    if lower.ends_with(".dll")
        || lower.contains("qnetworkaccessmanager")
        || lower.contains("qprocess")
        || lower.starts_with("createprocess")
        || lower.starts_with("openprocess")
    {
        return "imports_apis";
    }
    if lower.contains('=')
        || lower.contains("version")
        || lower.contains("product")
        || lower.contains("company")
        || lower.contains("copyright")
    {
        return "metadata";
    }
    "raw"
}

fn is_windows_path(value: &str) -> bool {
    (value.len() >= 3
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value.as_bytes()[1] == b':'
        && matches!(value.as_bytes()[2], b'\\' | b'/'))
        || value.starts_with("\\\\")
}

fn is_registry_key(value: &str) -> bool {
    [
        "hklm\\",
        "hkcu\\",
        "hkcr\\",
        "hku\\",
        "hkcc\\",
        "hkey_local_machine\\",
        "hkey_current_user\\",
        "hkey_classes_root\\",
        "hkey_users\\",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

fn section_entropy<R: Read + Seek>(
    reader: &mut Reader<'_, R>,
    offset: u64,
    size: u64,
) -> Result<f64, WorkerFailure> {
    checked_range(reader.len, offset, size, "section data")?;
    reader.file.seek(SeekFrom::Start(offset))?;
    let mut counts = [0_u64; 256];
    let mut remaining = size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        reader.file.read_exact(&mut buffer[..wanted])?;
        for byte in &buffer[..wanted] {
            counts[usize::from(*byte)] += 1;
        }
        remaining -= wanted as u64;
    }
    let entropy = counts
        .into_iter()
        .filter(|count| *count != 0)
        .fold(0.0, |entropy, count| {
            let probability = count as f64 / size as f64;
            entropy - probability * probability.log2()
        });
    Ok((entropy * ENTROPY_ROUNDING_SCALE).round() / ENTROPY_ROUNDING_SCALE)
}

fn bounded_nul_text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())
        .min(MAX_NAME_BYTES);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn checked_add(base: u64, amount: u64, label: &str) -> Result<u64, WorkerFailure> {
    base.checked_add(amount)
        .ok_or_else(|| WorkerFailure::invalid_pe(format!("{label} overflowed")))
}

fn checked_range(length: u64, offset: u64, size: u64, label: &str) -> Result<(), WorkerFailure> {
    if offset > length || size > length - offset {
        Err(WorkerFailure::invalid_pe(format!(
            "{label} lies outside the artifact"
        )))
    } else {
        Ok(())
    }
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn deterministic_indicator_recognizers_reject_near_misses() {
        assert!(is_ipv4("192.0.2.1"));
        assert!(!is_ipv4("999.0.2.1"));
        assert!(is_domain("example.test"));
        assert!(!is_domain("bad_domain.test"));
        assert!(!is_domain("kernel32.dll"));
        assert!(!is_domain("q.lx"));
        assert!(is_windows_path("C:\\Windows\\System32\\cmd.exe"));
        assert!(is_registry_key("hklm\\software\\example"));
    }

    #[test]
    fn indicator_evidence_has_deterministic_categories_and_inferred_class() {
        let mut seen = BTreeSet::new();
        let mut output = Vec::new();
        recognize_indicators(
            12,
            "ascii",
            "cmd.exe /c C:\\Temp\\x https://Example.Test/a 192.0.2.1 HKLM\\Software\\X",
            32,
            &mut seen,
            &mut output,
        );
        let categories: BTreeSet<_> = output
            .iter()
            .filter_map(|item| item.value["category"].as_str())
            .collect();
        for category in [
            "command",
            "domain",
            "ipv4",
            "registry_key",
            "url",
            "windows_path",
        ] {
            assert!(categories.contains(category), "missing {category}");
        }
        assert!(
            output
                .iter()
                .all(|item| item.class == ObservationClass::Inferred)
        );
        let url = output
            .iter()
            .find(|item| item.value["category"] == "url")
            .expect("URL indicator");
        assert_eq!(url.value["canonical_value"], "https://example.test/a");
    }

    #[test]
    fn resource_relative_ranges_are_bounded() {
        assert_eq!(resource_relative(100, 32, 8, 16).expect("in range"), 108);
        assert!(resource_relative(100, 32, 24, 16).is_err());
    }

    #[test]
    fn imphash_is_deterministic_and_normalizes_case_and_extensions() {
        let first = vec![
            ImportKey {
                dll: "KERNEL32.DLL".to_owned(),
                symbol: "CreateFileW".to_owned(),
            },
            ImportKey {
                dll: "sample.OCX".to_owned(),
                symbol: "ord7".to_owned(),
            },
        ];
        let equivalent = vec![
            ImportKey {
                dll: "kernel32.dll".to_owned(),
                symbol: "createfilew".to_owned(),
            },
            ImportKey {
                dll: "SAMPLE.ocx".to_owned(),
                symbol: "ORD7".to_owned(),
            },
        ];
        let mut left = Vec::new();
        let mut right = Vec::new();
        emit_imphash(&first, &mut left);
        emit_imphash(&equivalent, &mut right);
        assert_eq!(left[0].value["value"], right[0].value["value"]);
        let mut reversed = Vec::new();
        emit_imphash(
            &equivalent.into_iter().rev().collect::<Vec<_>>(),
            &mut reversed,
        );
        assert_ne!(left[0].value["value"], reversed[0].value["value"]);
        assert_eq!(left[0].value["algorithm"], "pefile_compatible_md5");
    }

    #[test]
    fn overlay_offset_size_and_hash_are_bounded_to_post_section_bytes() {
        let mut file = tempfile::tempfile().expect("temporary file");
        let mut bytes = vec![0_u8; 600];
        bytes[528..].fill(0xa5);
        file.write_all(&bytes).expect("fixture write");
        let image = Image {
            pe64: true,
            machine: 0x8664,
            image_base: 0x140000000,
            size_of_headers: 512,
            pe_offset: 64,
            checksum_offset: 152,
            security_directory_offset: 232,
            sections: vec![Section {
                name: ".text".to_owned(),
                virtual_size: 16,
                virtual_address: 0x1000,
                raw_size: 16,
                raw_offset: 512,
                entropy: Some(0.0),
            }],
            directories: [Directory::default(); 16],
        };
        let mut reader = Reader {
            file: &mut file,
            len: bytes.len() as u64,
        };
        let mut records = Vec::new();
        parse_overlay(&mut reader, &image, &mut records).expect("overlay parse");
        assert_eq!(records[0].value["offset"], 528);
        assert_eq!(records[0].value["size"], 72);
        assert_eq!(
            records[0].value["sha256"],
            format!("{:x}", Sha256::digest(&bytes[528..]))
        );
    }

    #[test]
    fn overlay_excludes_a_valid_certificate_table_after_sections() {
        let mut file = tempfile::tempfile().expect("temporary file");
        let mut bytes = vec![0_u8; 640];
        bytes[528..544].fill(0x11);
        bytes[544..608].fill(0x22);
        bytes[608..].fill(0x33);
        file.write_all(&bytes).expect("fixture write");
        let mut directories = [Directory::default(); 16];
        directories[4] = Directory { rva: 544, size: 64 };
        let image = Image {
            pe64: true,
            machine: 0x8664,
            image_base: 0x140000000,
            size_of_headers: 512,
            pe_offset: 64,
            checksum_offset: 152,
            security_directory_offset: 232,
            sections: vec![Section {
                name: ".text".to_owned(),
                virtual_size: 16,
                virtual_address: 0x1000,
                raw_size: 16,
                raw_offset: 512,
                entropy: Some(0.0),
            }],
            directories,
        };
        let mut reader = Reader {
            file: &mut file,
            len: bytes.len() as u64,
        };
        let mut records = Vec::new();
        parse_overlay(&mut reader, &image, &mut records).expect("overlay parse");
        let expected = [bytes[528..544].as_ref(), bytes[608..].as_ref()].concat();
        assert_eq!(records[0].value["size"], 48);
        assert_eq!(records[0].value["certificate_table_excluded"], true);
        assert_eq!(
            records[0].value["sha256"],
            format!("{:x}", Sha256::digest(expected))
        );
    }

    #[test]
    fn rich_header_entries_are_decoded_from_an_inert_stub() {
        let key = 0x1234_5678_u32;
        let mut bytes = vec![0_u8; 512];
        bytes[0x80..0x84].copy_from_slice(&(u32::from_le_bytes(*b"DanS") ^ key).to_le_bytes());
        for offset in [0x84, 0x88, 0x8c] {
            bytes[offset..offset + 4].copy_from_slice(&key.to_le_bytes());
        }
        bytes[0x90..0x94].copy_from_slice(&(0x0102_0304_u32 ^ key).to_le_bytes());
        bytes[0x94..0x98].copy_from_slice(&(7_u32 ^ key).to_le_bytes());
        bytes[0x98..0x9c].copy_from_slice(b"Rich");
        bytes[0x9c..0xa0].copy_from_slice(&key.to_le_bytes());
        let mut file = tempfile::tempfile().expect("temporary file");
        file.write_all(&bytes).expect("fixture write");
        let image = Image {
            pe64: true,
            machine: 0x8664,
            image_base: 0x140000000,
            size_of_headers: 512,
            pe_offset: 0x100,
            checksum_offset: 0x140,
            security_directory_offset: 0x180,
            sections: Vec::new(),
            directories: [Directory::default(); 16],
        };
        let mut reader = Reader {
            file: &mut file,
            len: bytes.len() as u64,
        };
        let mut records = Vec::new();
        parse_rich_header(&mut reader, &image, &mut records).expect("Rich parse");
        assert_eq!(records[0].value["decoded_entry_count"], 1);
        assert_eq!(records[0].value["entries"][0]["product_id"], 0x0102);
        assert_eq!(records[0].value["entries"][0]["build_number"], 0x0304);
        assert_eq!(records[0].value["entries"][0]["use_count"], 7);
    }

    #[test]
    fn manifest_and_version_info_payloads_are_bounded_and_typed() {
        let mut version = vec![0_u8; 92];
        version[0..2].copy_from_slice(&92_u16.to_le_bytes());
        version[2..4].copy_from_slice(&52_u16.to_le_bytes());
        let key: Vec<u8> = "VS_VERSION_INFO\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        version[6..6 + key.len()].copy_from_slice(&key);
        version[40..44].copy_from_slice(&0xfeef_04bd_u32.to_le_bytes());
        version[48..52].copy_from_slice(&0x0001_0002_u32.to_le_bytes());
        version[52..56].copy_from_slice(&0x0003_0004_u32.to_le_bytes());
        let manifest = b"<assembly manifestVersion=\"1.0\"></assembly>";
        let mut bytes = version.clone();
        bytes.extend_from_slice(manifest);
        let mut file = tempfile::tempfile().expect("temporary file");
        file.write_all(&bytes).expect("fixture write");
        let mut reader = Reader {
            file: &mut file,
            len: bytes.len() as u64,
        };
        let mut records = Vec::new();
        parse_manifest(
            &mut reader,
            &TypedResource {
                kind: 24,
                path: vec![json!({"id": 24})],
                file_offset: 92,
                size: manifest.len() as u32,
            },
            &mut records,
        )
        .expect("manifest parse");
        parse_version_info(
            &mut reader,
            &TypedResource {
                kind: 16,
                path: vec![json!({"id": 16})],
                file_offset: 0,
                size: version.len() as u32,
            },
            &mut records,
        )
        .expect("version parse");
        assert_eq!(records[0].value["encoding"], "utf8_or_ansi");
        assert_eq!(records[1].value["structural_status"], "parsed");
        assert_eq!(
            records[1].value["metadata"]["value"]["signature"],
            "feef04bd"
        );
    }
}
