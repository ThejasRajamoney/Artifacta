#![forbid(unsafe_code)]

use std::io::{Read, Seek};

use thiserror::Error;

pub const MAX_ARCHIVE_ENTRIES: usize = 10_000;
pub const MAX_ENTRY_SIZE: u64 = 512 * 1024 * 1024;
pub const MAX_TOTAL_EXTRACTED: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("archive could not be opened: {0}")]
    Open(#[source] zip::result::ZipError),
    #[error("archive contains too many entries (limit: {MAX_ARCHIVE_ENTRIES})")]
    TooManyEntries,
    #[error("archive entry '{name}' exceeds the size limit of {MAX_ENTRY_SIZE} bytes")]
    EntryTooLarge { name: String, size: u64 },
    #[error("total extracted size would exceed {MAX_TOTAL_EXTRACTED} bytes")]
    TotalSizeExceeded,
    #[error("archive entry '{name}' contains a path traversal")]
    PathTraversal { name: String },
    #[error("archive entry '{name}' could not be read: {source}")]
    Io {
        name: String,
        #[source]
        source: std::io::Error,
    },
    #[error("archive contains no entries")]
    Empty,
}

#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    pub name: String,
    pub size: u64,
    pub is_directory: bool,
}

#[derive(Debug, Clone)]
pub struct ArchiveListing {
    pub entries: Vec<ArchiveEntry>,
    pub total_size: u64,
}

pub fn list_archive<R: Read + Seek>(reader: R) -> Result<ArchiveListing, ArchiveError> {
    let mut archive = zip::ZipArchive::new(reader).map_err(ArchiveError::Open)?;
    let file_count = archive.len();
    if file_count > MAX_ARCHIVE_ENTRIES {
        return Err(ArchiveError::TooManyEntries);
    }
    let mut entries = Vec::with_capacity(file_count);
    let mut total_size: u64 = 0;
    for i in 0..file_count {
        let entry = archive.by_index(i).map_err(|e| ArchiveError::Io {
            name: format!("entry-{i}"),
            source: e.into(),
        })?;
        let name = entry.name().to_owned();
        let size = entry.size();
        let is_directory = name.ends_with('/');
        if !is_directory {
            total_size += size;
            if size > MAX_ENTRY_SIZE {
                return Err(ArchiveError::EntryTooLarge { name, size });
            }
        }
        entries.push(ArchiveEntry {
            name,
            size,
            is_directory,
        });
    }
    if entries.is_empty() {
        return Err(ArchiveError::Empty);
    }
    Ok(ArchiveListing {
        entries,
        total_size,
    })
}

pub fn extract_archive<R: Read + Seek, F: FnMut(&str, &[u8])>(
    reader: R,
    mut on_entry: F,
) -> Result<ArchiveListing, ArchiveError> {
    let mut archive = zip::ZipArchive::new(reader).map_err(ArchiveError::Open)?;
    let file_count = archive.len();
    if file_count > MAX_ARCHIVE_ENTRIES {
        return Err(ArchiveError::TooManyEntries);
    }
    let mut entries = Vec::with_capacity(file_count);
    let mut total_size: u64 = 0;
    for i in 0..file_count {
        let mut entry = archive.by_index(i).map_err(|e| ArchiveError::Io {
            name: format!("entry-{i}"),
            source: e.into(),
        })?;
        let name = entry.name().to_owned();
        let size = entry.size();
        let is_directory = name.ends_with('/');
        if has_path_traversal(&name) {
            return Err(ArchiveError::PathTraversal { name });
        }
        if !is_directory {
            total_size += size;
            if size > MAX_ENTRY_SIZE {
                return Err(ArchiveError::EntryTooLarge { name, size });
            }
            let mut buf = Vec::with_capacity(size as usize);
            entry.read_to_end(&mut buf).map_err(|e| ArchiveError::Io {
                name: name.clone(),
                source: e,
            })?;
            on_entry(&name, &buf);
        }
        entries.push(ArchiveEntry {
            name,
            size,
            is_directory,
        });
    }
    if total_size > MAX_TOTAL_EXTRACTED {
        return Err(ArchiveError::TotalSizeExceeded);
    }
    if entries.is_empty() {
        return Err(ArchiveError::Empty);
    }
    Ok(ArchiveListing {
        entries,
        total_size,
    })
}

pub fn is_archive(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0] == b'P' && bytes[1] == b'K' && bytes[2] == 0x03 && bytes[3] == 0x04
}

fn has_path_traversal(name: &str) -> bool {
    let normalized = name.replace('\\', "/");
    for component in normalized.split('/') {
        if component == ".." {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_zip_magic_bytes() {
        assert!(is_archive(b"PK\x03\x04rest"));
        assert!(!is_archive(b"MZ\x00\x00"));
        assert!(!is_archive(b"RIFF"));
        assert!(!is_archive(&[]));
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(has_path_traversal("../etc/passwd"));
        assert!(has_path_traversal("foo/../../bar"));
        assert!(has_path_traversal("foo/.."));
        assert!(!has_path_traversal("foo/bar.txt"));
        assert!(!has_path_traversal(".hidden/file.txt"));
    }
}
