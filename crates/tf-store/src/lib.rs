#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;

pub const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredArtifact {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub size_bytes: u64,
    pub relative_path: String,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("the selected path is not a regular file")]
    NotARegularFile,
    #[error("the artifact is empty")]
    EmptyArtifact,
    #[error("the artifact exceeds the {max_bytes} byte intake limit")]
    ArtifactTooLarge { max_bytes: u64 },
    #[error("the content-addressed copy failed integrity verification")]
    IntegrityMismatch,
    #[error("the content-addressed object path is invalid")]
    InvalidObjectPath,
    #[error("the content-addressed object path contains a symbolic link or reparse point")]
    ReparsePoint,
    #[error("artifact storage failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupOutcome {
    Removed,
    AlreadyMissing,
    Deferred(String),
}

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        ensure_regular_directory(&root)?;
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("staging"))?;
        ensure_regular_directory(&root.join("objects"))?;
        ensure_regular_directory(&root.join("staging"))?;
        clean_staging_directory(&root.join("staging"))?;
        Ok(Self { root })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ingest(&self, source: impl AsRef<Path>) -> Result<StoredArtifact, StoreError> {
        let source = source.as_ref();
        let metadata = fs::symlink_metadata(source)?;
        if !metadata.file_type().is_file() {
            return Err(StoreError::NotARegularFile);
        }
        if metadata.len() == 0 {
            return Err(StoreError::EmptyArtifact);
        }
        if metadata.len() > MAX_ARTIFACT_BYTES {
            return Err(StoreError::ArtifactTooLarge {
                max_bytes: MAX_ARTIFACT_BYTES,
            });
        }

        let mut input = BufReader::with_capacity(COPY_BUFFER_BYTES, File::open(source)?);
        let mut staged = NamedTempFile::new_in(self.root.join("staging"))?;
        let mut sha256 = Sha256::new();
        let mut sha1 = Sha1::new();
        let mut md5 = Md5::new();
        let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
        let mut size_bytes = 0_u64;

        loop {
            let bytes_read = input.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            size_bytes =
                size_bytes
                    .checked_add(bytes_read as u64)
                    .ok_or(StoreError::ArtifactTooLarge {
                        max_bytes: MAX_ARTIFACT_BYTES,
                    })?;
            if size_bytes > MAX_ARTIFACT_BYTES {
                return Err(StoreError::ArtifactTooLarge {
                    max_bytes: MAX_ARTIFACT_BYTES,
                });
            }
            let bytes = &buffer[..bytes_read];
            sha256.update(bytes);
            sha1.update(bytes);
            md5.update(bytes);
            staged.write_all(bytes)?;
        }

        if size_bytes == 0 {
            return Err(StoreError::EmptyArtifact);
        }
        staged.as_file_mut().sync_all()?;

        let sha256 = format!("{:x}", sha256.finalize());
        let sha1 = format!("{:x}", sha1.finalize());
        let md5 = format!("{:x}", md5.finalize());
        let relative_path = format!("objects/{}/{}", &sha256[..2], sha256);
        let destination = self.root.join(Path::new(&relative_path));
        let parent = destination.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "artifact path has no parent")
        })?;
        fs::create_dir_all(parent)?;
        ensure_regular_directory(&self.root.join("objects"))?;
        ensure_regular_directory(parent)?;

        if fs::symlink_metadata(&destination).is_ok() {
            verify_file(&destination, &sha256, size_bytes)?;
        } else {
            match staged.persist_noclobber(&destination) {
                Ok(_) => set_read_only(&destination)?,
                Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                    verify_file(&destination, &sha256, size_bytes)?;
                }
                Err(error) => return Err(StoreError::Io(error.error)),
            }
        }

        Ok(StoredArtifact {
            sha256,
            sha1,
            md5,
            size_bytes,
            relative_path,
        })
    }

    #[must_use]
    pub fn absolute_path(&self, artifact: &StoredArtifact) -> PathBuf {
        self.root.join(Path::new(&artifact.relative_path))
    }

    pub fn resolve_object(
        &self,
        relative_path: &str,
        expected_sha256: &str,
        expected_size: u64,
    ) -> Result<PathBuf, StoreError> {
        let path = self.validated_object_path(relative_path, expected_sha256)?;
        ensure_no_reparse_path(&self.root, &path)?;
        verify_file(&path, expected_sha256, expected_size)?;
        Ok(path)
    }

    pub fn remove_object(&self, relative_path: &str, expected_sha256: &str) -> CleanupOutcome {
        let path = match self.validated_object_path(relative_path, expected_sha256) {
            Ok(path) => path,
            Err(error) => return CleanupOutcome::Deferred(error.to_string()),
        };
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => CleanupOutcome::AlreadyMissing,
            Err(error) => CleanupOutcome::Deferred(error.to_string()),
            Ok(metadata) => {
                if is_reparse_point(&metadata) || !metadata.file_type().is_file() {
                    return CleanupOutcome::Deferred(StoreError::ReparsePoint.to_string());
                }
                if let Err(error) = ensure_no_reparse_path(&self.root, &path) {
                    return CleanupOutcome::Deferred(error.to_string());
                }
                if let Err(error) =
                    make_removable(&path, &metadata).and_then(|()| fs::remove_file(&path))
                {
                    return CleanupOutcome::Deferred(error.to_string());
                }
                CleanupOutcome::Removed
            }
        }
    }

    fn validated_object_path(
        &self,
        relative_path: &str,
        expected_sha256: &str,
    ) -> Result<PathBuf, StoreError> {
        if expected_sha256.len() != 64
            || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(StoreError::InvalidObjectPath);
        }
        let normalized_hash = expected_sha256.to_ascii_lowercase();
        let expected = format!("objects/{}/{}", &normalized_hash[..2], normalized_hash);
        if relative_path.replace('\\', "/") != expected {
            return Err(StoreError::InvalidObjectPath);
        }
        Ok(self.root.join(Path::new(&expected)))
    }
}

fn clean_staging_directory(path: &Path) -> Result<(), StoreError> {
    ensure_regular_directory(path)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_file() && !is_reparse_point(&metadata) {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn verify_file(path: &Path, expected_sha256: &str, expected_size: u64) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if is_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() != expected_size
    {
        return Err(StoreError::IntegrityMismatch);
    }

    let mut reader = BufReader::with_capacity(COPY_BUFFER_BYTES, File::open(path)?);
    let mut hasher = Sha256::new();
    io::copy(&mut reader, &mut HashWriter(&mut hasher))?;
    if format!("{:x}", hasher.finalize()) != expected_sha256 {
        return Err(StoreError::IntegrityMismatch);
    }
    Ok(())
}

fn ensure_regular_directory(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if is_reparse_point(&metadata) || !metadata.file_type().is_dir() {
        Err(StoreError::ReparsePoint)
    } else {
        Ok(())
    }
}

fn ensure_no_reparse_path(root: &Path, target: &Path) -> Result<(), StoreError> {
    ensure_regular_directory(root)?;
    let relative = target
        .strip_prefix(root)
        .map_err(|_| StoreError::InvalidObjectPath)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if is_reparse_point(&metadata) {
            return Err(StoreError::ReparsePoint);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
#[allow(clippy::permissions_set_readonly_false)]
fn make_removable(path: &Path, metadata: &fs::Metadata) -> Result<(), io::Error> {
    let mut permissions = metadata.permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)
}

#[cfg(not(windows))]
fn make_removable(_path: &Path, _metadata: &fs::Metadata) -> Result<(), io::Error> {
    Ok(())
}

fn set_read_only(path: &Path) -> Result<(), io::Error> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)
}

struct HashWriter<'a>(&'a mut Sha256);

impl Write for HashWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.update(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn detect_pe(path: impl AsRef<Path>) -> Result<PeKind, PeError> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let file_size = file.metadata()?.len();
    if file_size < 90 {
        return Err(PeError::InvalidFormat);
    }

    let mut dos_header = [0_u8; 64];
    file.read_exact(&mut dos_header)?;
    if &dos_header[..2] != b"MZ" {
        return Err(PeError::InvalidFormat);
    }

    let pe_offset = u32::from_le_bytes(
        dos_header[0x3c..0x40]
            .try_into()
            .map_err(|_| PeError::InvalidFormat)?,
    ) as u64;
    if pe_offset < 64 || pe_offset.checked_add(26).is_none_or(|end| end > file_size) {
        return Err(PeError::InvalidFormat);
    }

    file.seek(SeekFrom::Start(pe_offset))?;
    let mut pe_header = [0_u8; 26];
    file.read_exact(&mut pe_header)?;
    if &pe_header[..4] != b"PE\0\0" {
        return Err(PeError::InvalidFormat);
    }
    let optional_header_size = u16::from_le_bytes([pe_header[20], pe_header[21]]);
    if optional_header_size < 2 {
        return Err(PeError::InvalidFormat);
    }

    match u16::from_le_bytes([pe_header[24], pe_header[25]]) {
        0x10b => Ok(PeKind::Pe32),
        0x20b => Ok(PeKind::Pe64),
        _ => Err(PeError::InvalidFormat),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeKind {
    Pe32,
    Pe64,
}

#[derive(Debug, Error)]
pub enum PeError {
    #[error("the selected file is not a valid PE32 or PE32+ image")]
    InvalidFormat,
    #[error("PE validation failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_fixture(magic: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; 128];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[84..86].copy_from_slice(&2_u16.to_le_bytes());
        bytes[88..90].copy_from_slice(&magic.to_le_bytes());
        bytes
    }

    #[test]
    fn detects_pe_kind_from_bytes_not_extension() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("sample.txt");
        fs::write(&path, pe_fixture(0x20b)).expect("fixture write");

        assert_eq!(detect_pe(path).expect("valid PE"), PeKind::Pe64);
    }

    #[test]
    fn rejects_invalid_pe_offsets_without_allocating_from_them() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("invalid.exe");
        let mut bytes = pe_fixture(0x10b);
        bytes[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, bytes).expect("fixture write");

        assert!(matches!(detect_pe(path), Err(PeError::InvalidFormat)));
    }

    #[test]
    fn stores_content_once_by_sha256() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.bin");
        fs::write(&source, b"artifacta artifact").expect("fixture write");
        let store = ArtifactStore::open(directory.path().join("store")).expect("store");

        let first = store.ingest(&source).expect("first ingest");
        let second = store.ingest(&source).expect("deduplicated ingest");

        assert_eq!(first, second);
        assert_eq!(first.sha256.len(), 64);
        assert!(store.absolute_path(&first).is_file());
    }

    #[test]
    fn open_cleans_only_regular_staging_files_and_keeps_objects() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("store");
        fs::create_dir_all(root.join("staging/nested")).expect("staging fixture");
        fs::create_dir_all(root.join("objects/aa")).expect("object fixture");
        let stale = root.join("staging/stale.tmp");
        let nested = root.join("staging/nested/keep.tmp");
        let object = root.join("objects/aa/immutable");
        fs::write(&stale, b"stale intake").expect("stale fixture");
        fs::write(&nested, b"nested").expect("nested fixture");
        fs::write(&object, b"immutable object").expect("object fixture");

        ArtifactStore::open(&root).expect("store");

        assert!(!stale.exists());
        assert!(nested.is_file());
        assert_eq!(fs::read(object).expect("object bytes"), b"immutable object");
    }

    #[cfg(unix)]
    #[test]
    fn staging_cleanup_does_not_follow_symbolic_links() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("store");
        let staging = root.join("staging");
        fs::create_dir_all(root.join("objects")).expect("object directory");
        fs::create_dir_all(&staging).expect("staging directory");
        let external = directory.path().join("external.tmp");
        fs::write(&external, b"keep").expect("external fixture");
        symlink(&external, staging.join("linked.tmp")).expect("staging symlink");

        ArtifactStore::open(root).expect("store");

        assert_eq!(fs::read(external).expect("external bytes"), b"keep");
    }

    #[cfg(windows)]
    #[test]
    fn staging_cleanup_does_not_follow_reparse_points_when_supported() {
        use std::os::windows::fs::symlink_file;

        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("store");
        let staging = root.join("staging");
        fs::create_dir_all(root.join("objects")).expect("object directory");
        fs::create_dir_all(&staging).expect("staging directory");
        let external = directory.path().join("external.tmp");
        fs::write(&external, b"keep").expect("external fixture");
        if let Err(error) = symlink_file(&external, staging.join("linked.tmp")) {
            if error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("file symlink: {error}");
        }

        ArtifactStore::open(root).expect("store");

        assert_eq!(fs::read(external).expect("external bytes"), b"keep");
    }

    #[test]
    fn resolves_and_removes_only_the_exact_content_addressed_object() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.bin");
        fs::write(&source, b"artifacta artifact").expect("fixture write");
        let store = ArtifactStore::open(directory.path().join("store")).expect("store");
        let artifact = store.ingest(&source).expect("ingest");

        assert_eq!(
            store
                .resolve_object(
                    &artifact.relative_path,
                    &artifact.sha256,
                    artifact.size_bytes
                )
                .expect("verified object"),
            store.absolute_path(&artifact)
        );
        assert!(matches!(
            store.remove_object("objects/../outside", &artifact.sha256),
            CleanupOutcome::Deferred(_)
        ));
        assert!(store.absolute_path(&artifact).is_file());
        assert_eq!(
            store.remove_object(&artifact.relative_path, &artifact.sha256),
            CleanupOutcome::Removed
        );
        assert_eq!(
            store.remove_object(&artifact.relative_path, &artifact.sha256),
            CleanupOutcome::AlreadyMissing
        );
    }

    #[cfg(windows)]
    #[test]
    fn cleanup_refuses_a_reparse_point_when_symlinks_are_available() {
        use std::os::windows::fs::symlink_file;

        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.bin");
        let external = directory.path().join("external.bin");
        fs::write(&source, b"artifacta artifact").expect("fixture write");
        fs::write(&external, b"do not remove").expect("external write");
        let store = ArtifactStore::open(directory.path().join("store")).expect("store");
        let artifact = store.ingest(&source).expect("ingest");
        let object = store.absolute_path(&artifact);
        let metadata = fs::symlink_metadata(&object).expect("object metadata");
        make_removable(&object, &metadata).expect("object permissions");
        fs::remove_file(&object).expect("remove object for test");
        if let Err(error) = symlink_file(&external, &object) {
            if error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("file symlink: {error}");
        }

        assert!(matches!(
            store.remove_object(&artifact.relative_path, &artifact.sha256),
            CleanupOutcome::Deferred(_)
        ));
        assert_eq!(
            fs::read(&external).expect("external bytes"),
            b"do not remove"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_refuses_a_symbolic_link() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.bin");
        let external = directory.path().join("external.bin");
        fs::write(&source, b"artifacta artifact").expect("fixture write");
        fs::write(&external, b"do not remove").expect("external write");
        let store = ArtifactStore::open(directory.path().join("store")).expect("store");
        let artifact = store.ingest(&source).expect("ingest");
        let object = store.absolute_path(&artifact);
        fs::remove_file(&object).expect("remove object for test");
        symlink(&external, &object).expect("file symlink");

        assert!(matches!(
            store.remove_object(&artifact.relative_path, &artifact.sha256),
            CleanupOutcome::Deferred(_)
        ));
        assert_eq!(
            fs::read(&external).expect("external bytes"),
            b"do not remove"
        );
    }
}
