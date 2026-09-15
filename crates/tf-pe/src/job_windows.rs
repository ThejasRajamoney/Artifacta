//! Documented Windows AppContainer containment for disposable workers.

use std::fs;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree, WAIT_FAILED};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
    DeriveAppContainerSidFromAppContainerName, GetAppContainerFolderPath,
};
use windows_sys::Win32::Security::{FreeSid, PSID, SECURITY_CAPABILITIES};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
    SetDllDirectoryW,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
};

const PROFILE_NAME: &str = "Artifacta.tf-pe.worker";
const WORKER_MODE: &str = "--pe-worker";
const WORKER_EXE: &str = "worker.exe";
const LIMIT_FILE: &str = "broker-memory-limit";
const ERROR_ALREADY_EXISTS_HRESULT: i32 = 0x8007_00b7_u32 as i32;

pub(crate) struct StagedWorker {
    directory: TempDir,
}

impl StagedWorker {
    pub(crate) fn new(executable: &Path, memory_bytes: u64) -> io::Result<Self> {
        let root = appcontainer_folder()?;
        ensure_plain_directory(&root)?;
        let mut directory = tempfile::Builder::new().prefix("run-").tempdir_in(root)?;
        if let Err(error) = ensure_plain_directory(directory.path()) {
            directory.disable_cleanup(true);
            let _ = remove_tree_without_following_reparses(directory.path());
            return Err(error);
        }
        directory.disable_cleanup(true);
        let staged = Self { directory };
        staged.copy_file(executable, WORKER_EXE)?;
        let limit_path = staged.directory.path().join(LIMIT_FILE);
        fs::write(&limit_path, memory_bytes.to_string())?;
        set_read_only(&limit_path)?;
        Ok(staged)
    }

    pub(crate) fn copy_file(&self, source: &Path, name: &str) -> io::Result<PathBuf> {
        let destination = self.directory.path().join(name);
        fs::copy(source, &destination)?;
        set_read_only(&destination)?;
        Ok(destination)
    }

    pub(crate) fn configure_broker(&self, command: &mut std::process::Command) {
        command
            .arg("--pe-broker")
            .current_dir(self.directory.path());
    }
}

impl Drop for StagedWorker {
    fn drop(&mut self) {
        let _ = remove_tree_without_following_reparses(self.directory.path());
    }
}

pub(crate) fn harden_worker_dll_search() -> io::Result<()> {
    let empty = [0_u16];
    // SAFETY: `empty` is a valid NUL-terminated UTF-16 string.
    if unsafe { SetDllDirectoryW(empty.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: these documented flags exclude the CWD and PATH from DLL lookup.
    if unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn run_broker() -> io::Result<u32> {
    let directory = std::env::current_dir()?;
    ensure_plain_directory(&directory)?;
    let worker = directory.join(WORKER_EXE);
    ensure_plain_file(&worker)?;
    let limit_file = directory.join(LIMIT_FILE);
    ensure_plain_file(&limit_file)?;
    let memory_bytes = fs::read_to_string(limit_file)?
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid worker memory limit"))?;
    create_appcontainer_worker(&worker, &directory, memory_bytes, WORKER_MODE)
}

pub(crate) fn cleanup_profile() {
    let name = wide(std::ffi::OsStr::new(PROFILE_NAME));
    // Best-effort uninstall cleanup: absence and in-use profiles must not break uninstall.
    unsafe { DeleteAppContainerProfile(name.as_ptr()) };
}

fn create_appcontainer_worker(
    worker: &Path,
    directory: &Path,
    memory_bytes: u64,
    worker_mode: &str,
) -> io::Result<u32> {
    let stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    let process = spawn_appcontainer_worker(
        worker,
        directory,
        memory_bytes,
        &[worker_mode.to_owned()],
        [stdin, stdout, stderr],
    )?;
    process.wait()
}

fn spawn_appcontainer_worker(
    worker: &Path,
    directory: &Path,
    memory_bytes: u64,
    arguments: &[String],
    handles: [HANDLE; 3],
) -> io::Result<WorkerProcess> {
    let memory = usize::try_from(memory_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "worker memory limit exceeds pointer width",
        )
    })?;
    let sid = derive_profile_sid()?;
    let job = Job::new(memory)?;
    let [stdin, stdout, stderr] = handles;
    if stdin.is_null() || stdout.is_null() || stderr.is_null() {
        return Err(io::Error::last_os_error());
    }
    let jobs = [job.0];
    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: sid.0,
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let mut attributes = AttributeList::new(3)?;
    attributes.update(
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
        std::ptr::from_ref(&capabilities).cast(),
        size_of::<SECURITY_CAPABILITIES>(),
    )?;
    attributes.update(
        PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
        jobs.as_ptr().cast(),
        size_of_val(&jobs),
    )?;
    attributes.update(
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
        handles.as_ptr().cast(),
        size_of_val(&handles),
    )?;

    let worker_wide = wide(worker.as_os_str());
    let directory_wide = wide(directory.as_os_str());
    let mut command = format!("\"{}\"", worker.display());
    for argument in arguments {
        command.push(' ');
        command.push_str(argument);
    }
    let mut command_line = wide(std::ffi::OsStr::new(&command));
    // SAFETY: zero is valid initialization for both documented output/input structures.
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin;
    startup.StartupInfo.hStdOutput = stdout;
    startup.StartupInfo.hStdError = stderr;
    startup.lpAttributeList = attributes.as_ptr();
    // SAFETY: zero provides valid storage for CreateProcessW output.
    let mut process: PROCESS_INFORMATION = unsafe { zeroed() };
    // SAFETY: all pointers remain live through the call; only the listed handles are inherited.
    if unsafe {
        CreateProcessW(
            worker_wide.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null(),
            directory_wide.as_ptr(),
            std::ptr::from_ref(&startup.StartupInfo),
            &mut process,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let process_handle = OwnedHandle(process.hProcess);
    let thread_handle = OwnedHandle(process.hThread);
    drop(thread_handle);
    drop(attributes);
    Ok(WorkerProcess {
        process: process_handle,
        _job: job,
    })
}

struct WorkerProcess {
    process: OwnedHandle,
    _job: Job,
}

impl WorkerProcess {
    fn wait(self) -> io::Result<u32> {
        // Keep `self._job` alive until the worker has terminated.
        if unsafe { WaitForSingleObject(self.process.0, INFINITE) } == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
        let mut code = 0_u32;
        if unsafe { GetExitCodeProcess(self.process.0, &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(code)
    }
}

fn appcontainer_folder() -> io::Result<PathBuf> {
    let name = wide(std::ffi::OsStr::new(PROFILE_NAME));
    let display = wide(std::ffi::OsStr::new("Artifacta analysis worker"));
    let description = wide(std::ffi::OsStr::new(
        "Artifacta zero-capability analysis worker",
    ));
    let mut sid = std::ptr::null_mut();
    // SAFETY: all strings are NUL-terminated and output storage is valid.
    let result = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            display.as_ptr(),
            description.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        )
    };
    if result == ERROR_ALREADY_EXISTS_HRESULT {
        // SAFETY: name and output storage satisfy the documented API contract.
        let derived = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        check_hresult(derived, "DeriveAppContainerSidFromAppContainerName")?;
    } else {
        check_hresult(result, "CreateAppContainerProfile")?;
    }
    if sid.is_null() {
        return Err(io::Error::other("AppContainer profile returned a null SID"));
    }
    let sid = OwnedSid(sid);
    let mut sid_string = std::ptr::null_mut();
    // SAFETY: the profile SID is live and output storage is valid.
    if unsafe { ConvertSidToStringSidW(sid.0, &mut sid_string) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid_string = LocalWide(sid_string);
    let mut folder = std::ptr::null_mut();
    // SAFETY: sid_string is NUL-terminated and output storage is valid.
    let result = unsafe { GetAppContainerFolderPath(sid_string.0, &mut folder) };
    check_hresult(result, "GetAppContainerFolderPath")?;
    if folder.is_null() {
        return Err(io::Error::other(
            "AppContainer profile returned a null folder",
        ));
    }
    let folder = CoTaskWide(folder);
    Ok(PathBuf::from(wide_pointer_to_os_string(folder.0)?))
}

fn derive_profile_sid() -> io::Result<OwnedSid> {
    let name = wide(std::ffi::OsStr::new(PROFILE_NAME));
    let mut sid = std::ptr::null_mut();
    // SAFETY: name is NUL-terminated and output storage is valid.
    let result = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
    check_hresult(result, "DeriveAppContainerSidFromAppContainerName")?;
    if sid.is_null() {
        Err(io::Error::other("AppContainer profile returned a null SID"))
    } else {
        Ok(OwnedSid(sid))
    }
}

fn check_hresult(result: i32, operation: &str) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::other(format!("{operation} failed: {result:#x}")))
    } else {
        Ok(())
    }
}

struct Job(HANDLE);

impl Job {
    fn new(memory: usize) -> io::Result<Self> {
        // SAFETY: null security/name pointers request an unnamed job with default security.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self(handle);
        // SAFETY: zero initializes the documented information structure before fields are set.
        let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        information.BasicLimitInformation.ActiveProcessLimit = 1;
        information.ProcessMemoryLimit = memory;
        information.JobMemoryLimit = memory;
        // SAFETY: handle, information pointer, class, and size satisfy the API contract.
        if unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&information).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: this type uniquely owns the non-null Job handle.
        unsafe { CloseHandle(self.0) };
    }
}

struct AttributeList {
    storage: Vec<usize>,
}

impl AttributeList {
    fn new(count: u32) -> io::Result<Self> {
        let mut bytes = 0_usize;
        // SAFETY: the documented sizing call accepts a null list.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut bytes) };
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut storage = vec![0_usize; bytes.div_ceil(size_of::<usize>())];
        // SAFETY: storage is aligned and contains at least `bytes` writable bytes.
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), count, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { storage })
    }

    fn as_ptr(&mut self) -> windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }

    fn update(
        &mut self,
        attribute: usize,
        value: *const std::ffi::c_void,
        bytes: usize,
    ) -> io::Result<()> {
        // SAFETY: the initialized list is live and each value remains live through CreateProcessW.
        if unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                attribute,
                value,
                bytes,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: this list was initialized successfully and is uniquely owned.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns a non-null process or thread handle.
        unsafe { CloseHandle(self.0) };
    }
}

struct OwnedSid(PSID);

impl Drop for OwnedSid {
    fn drop(&mut self) {
        // SAFETY: profile APIs allocate SIDs that must be released with FreeSid.
        unsafe { FreeSid(self.0) };
    }
}

struct LocalWide(*mut u16);

impl Drop for LocalWide {
    fn drop(&mut self) {
        // SAFETY: ConvertSidToStringSidW allocates this pointer with LocalAlloc.
        unsafe { LocalFree(self.0.cast()) };
    }
}

struct CoTaskWide(*mut u16);

impl Drop for CoTaskWide {
    fn drop(&mut self) {
        // SAFETY: GetAppContainerFolderPath returns task-allocator memory.
        unsafe { CoTaskMemFree(self.0.cast()) };
    }
}

fn set_read_only(path: &Path) -> io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)
}

fn ensure_plain_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged worker is not a plain file",
        ));
    }
    Ok(())
}

fn ensure_plain_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "worker staging path is not a plain directory",
        ));
    }
    Ok(())
}

fn remove_tree_without_following_reparses(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let attributes = metadata.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            fs::remove_dir(path)
        } else {
            make_writable(path).and_then(|()| fs::remove_file(path))
        };
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            remove_tree_without_following_reparses(&entry?.path())?;
        }
        fs::remove_dir(path)
    } else {
        make_writable(path).and_then(|()| fs::remove_file(path))
    }
}

#[allow(clippy::permissions_set_readonly_false)]
fn make_writable(path: &Path) -> io::Result<()> {
    let mut permissions = fs::symlink_metadata(path)?.permissions();
    if permissions.readonly() {
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn wide_pointer_to_os_string(pointer: *const u16) -> io::Result<std::ffi::OsString> {
    use std::os::windows::ffi::OsStringExt;
    let mut length = 0_usize;
    // Windows paths are bounded; reject an unterminated API result rather than scanning forever.
    while length < 32_768 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    if length == 32_768 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "AppContainer folder path is not terminated",
        ));
    }
    // SAFETY: the preceding bounded scan found a terminator after `length` initialized code units.
    Ok(std::ffi::OsString::from_wide(unsafe {
        std::slice::from_raw_parts(pointer, length)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{TcpListener, UdpSocket};
    use std::process::Command;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Security::{
        GetTokenInformation, IsTokenRestricted, SECURITY_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY,
        TokenCapabilities, TokenIsAppContainer,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    #[test]
    #[ignore = "requires appcontainer capabilities unavailable on CI runners"]
    fn zero_capability_appcontainer_denies_tcp() {
        let canary = compile_canary();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TCP control");
        let address = listener.local_addr().expect("TCP control address");
        let nonce = "artifacta-tcp-control";
        let status = Command::new(&canary)
            .args(["tcp", &address.to_string(), nonce])
            .status()
            .expect("run TCP control");
        assert!(status.success());
        assert_eq!(receive_tcp(&listener), Some(nonce.as_bytes().to_vec()));

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind sandbox TCP receiver");
        let address = listener.local_addr().expect("sandbox TCP address");
        let staged = StagedWorker::new(&canary, 64 * 1024 * 1024).expect("stage TCP canary");
        let worker = spawn_test_canary(
            &staged,
            &["tcp".to_owned(), address.to_string(), nonce.to_owned()],
        );
        assert_zero_capability_appcontainer(&worker);
        assert_eq!(worker.wait().expect("wait for TCP canary"), 0);
        assert_eq!(receive_tcp(&listener), None, "sandbox TCP nonce escaped");
    }

    #[test]
    #[ignore = "requires appcontainer capabilities unavailable on CI runners"]
    fn zero_capability_appcontainer_denies_udp() {
        let canary = compile_canary();
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind UDP control");
        let address = receiver.local_addr().expect("UDP control address");
        let nonce = "artifacta-udp-control";
        let status = Command::new(&canary)
            .args(["udp", &address.to_string(), nonce])
            .status()
            .expect("run UDP control");
        assert!(status.success());
        assert_eq!(receive_udp(&receiver), Some(nonce.as_bytes().to_vec()));

        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind sandbox UDP receiver");
        let address = receiver.local_addr().expect("sandbox UDP address");
        let staged = StagedWorker::new(&canary, 64 * 1024 * 1024).expect("stage UDP canary");
        let worker = spawn_test_canary(
            &staged,
            &["udp".to_owned(), address.to_string(), nonce.to_owned()],
        );
        assert_zero_capability_appcontainer(&worker);
        assert_eq!(worker.wait().expect("wait for UDP canary"), 0);
        assert_eq!(receive_udp(&receiver), None, "sandbox UDP nonce escaped");
    }

    fn compile_canary() -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT_CANARY: AtomicUsize = AtomicUsize::new(0);
        let output = std::env::temp_dir().join(format!(
            "artifacta-network-canary-{}-{}.exe",
            std::process::id(),
            NEXT_CANARY.fetch_add(1, Ordering::Relaxed)
        ));
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testfiles/windows_network_canary.rs");
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let status = Command::new(rustc)
            .arg(source)
            .arg("-o")
            .arg(&output)
            .status()
            .expect("compile network canary");
        assert!(status.success(), "network canary compilation failed");
        output
    }

    fn spawn_test_canary(staged: &StagedWorker, arguments: &[String]) -> WorkerProcess {
        let security = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        let mut stdin_read = std::ptr::null_mut();
        let mut stdin_write = std::ptr::null_mut();
        let mut stdout_read = std::ptr::null_mut();
        let mut stdout_write = std::ptr::null_mut();
        let mut stderr_read = std::ptr::null_mut();
        let mut stderr_write = std::ptr::null_mut();
        for (read, write) in [
            (&mut stdin_read, &mut stdin_write),
            (&mut stdout_read, &mut stdout_write),
            (&mut stderr_read, &mut stderr_write),
        ] {
            assert_ne!(unsafe { CreatePipe(read, write, &security, 0) }, 0);
        }
        let handles = [
            OwnedHandle(stdin_read),
            OwnedHandle(stdin_write),
            OwnedHandle(stdout_read),
            OwnedHandle(stdout_write),
            OwnedHandle(stderr_read),
            OwnedHandle(stderr_write),
        ];
        let worker = spawn_appcontainer_worker(
            &staged.directory.path().join(WORKER_EXE),
            staged.directory.path(),
            64 * 1024 * 1024,
            arguments,
            [handles[0].0, handles[3].0, handles[5].0],
        )
        .expect("spawn sandbox canary");
        drop(handles);
        worker
    }

    fn assert_zero_capability_appcontainer(worker: &WorkerProcess) {
        let mut token = std::ptr::null_mut();
        assert_ne!(
            unsafe { OpenProcessToken(worker.process.0, TOKEN_QUERY, &mut token) },
            0
        );
        let token = OwnedHandle(token);
        // AppContainer lowbox tokens are queried separately below; IsTokenRestricted reports
        // only the restricted-SID mechanism and is not the AppContainer predicate.
        let _restricted_sid_token = unsafe { IsTokenRestricted(token.0) };
        let mut is_appcontainer = 0_u32;
        let mut bytes = 0_u32;
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    token.0,
                    TokenIsAppContainer,
                    std::ptr::from_mut(&mut is_appcontainer).cast(),
                    size_of::<u32>() as u32,
                    &mut bytes,
                )
            },
            0
        );
        assert_eq!(is_appcontainer, 1);
        let capabilities = token_information(token.0, TokenCapabilities);
        let groups = unsafe { &*(capabilities.as_ptr().cast::<TOKEN_GROUPS>()) };
        assert_eq!(groups.GroupCount, 0);
    }

    fn token_information(token: HANDLE, class: i32) -> Vec<usize> {
        let mut bytes = 0_u32;
        unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut bytes) };
        assert!(bytes > 0);
        let mut buffer = vec![0_usize; (bytes as usize).div_ceil(size_of::<usize>())];
        assert_ne!(
            unsafe {
                GetTokenInformation(token, class, buffer.as_mut_ptr().cast(), bytes, &mut bytes)
            },
            0
        );
        buffer
    }

    fn receive_tcp(listener: &TcpListener) -> Option<Vec<u8>> {
        listener.set_nonblocking(true).expect("set TCP nonblocking");
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut bytes = Vec::new();
                    stream.read_to_end(&mut bytes).expect("read TCP nonce");
                    return Some(bytes);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept TCP canary: {error}"),
            }
        }
        None
    }

    fn receive_udp(receiver: &UdpSocket) -> Option<Vec<u8>> {
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set UDP timeout");
        let mut bytes = [0_u8; 128];
        match receiver.recv_from(&mut bytes) {
            Ok((count, _)) => Some(bytes[..count].to_vec()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                None
            }
            Err(error) => panic!("receive UDP canary: {error}"),
        }
    }
}
