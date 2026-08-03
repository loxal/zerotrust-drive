// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Version 2 immutable-object storage.
//!
//! V2 never overwrites a referenced data object. Files are sparse radix trees
//! of immutable authenticated chunks; metadata indexes and generation records
//! are immutable objects too. `_root.age` is the only mutable visibility
//! pointer and is atomically switched after every referenced object is durable.

use std::collections::HashSet;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::{
    RecoveryFingerprint, V1_CIPHERTEXT_OVERHEAD, ciphertext_bytes_fingerprint, decrypt_bytes_owned,
    encrypt_bytes, exact_fingerprint,
};
use crate::fault::{self, DurabilityEvent};
use crate::fs::{
    DiskIndex, backing_entry_exists, ensure_no_index_siblings, read_bounded_backing_file,
    validate_disk_index_v2, validate_reachable_v2_files, validate_reachable_v2_files_with_pin,
};

#[path = "v2_gc.rs"]
mod gc;
pub(crate) use gc::{gc_preview, gc_purge, gc_quarantine, gc_restore};

pub(crate) const ROOT_FILE: &str = "_root.age";
pub(crate) const WRITE_MANIFEST: &str = "_write.manifest";
pub(crate) const OBJECT_DIRECTORY: &str = "_zdrive-v2";
pub(crate) const LEGACY_OBJECT_DIRECTORY: &str = ".zdrive-v2";
pub(crate) const CHUNK_SIZE: usize = 4 * 1024 * 1024;
/// Hard cap for one cached FUSE read response. This matches fuser 0.17's
/// maximum request buffer and stays independent of the complete file size.
pub(crate) const MAX_FUSE_READ_SIZE: usize = 16 * 1024 * 1024;
pub(crate) const FORMAT_VERSION: u32 = 2;

pub(crate) const fn platform_supports_atomic_exchange() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

pub(crate) fn probe_atomic_exchange(base_path: &Path) -> std::io::Result<()> {
    if !platform_supports_atomic_exchange() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this platform has no atomic exchange rename",
        ));
    }
    ensure_layout(base_path)?;
    probe_atomic_exchange_internal(base_path, None)
}

pub(crate) fn probe_atomic_exchange_with_pin(
    base_path: &Path,
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<()> {
    namespace_pin.verify(base_path)?;
    probe_atomic_exchange_internal(base_path, Some(namespace_pin))
}

fn probe_atomic_exchange_internal(
    base_path: &Path,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<()> {
    if !platform_supports_atomic_exchange() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this platform has no atomic exchange rename",
        ));
    }
    let evidence = selected_object_directory(base_path)?.join(EVIDENCE_DIRECTORY);
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    let prefix = format!("exchange-probe-{}", to_hex(&id));
    let first = evidence.join(format!("{prefix}-a"));
    let second = evidence.join(format!("{prefix}-b"));
    write_new_file(&first, b"first", "stage atomic-exchange capability probe")?;
    write_new_file(&second, b"second", "stage atomic-exchange capability probe")?;
    rename_exchange(&first, &second)?;
    fault::checkpoint(
        DurabilityEvent::Rename,
        "probe backing-directory atomic exchange support",
    )?;
    if read_bounded_regular(&first, 6)? != b"second"
        || read_bounded_regular(&second, 5)? != b"first"
    {
        return Err(io_invalid(
            "backing directory did not preserve both files across atomic exchange",
        ));
    }
    fs::remove_file(&first)?;
    fault::checkpoint(DurabilityEvent::Cleanup, "clean atomic exchange probe")?;
    fs::remove_file(&second)?;
    fault::checkpoint(DurabilityEvent::Cleanup, "clean atomic exchange probe")?;
    File::open(&evidence)?.sync_all()?;
    fault::checkpoint(
        DurabilityEvent::DirectorySync,
        "persist atomic exchange probe cleanup",
    )?;
    if let Some(pin) = namespace_pin {
        pin.verify(base_path)?;
    }
    Ok(())
}

pub(crate) const OBJECTS_DIRECTORY: &str = "objects";
pub(crate) const EVIDENCE_DIRECTORY: &str = "evidence";
const ROOT_MAGIC: &str = "zerotrust-drive-v2-root";
const ROOT_READY_PREFIX: &str = "_z2-head-";
const MANIFEST_READY_PREFIX: &str = "_z2-manifest-";
const LEGACY_ROOT_READY_PREFIX: &str = "._z2-head-";
const LEGACY_MANIFEST_READY_PREFIX: &str = "._z2-manifest-";
const MANIFEST_VERSION: u32 = 1;
const TREE_FANOUT: u64 = 256;
const MAX_TREE_HEIGHT: u8 = 7;
const MAX_INDEX_CIPHERTEXT: u64 = 64 * 1024 * 1024;
const MAX_METADATA_OBJECT: u64 = 64 * 1024;
pub(crate) const MAX_ROOT_CIPHERTEXT: u64 = MAX_METADATA_OBJECT + V1_CIPHERTEXT_OVERHEAD;
const MAX_MANIFEST_CIPHERTEXT: u64 = 256 * 1024;
const MAX_EVIDENCE_ENTRIES: usize = 250_000;
const OBJECT_AAD_PREFIX: &[u8] = b"zerotrust-drive\0v2\0object\0";
const ROOT_AAD: &[u8] = b"zerotrust-drive\0v2\0root\0";
const MANIFEST_AAD: &[u8] = b"zerotrust-drive\0v2\0normal-write-manifest\0";

/// Pins the exact immutable namespace selected for one mounted writer or
/// recovery transaction. Immutable object publication uses the retained
/// `objects` descriptor rather than resolving the provider-controlled path for
/// each file. Publication-boundary verification additionally requires the
/// canonical namespace, objects, and evidence names to still resolve to these
/// same inodes.
pub(crate) struct V2NamespacePin {
    namespace_path: PathBuf,
    objects_path: PathBuf,
    evidence_path: PathBuf,
    namespace: File,
    objects: File,
    evidence: File,
    #[cfg(unix)]
    namespace_identity: (u64, u64),
    #[cfg(unix)]
    objects_identity: (u64, u64),
    #[cfg(unix)]
    evidence_identity: (u64, u64),
}

impl V2NamespacePin {
    pub(crate) fn capture(base_path: &Path) -> std::io::Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = base_path;
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "pinned v2 namespace descriptors require Unix openat semantics",
            ));
        }
        #[cfg(unix)]
        {
            let namespace_path = selected_object_directory(base_path)?;
            let objects_path = namespace_path.join(OBJECTS_DIRECTORY);
            let evidence_path = namespace_path.join(EVIDENCE_DIRECTORY);
            let namespace = open_directory_nofollow(&namespace_path)?;
            let objects = open_directory_nofollow(&objects_path)?;
            let evidence = open_directory_nofollow(&evidence_path)?;
            let namespace_identity = directory_identity(&namespace, &namespace_path)?;
            let objects_identity = directory_identity(&objects, &objects_path)?;
            let evidence_identity = directory_identity(&evidence, &evidence_path)?;
            let pin = Self {
                namespace_path,
                objects_path,
                evidence_path,
                namespace,
                objects,
                evidence,
                namespace_identity,
                objects_identity,
                evidence_identity,
            };
            pin.verify(base_path)?;
            Ok(pin)
        }
    }

    pub(crate) fn verify(&self, base_path: &Path) -> std::io::Result<()> {
        #[cfg(not(unix))]
        {
            let _ = base_path;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "pinned v2 namespace verification requires Unix inode identity",
            ))
        }
        #[cfg(unix)]
        {
            let selected = selected_object_directory(base_path)?;
            if selected != self.namespace_path {
                return Err(namespace_changed(
                    "the selected immutable v2 namespace name changed during a transaction",
                ));
            }
            verify_pinned_directory(
                &self.namespace,
                &self.namespace_path,
                self.namespace_identity,
                "immutable v2 namespace",
            )?;
            verify_pinned_directory(
                &self.objects,
                &self.objects_path,
                self.objects_identity,
                "immutable v2 objects directory",
            )?;
            verify_pinned_directory(
                &self.evidence,
                &self.evidence_path,
                self.evidence_identity,
                "immutable v2 evidence directory",
            )
        }
    }

    pub(crate) fn verify_at(
        &self,
        base_path: &Path,
        _context: &'static str,
    ) -> std::io::Result<()> {
        #[cfg(test)]
        namespace_test_hook::checkpoint(_context);
        self.verify(base_path)
    }

    fn write_object_file(
        &self,
        base_path: &Path,
        name: &str,
        bytes: &[u8],
        context: &str,
    ) -> std::io::Result<bool> {
        self.verify(base_path)?;
        #[cfg(not(unix))]
        {
            let _ = (name, bytes, context);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "pinned immutable-object publication requires Unix openat semantics",
            ));
        }
        #[cfg(unix)]
        {
            let name = CString::new(name)
                .map_err(|_| io_invalid("immutable v2 object name contains NUL"))?;
            let fd = unsafe {
                libc::openat(
                    self.objects.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    return Ok(false);
                }
                return Err(error);
            }
            let mut file = unsafe { File::from_raw_fd(fd) };
            let created_metadata = file.metadata()?;
            if !created_metadata.is_file() || created_metadata.nlink() != 1 {
                return Err(namespace_changed(
                    "new immutable v2 object did not begin as an exclusive regular file",
                ));
            }
            let created_identity = (created_metadata.dev(), created_metadata.ino());
            file.write_all(bytes)?;
            fault::checkpoint(DurabilityEvent::Write, context)?;
            file.sync_all()?;
            fault::checkpoint(DurabilityEvent::FileSync, context)?;
            drop(file);
            self.objects.sync_all()?;
            fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
            #[cfg(test)]
            namespace_test_hook::checkpoint("before pinned v2 object name verification");
            let verify_fd = unsafe {
                libc::openat(
                    self.objects.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if verify_fd < 0 {
                return Err(namespace_changed(format!(
                    "new immutable v2 object {name:?} disappeared before publication verification: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let mut verified = unsafe { File::from_raw_fd(verify_fd) };
            let verified_metadata = verified.metadata()?;
            if !verified_metadata.is_file()
                || verified_metadata.nlink() != 1
                || (verified_metadata.dev(), verified_metadata.ino()) != created_identity
                || verified_metadata.len() != bytes.len() as u64
            {
                return Err(namespace_changed(format!(
                    "new immutable v2 object {name:?} changed identity, link count, type, or length before publication verification"
                )));
            }
            let mut compared = 0usize;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = verified.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                let end = compared
                    .checked_add(read)
                    .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
                if bytes.get(compared..end) != Some(&buffer[..read]) {
                    return Err(namespace_changed(format!(
                        "new immutable v2 object {name:?} changed bytes before publication verification"
                    )));
                }
                compared = end;
            }
            if compared != bytes.len() {
                return Err(namespace_changed(format!(
                    "new immutable v2 object {name:?} changed length while being verified"
                )));
            }
            self.verify(base_path)?;
            Ok(true)
        }
    }

    fn read_object_file(
        &self,
        base_path: &Path,
        name: &str,
        max_len: u64,
    ) -> std::io::Result<Vec<u8>> {
        self.verify(base_path)?;
        #[cfg(test)]
        namespace_test_hook::checkpoint("before pinned v2 object read");
        #[cfg(not(unix))]
        {
            let _ = (name, max_len);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "pinned immutable-object reads require Unix openat semantics",
            ));
        }
        #[cfg(unix)]
        {
            let name = CString::new(name)
                .map_err(|_| io_invalid("immutable v2 object name contains NUL"))?;
            let fd = unsafe {
                libc::openat(
                    self.objects.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let file = unsafe { File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() > max_len {
                return Err(io_invalid(format!(
                    "pinned immutable v2 object {name:?} is not a bounded regular file"
                )));
            }
            let capacity = usize::try_from(metadata.len())
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(capacity)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
            file.take(max_len.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 != metadata.len() {
                return Err(io_invalid(format!(
                    "pinned immutable v2 object {name:?} changed size while being read"
                )));
            }
            self.verify(base_path)?;
            Ok(bytes)
        }
    }

    fn for_each_evidence_entry(
        &self,
        base_path: &Path,
        visit: impl FnMut(&OsStr) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        self.verify(base_path)?;
        #[cfg(test)]
        namespace_test_hook::checkpoint("before pinned v2 evidence inventory");
        let mut visit = visit;
        let mut count = 0usize;
        for_each_directory_entry_name(&self.evidence, |name| {
            count = count
                .checked_add(1)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
            if count > MAX_EVIDENCE_ENTRIES {
                return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
            }
            visit(name)
        })?;
        self.verify(base_path)?;
        Ok(())
    }

    fn evidence_entry_exists(&self, name: &OsStr) -> std::io::Result<bool> {
        entry_exists_at(&self.evidence, name)
    }

    fn read_evidence_file(&self, name: &OsStr, max_len: u64) -> std::io::Result<Vec<u8>> {
        read_bounded_regular_at(&self.evidence, name, max_len)
    }
}

#[cfg(unix)]
fn c_name(name: &OsStr, label: &str) -> std::io::Result<CString> {
    if name.as_bytes().is_empty() || name.as_bytes().contains(&b'/') {
        return Err(io_invalid(format!(
            "{label} is not a single path component"
        )));
    }
    CString::new(name.as_bytes()).map_err(|_| io_invalid(format!("{label} contains NUL")))
}

#[cfg(unix)]
fn openat_nofollow(
    directory: &File,
    name: &OsStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<File> {
    let name = c_name(name, "pinned v2 entry name")?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            libc::c_uint::from(mode),
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(unix)]
fn entry_exists_at(directory: &File, name: &OsStr) -> std::io::Result<bool> {
    let name = c_name(name, "pinned v2 entry name")?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(true)
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(error)
        }
    }
}

#[cfg(not(unix))]
fn entry_exists_at(_directory: &File, _name: &OsStr) -> std::io::Result<bool> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pinned v2 entry inspection requires openat",
    ))
}

#[cfg(unix)]
fn read_bounded_regular_at(
    directory: &File,
    name: &OsStr,
    max_len: u64,
) -> std::io::Result<Vec<u8>> {
    let file = openat_nofollow(directory, name, libc::O_RDONLY, 0)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_len {
        return Err(io_invalid(format!(
            "pinned v2 entry {name:?} is not a bounded regular file"
        )));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
    file.take(max_len.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(io_invalid(format!(
            "pinned v2 entry {name:?} changed size while being read"
        )));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_bounded_regular_at(
    _directory: &File,
    _name: &OsStr,
    _max_len: u64,
) -> std::io::Result<Vec<u8>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pinned v2 reads require openat",
    ))
}

#[cfg(unix)]
fn set_readdir_errno_zero() {
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = 0;
    }
    #[cfg(target_os = "macos")]
    unsafe {
        *libc::__error() = 0;
    }
}

#[cfg(unix)]
fn for_each_directory_entry_name(
    directory: &File,
    mut visit: impl FnMut(&OsStr) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let dot = CString::new(".").expect("literal has no NUL");
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(error);
    }
    let result = loop {
        set_readdir_errno_zero();
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            break if error.raw_os_error() == Some(0) {
                Ok(())
            } else {
                Err(error)
            };
        }
        let raw_name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if raw_name != b"." && raw_name != b".." {
            let name = OsString::from_vec(raw_name.to_vec());
            if let Err(error) = visit(&name) {
                break Err(error);
            }
        }
    };
    let close_result = unsafe { libc::closedir(stream) };
    result?;
    if close_result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn for_each_directory_entry_name(
    _directory: &File,
    _visit: impl FnMut(&OsStr) -> std::io::Result<()>,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pinned v2 directory scans require openat",
    ))
}

#[cfg(unix)]
fn open_directory_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path)
}

#[cfg(unix)]
fn directory_identity(file: &File, path: &Path) -> std::io::Result<(u64, u64)> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.ino() == 0 {
        return Err(io_invalid(format!(
            "{} has no stable directory identity",
            path.display()
        )));
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(unix)]
fn verify_pinned_directory(
    file: &File,
    path: &Path,
    expected: (u64, u64),
    label: &str,
) -> std::io::Result<()> {
    if directory_identity(file, path)? != expected {
        return Err(namespace_changed(format!(
            "the pinned {label} descriptor changed identity"
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        namespace_changed(format!(
            "the canonical {label} {} cannot be revalidated: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || (metadata.dev(), metadata.ino()) != expected
    {
        return Err(namespace_changed(format!(
            "the canonical {label} {} no longer resolves to the pinned directory",
            path.display()
        )));
    }
    Ok(())
}

fn namespace_changed(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::AlreadyExists, message.into())
}

#[cfg(test)]
mod namespace_test_hook {
    use std::cell::RefCell;

    struct Hook {
        context: &'static str,
        action: Option<Box<dyn FnOnce()>>,
    }

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    pub(super) struct Guard;

    impl Guard {
        pub(super) fn arm(context: &'static str, action: impl FnOnce() + 'static) -> Self {
            HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Hook {
                    context,
                    action: Some(Box::new(action)),
                });
            });
            Self
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            HOOK.with(|hook| *hook.borrow_mut() = None);
        }
    }

    pub(super) fn checkpoint(context: &'static str) {
        let action = HOOK.with(|hook| {
            let mut hook = hook.borrow_mut();
            let hook = hook.as_mut()?;
            (hook.context == context)
                .then(|| hook.action.take())
                .flatten()
        });
        if let Some(action) = action {
            action();
        }
    }
}

#[cfg(test)]
pub(crate) fn arm_namespace_test_hook(
    context: &'static str,
    action: impl FnOnce() + 'static,
) -> impl Drop {
    namespace_test_hook::Guard::arm(context, action)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub(crate) struct ObjectRef {
    id: [u8; 16],
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectKind {
    Data,
    Tree,
    FileRoot,
    Index,
    Generation,
}

impl ObjectKind {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Data => b"data",
            Self::Tree => b"tree",
            Self::FileRoot => b"file-root",
            Self::Index => b"index",
            Self::Generation => b"generation",
        }
    }

    fn max_plaintext_len(self) -> u64 {
        match self {
            Self::Data => CHUNK_SIZE as u64,
            Self::Index => MAX_INDEX_CIPHERTEXT - V1_CIPHERTEXT_OVERHEAD,
            Self::Tree | Self::FileRoot | Self::Generation => MAX_METADATA_OBJECT,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootPointer {
    magic: String,
    format_version: u32,
    generation: ObjectRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Generation {
    format_version: u32,
    number: u64,
    lineage_id: [u8; 16],
    index: ObjectRef,
    previous: Option<ObjectRef>,
    origin: Option<ObjectRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRoot {
    format_version: u32,
    size: u64,
    height: u8,
    tree: Option<ObjectRef>,
}

impl FileRoot {
    fn empty() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            size: 0,
            height: 0,
            tree: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TreeNode {
    format_version: u32,
    height: u8,
    slots: Vec<TreeSlot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TreeSlot {
    slot: u8,
    child: ObjectRef,
}

#[derive(Clone, Debug)]
pub(crate) struct CommitState {
    pub(crate) number: u64,
    pub(crate) generation: ObjectRef,
    pub(crate) parent: Option<ObjectRef>,
    pub(crate) origin: Option<ObjectRef>,
    pub(crate) lineage_id: [u8; 16],
    pub(crate) root_fingerprint: RecoveryFingerprint,
}

#[derive(Debug)]
pub(crate) struct CommitFailure {
    pub(crate) error: std::io::Error,
    pub(crate) recovery_required: bool,
    pub(crate) own_intent_may_be_durable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteManifest {
    manifest_version: u32,
    transaction_id: [u8; 16],
    kdf_fingerprint: RecoveryFingerprint,
    old_root: Option<RecoveryFingerprint>,
    new_root: RecoveryFingerprint,
    previous_generation: Option<ObjectRef>,
    origin_generation: Option<ObjectRef>,
    new_generation: ObjectRef,
    generation_number: u64,
    lineage_id: [u8; 16],
    root_ready_name: String,
    manifest_ready_name: String,
}

fn io_invalid(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn from_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut result = [0u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        result[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(result)
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Blake2s256::digest(bytes).into()
}

fn object_name(id: &[u8; 16]) -> String {
    format!("{}.z2", to_hex(id))
}

pub(crate) fn selected_object_directory(base_path: &Path) -> std::io::Result<PathBuf> {
    let current = base_path.join(OBJECT_DIRECTORY);
    let legacy = base_path.join(LEGACY_OBJECT_DIRECTORY);
    match (
        backing_entry_exists(&current)?,
        backing_entry_exists(&legacy)?,
    ) {
        (true, true) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "both current {} and legacy {} v2 object directories exist; preserve both and reconcile the provider conflict",
                current.display(),
                legacy.display()
            ),
        )),
        (false, true) => Ok(legacy),
        _ => Ok(current),
    }
}

pub(crate) fn ensure_unambiguous_object_directory(base_path: &Path) -> std::io::Result<()> {
    selected_object_directory(base_path).map(|_| ())
}

fn object_path(base_path: &Path, reference: &ObjectRef) -> std::io::Result<PathBuf> {
    Ok(selected_object_directory(base_path)?
        .join(OBJECTS_DIRECTORY)
        .join(object_name(&reference.id)))
}

fn object_aad(kind: ObjectKind, id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(OBJECT_AAD_PREFIX.len() + kind.tag().len() + 1 + id.len());
    aad.extend_from_slice(OBJECT_AAD_PREFIX);
    aad.extend_from_slice(kind.tag());
    aad.push(0);
    aad.extend_from_slice(id);
    aad
}

pub(crate) fn encode_file_root(reference: &ObjectRef) -> String {
    format!("z2:{}:{}", to_hex(&reference.id), to_hex(&reference.digest))
}

pub(crate) fn decode_file_root(value: &str) -> Option<ObjectRef> {
    let mut parts = value.split(':');
    if parts.next()? != "z2" {
        return None;
    }
    let id = from_hex(parts.next()?)?;
    let digest = from_hex(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some(ObjectRef { id, digest })
}

fn ensure_directory(path: &Path, parent: &Path) -> std::io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {
            fault::checkpoint(DurabilityEvent::Write, "create v2 directory")?;
            File::open(parent)?.sync_all()?;
            fault::checkpoint(DurabilityEvent::DirectorySync, "persist v2 directory")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(io_invalid(format!(
            "{} is not a real v2 backing directory",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn ensure_layout(base_path: &Path) -> std::io::Result<()> {
    let v2 = selected_object_directory(base_path)?;
    ensure_directory(&v2, base_path)?;
    ensure_directory(&v2.join(OBJECTS_DIRECTORY), &v2)?;
    ensure_directory(&v2.join(EVIDENCE_DIRECTORY), &v2)
}

fn open_new_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

pub(crate) fn write_new_file(path: &Path, bytes: &[u8], context: &str) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io_invalid("v2 target has no parent directory"))?;
    let mut file = open_new_file(path)?;
    file.write_all(bytes)?;
    fault::checkpoint(DurabilityEvent::Write, context)?;
    file.sync_all()?;
    fault::checkpoint(DurabilityEvent::FileSync, context)?;
    drop(file);
    File::open(parent)?.sync_all()?;
    fault::checkpoint(DurabilityEvent::DirectorySync, context)
}

fn read_bounded_regular(path: &Path, max_len: u64) -> std::io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_len {
        return Err(io_invalid(format!(
            "{} is not a bounded regular file ({} bytes; maximum {max_len})",
            path.display(),
            metadata.len()
        )));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
    file.take(max_len.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(io_invalid(format!(
            "{} changed size while being read",
            path.display()
        )));
    }
    Ok(bytes)
}

#[cfg_attr(not(test), allow(dead_code))]
fn write_object(
    base_path: &Path,
    key: &[u8; 32],
    kind: ObjectKind,
    plaintext: &[u8],
) -> std::io::Result<ObjectRef> {
    write_object_with_pin(base_path, key, kind, plaintext, None)
}

fn write_object_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    kind: ObjectKind,
    plaintext: &[u8],
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<ObjectRef> {
    if plaintext.len() as u64 > kind.max_plaintext_len() {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
    }
    if let Some(pin) = namespace_pin {
        pin.verify(base_path)?;
    } else {
        ensure_layout(base_path)?;
    }
    loop {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let ciphertext =
            encrypt_bytes(key, plaintext, &object_aad(kind, &id)).map_err(std::io::Error::other)?;
        let reference = ObjectRef {
            id,
            digest: digest_bytes(&ciphertext),
        };
        let name = object_name(&reference.id);
        let result = match namespace_pin {
            Some(pin) => {
                pin.write_object_file(base_path, &name, &ciphertext, "publish immutable v2 object")
            }
            None => {
                let path = object_path(base_path, &reference)?;
                match write_new_file(&path, &ciphertext, "publish immutable v2 object") {
                    Ok(()) => Ok(true),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                    Err(error) => Err(error),
                }
            }
        };
        match result {
            Ok(true) => return Ok(reference),
            Ok(false) => continue,
            Err(error) => return Err(error),
        }
    }
}

fn read_object(
    base_path: &Path,
    key: &[u8; 32],
    kind: ObjectKind,
    reference: &ObjectRef,
) -> std::io::Result<Vec<u8>> {
    read_object_with_pin(base_path, key, kind, reference, None)
}

fn read_object_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    kind: ObjectKind,
    reference: &ObjectRef,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<Vec<u8>> {
    let max_ciphertext = kind
        .max_plaintext_len()
        .checked_add(V1_CIPHERTEXT_OVERHEAD)
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    let name = object_name(&reference.id);
    let path = object_path(base_path, reference)?;
    let ciphertext = match namespace_pin {
        Some(pin) => pin.read_object_file(base_path, &name, max_ciphertext)?,
        None => read_bounded_regular(&path, max_ciphertext)?,
    };
    if digest_bytes(&ciphertext) != reference.digest {
        return Err(io_invalid(format!(
            "immutable v2 object {} has the wrong complete ciphertext digest",
            path.display()
        )));
    }
    let plaintext = decrypt_bytes_owned(key, ciphertext, &object_aad(kind, &reference.id))
        .map_err(io_invalid)?;
    if plaintext.len() as u64 > kind.max_plaintext_len() {
        return Err(io_invalid("authenticated v2 object exceeds its type bound"));
    }
    Ok(plaintext)
}

fn serialize_metadata<T: Serialize>(value: &T, label: &str) -> std::io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| io_invalid(format!("serialize v2 {label}: {error}")))?;
    if bytes.len() as u64 > MAX_METADATA_OBJECT {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
    }
    Ok(bytes)
}

fn read_tree(
    base_path: &Path,
    key: &[u8; 32],
    reference: &ObjectRef,
    expected_height: u8,
) -> std::io::Result<TreeNode> {
    read_tree_with_pin(base_path, key, reference, expected_height, None)
}

fn read_tree_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    reference: &ObjectRef,
    expected_height: u8,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<TreeNode> {
    let bytes = read_object_with_pin(base_path, key, ObjectKind::Tree, reference, namespace_pin)?;
    let node: TreeNode = serde_json::from_slice(&bytes)
        .map_err(|error| io_invalid(format!("parse authenticated v2 tree node: {error}")))?;
    if node.format_version != FORMAT_VERSION || node.height != expected_height {
        return Err(io_invalid("v2 tree node version/height mismatch"));
    }
    if node.slots.is_empty() || node.slots.len() > TREE_FANOUT as usize {
        return Err(io_invalid("v2 tree node has an invalid fanout"));
    }
    let mut previous = None;
    for entry in &node.slots {
        if previous.is_some_and(|slot| slot >= entry.slot) {
            return Err(io_invalid("v2 tree slots are not strictly ordered"));
        }
        previous = Some(entry.slot);
    }
    Ok(node)
}

#[cfg_attr(not(test), allow(dead_code))]
fn write_tree(base_path: &Path, key: &[u8; 32], node: &TreeNode) -> std::io::Result<ObjectRef> {
    write_tree_with_pin(base_path, key, node, None)
}

fn write_tree_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    node: &TreeNode,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<ObjectRef> {
    write_object_with_pin(
        base_path,
        key,
        ObjectKind::Tree,
        &serialize_metadata(node, "tree node")?,
        namespace_pin,
    )
}

fn digit(chunk_index: u64, height: u8) -> u8 {
    ((chunk_index >> (u32::from(height) * 8)) & 0xff) as u8
}

fn required_height(chunk_index: u64) -> u8 {
    let mut value = chunk_index;
    let mut height = 0u8;
    while value >= TREE_FANOUT {
        value >>= 8;
        height += 1;
    }
    height
}

fn find_child(node: &TreeNode, slot: u8) -> Option<ObjectRef> {
    node.slots
        .binary_search_by_key(&slot, |entry| entry.slot)
        .ok()
        .map(|index| node.slots[index].child)
}

fn get_chunk_ref(
    base_path: &Path,
    key: &[u8; 32],
    mut node_ref: Option<ObjectRef>,
    mut height: u8,
    chunk_index: u64,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<Option<ObjectRef>> {
    // A short tree addresses only 256^(height + 1) chunks. Without this
    // guard, the radix digits of a far sparse read would wrap and could alias
    // a populated low chunk after a truncate-only growth.
    if required_height(chunk_index) > height {
        return Ok(None);
    }
    while let Some(reference) = node_ref {
        let node = read_tree_with_pin(base_path, key, &reference, height, namespace_pin)?;
        node_ref = find_child(&node, digit(chunk_index, height));
        if height == 0 {
            return Ok(node_ref);
        }
        height -= 1;
    }
    Ok(None)
}

fn cow_set_chunk(
    base_path: &Path,
    key: &[u8; 32],
    node_ref: Option<ObjectRef>,
    height: u8,
    chunk_index: u64,
    data_ref: Option<ObjectRef>,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<Option<ObjectRef>> {
    let mut node = match node_ref {
        Some(reference) => read_tree_with_pin(base_path, key, &reference, height, namespace_pin)?,
        None => TreeNode {
            format_version: FORMAT_VERSION,
            height,
            slots: Vec::new(),
        },
    };
    let slot = digit(chunk_index, height);
    let old_child = find_child(&node, slot);
    let child = if height == 0 {
        data_ref
    } else {
        cow_set_chunk(
            base_path,
            key,
            old_child,
            height - 1,
            chunk_index,
            data_ref,
            namespace_pin,
        )?
    };
    match node.slots.binary_search_by_key(&slot, |entry| entry.slot) {
        Ok(index) => match child {
            Some(child) => node.slots[index].child = child,
            None => {
                node.slots.remove(index);
            }
        },
        Err(index) => {
            if let Some(child) = child {
                node.slots.insert(index, TreeSlot { slot, child });
            }
        }
    }
    if node.slots.is_empty() {
        Ok(None)
    } else {
        write_tree_with_pin(base_path, key, &node, namespace_pin).map(Some)
    }
}

fn grow_tree(
    base_path: &Path,
    key: &[u8; 32],
    mut tree: Option<ObjectRef>,
    mut current_height: u8,
    required: u8,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<(Option<ObjectRef>, u8)> {
    if required > MAX_TREE_HEIGHT {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
    }
    while current_height < required {
        if let Some(child) = tree {
            tree = Some(write_tree_with_pin(
                base_path,
                key,
                &TreeNode {
                    format_version: FORMAT_VERSION,
                    height: current_height + 1,
                    slots: vec![TreeSlot { slot: 0, child }],
                },
                namespace_pin,
            )?);
        }
        current_height += 1;
    }
    Ok((tree, current_height))
}

fn load_file_root(
    base_path: &Path,
    key: &[u8; 32],
    encoded: &str,
    expected_size: u64,
) -> std::io::Result<FileRoot> {
    load_file_root_with_pin(base_path, key, encoded, expected_size, None)
}

fn load_file_root_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    encoded: &str,
    expected_size: u64,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<FileRoot> {
    if encoded.is_empty() {
        if expected_size == 0 {
            return Ok(FileRoot::empty());
        }
        return Err(io_invalid(
            "nonempty v2 file has no authenticated file root",
        ));
    }
    let reference = decode_file_root(encoded)
        .ok_or_else(|| io_invalid("v2 file has an invalid authenticated root reference"))?;
    let bytes = read_object_with_pin(
        base_path,
        key,
        ObjectKind::FileRoot,
        &reference,
        namespace_pin,
    )?;
    let root: FileRoot = serde_json::from_slice(&bytes)
        .map_err(|error| io_invalid(format!("parse authenticated v2 file root: {error}")))?;
    if root.format_version != FORMAT_VERSION
        || root.size != expected_size
        || root.height > MAX_TREE_HEIGHT
        || (root.tree.is_none() && root.height != 0)
    {
        return Err(io_invalid("authenticated v2 file root is inconsistent"));
    }
    Ok(root)
}

#[cfg_attr(not(test), allow(dead_code))]
fn write_file_root(base_path: &Path, key: &[u8; 32], root: &FileRoot) -> std::io::Result<String> {
    write_file_root_with_pin(base_path, key, root, None)
}

fn write_file_root_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    root: &FileRoot,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<String> {
    let reference = write_object_with_pin(
        base_path,
        key,
        ObjectKind::FileRoot,
        &serialize_metadata(root, "file root")?,
        namespace_pin,
    )?;
    Ok(encode_file_root(&reference))
}

fn load_chunk(
    base_path: &Path,
    key: &[u8; 32],
    root: &FileRoot,
    chunk_index: u64,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<Vec<u8>> {
    let Some(reference) = get_chunk_ref(
        base_path,
        key,
        root.tree,
        root.height,
        chunk_index,
        namespace_pin,
    )?
    else {
        return Ok(Vec::new());
    };
    let bytes = read_object_with_pin(base_path, key, ObjectKind::Data, &reference, namespace_pin)?;
    if bytes.len() > CHUNK_SIZE {
        return Err(io_invalid("authenticated v2 data chunk is oversized"));
    }
    Ok(bytes)
}

pub(crate) fn read_file_range(
    base_path: &Path,
    key: &[u8; 32],
    encoded_root: &str,
    file_size: u64,
    offset: u64,
    requested: usize,
) -> std::io::Result<Vec<u8>> {
    if offset >= file_size || requested == 0 {
        return Ok(Vec::new());
    }
    let root = load_file_root(base_path, key, encoded_root, file_size)?;
    let remaining = file_size - offset;
    // Cached FUSE reads must return the complete requested range except at EOF;
    // otherwise the kernel substitutes zeroes for the missing tail. The
    // negotiated request ceiling bounds this response, while the loop below
    // retains only one decrypted data chunk at a time.
    let result_len = usize::try_from(remaining.min(requested as u64))
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    if result_len > MAX_FUSE_READ_SIZE {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(result_len)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
    result.resize(result_len, 0);

    let mut result_offset = 0usize;
    while result_offset < result.len() {
        let absolute = offset
            .checked_add(result_offset as u64)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let chunk_index = absolute / CHUNK_SIZE as u64;
        let within = (absolute % CHUNK_SIZE as u64) as usize;
        let take = (CHUNK_SIZE - within).min(result.len() - result_offset);
        let chunk = load_chunk(base_path, key, &root, chunk_index, None)?;
        if within < chunk.len() {
            let available = take.min(chunk.len() - within);
            result[result_offset..result_offset + available]
                .copy_from_slice(&chunk[within..within + available]);
        }
        result_offset += take;
    }
    Ok(result)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn write_file_range(
    base_path: &Path,
    key: &[u8; 32],
    encoded_root: &str,
    file_size: u64,
    offset: u64,
    data: &[u8],
) -> std::io::Result<(String, u64)> {
    write_file_range_with_pin(base_path, key, encoded_root, file_size, offset, data, None)
}

pub(crate) fn write_file_range_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    encoded_root: &str,
    file_size: u64,
    offset: u64,
    data: &[u8],
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<(String, u64)> {
    if data.is_empty() {
        return Ok((encoded_root.to_string(), file_size));
    }
    if let Some(pin) = namespace_pin {
        pin.verify(base_path)?;
    }
    let end = offset
        .checked_add(data.len() as u64)
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    let mut root = load_file_root_with_pin(base_path, key, encoded_root, file_size, namespace_pin)?;
    let last_chunk = (end - 1) / CHUNK_SIZE as u64;
    let (tree, height) = grow_tree(
        base_path,
        key,
        root.tree,
        root.height,
        required_height(last_chunk),
        namespace_pin,
    )?;
    root.tree = tree;
    root.height = height;

    let mut source_offset = 0usize;
    let mut tree_changed = false;
    while source_offset < data.len() {
        let absolute = offset
            .checked_add(source_offset as u64)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let chunk_index = absolute / CHUNK_SIZE as u64;
        let within = (absolute % CHUNK_SIZE as u64) as usize;
        let take = (CHUNK_SIZE - within).min(data.len() - source_offset);
        let mut chunk = load_chunk(base_path, key, &root, chunk_index, namespace_pin)?;
        let needed = within + take;
        let incoming = &data[source_offset..source_offset + take];
        if incoming
            .iter()
            .enumerate()
            .all(|(index, byte)| chunk.get(within + index).copied().unwrap_or(0) == *byte)
        {
            source_offset += take;
            continue;
        }
        if chunk.len() < needed {
            chunk
                .try_reserve(needed - chunk.len())
                .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
            chunk.resize(needed, 0);
        }
        chunk[within..needed].copy_from_slice(incoming);
        let data_ref = if chunk.iter().all(|byte| *byte == 0) {
            None
        } else {
            Some(write_object_with_pin(
                base_path,
                key,
                ObjectKind::Data,
                &chunk,
                namespace_pin,
            )?)
        };
        root.tree = cow_set_chunk(
            base_path,
            key,
            root.tree,
            root.height,
            chunk_index,
            data_ref,
            namespace_pin,
        )?;
        tree_changed = true;
        source_offset += take;
    }
    if root.tree.is_none() {
        root.height = 0;
    }
    let new_size = root.size.max(end);
    if !tree_changed && new_size == root.size {
        return Ok((encoded_root.to_string(), root.size));
    }
    root.size = new_size;
    let encoded = write_file_root_with_pin(base_path, key, &root, namespace_pin)?;
    if let Some(pin) = namespace_pin {
        pin.verify(base_path)?;
    }
    Ok((encoded, root.size))
}

struct PendingTreeLevel {
    group: Option<u64>,
    slots: Vec<TreeSlot>,
}

struct StreamingTreeBuilder<'a> {
    base_path: &'a Path,
    key: &'a [u8; 32],
    namespace_pin: Option<&'a V2NamespacePin>,
    levels: Vec<PendingTreeLevel>,
}

impl<'a> StreamingTreeBuilder<'a> {
    fn new(base_path: &'a Path, key: &'a [u8; 32]) -> Self {
        Self {
            base_path,
            key,
            namespace_pin: None,
            levels: Vec::new(),
        }
    }

    fn new_with_pin(
        base_path: &'a Path,
        key: &'a [u8; 32],
        namespace_pin: &'a V2NamespacePin,
    ) -> Self {
        Self {
            base_path,
            key,
            namespace_pin: Some(namespace_pin),
            levels: Vec::new(),
        }
    }

    fn ensure_level(&mut self, height: usize) -> std::io::Result<()> {
        while self.levels.len() <= height {
            self.levels
                .try_reserve(1)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(TREE_FANOUT as usize)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
            self.levels.push(PendingTreeLevel { group: None, slots });
        }
        Ok(())
    }

    fn flush_level(&mut self, height: usize) -> std::io::Result<(u64, ObjectRef)> {
        let level = &mut self.levels[height];
        let group = level
            .group
            .take()
            .ok_or_else(|| io_invalid("cannot flush an empty streaming v2 tree level"))?;
        let slots = std::mem::take(&mut level.slots);
        let reference = write_tree_with_pin(
            self.base_path,
            self.key,
            &TreeNode {
                format_version: FORMAT_VERSION,
                height: u8::try_from(height)
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?,
                slots,
            },
            self.namespace_pin,
        )?;
        level
            .slots
            .try_reserve_exact(TREE_FANOUT as usize)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
        Ok((group, reference))
    }

    fn add(&mut self, height: usize, position: u64, child: ObjectRef) -> std::io::Result<()> {
        if height > MAX_TREE_HEIGHT as usize {
            return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
        }
        self.ensure_level(height)?;
        let group = position >> 8;
        if self.levels[height]
            .group
            .is_some_and(|current| current != group)
        {
            let (old_group, reference) = self.flush_level(height)?;
            self.add(height + 1, old_group, reference)?;
        }
        let level = &mut self.levels[height];
        level.group = Some(group);
        level.slots.push(TreeSlot {
            slot: (position & 0xff) as u8,
            child,
        });
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<(Option<ObjectRef>, u8)> {
        if self.levels.is_empty() {
            return Ok((None, 0));
        }
        let mut height = 0usize;
        loop {
            if height >= self.levels.len() {
                return Err(io_invalid("streaming v2 tree lost its root"));
            }
            if self.levels[height].group.is_none() {
                height += 1;
                continue;
            }
            let (group, reference) = self.flush_level(height)?;
            let has_higher = self
                .levels
                .iter()
                .skip(height + 1)
                .any(|level| level.group.is_some());
            if group == 0 && !has_higher {
                return Ok((
                    Some(reference),
                    u8::try_from(height)
                        .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?,
                ));
            }
            self.add(height + 1, group, reference)?;
            height += 1;
        }
    }
}

/// Convert one already-authenticated legacy plaintext into its final immutable
/// v2 tree without publishing an intermediate file root for every chunk. The
/// builder retains at most one 256-entry node per tree level.
#[allow(dead_code)]
pub(crate) fn import_authenticated_file(
    base_path: &Path,
    key: &[u8; 32],
    plaintext: &[u8],
) -> std::io::Result<String> {
    import_authenticated_file_internal(base_path, key, plaintext, None)
}

pub(crate) fn import_authenticated_file_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    plaintext: &[u8],
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<String> {
    import_authenticated_file_internal(base_path, key, plaintext, Some(namespace_pin))
}

fn import_authenticated_file_internal(
    base_path: &Path,
    key: &[u8; 32],
    plaintext: &[u8],
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<String> {
    let mut builder = match namespace_pin {
        Some(pin) => StreamingTreeBuilder::new_with_pin(base_path, key, pin),
        None => StreamingTreeBuilder::new(base_path, key),
    };
    for (chunk_index, chunk) in plaintext.chunks(CHUNK_SIZE).enumerate() {
        if chunk.iter().all(|byte| *byte == 0) {
            continue;
        }
        let chunk_index = u64::try_from(chunk_index)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let data = write_object_with_pin(base_path, key, ObjectKind::Data, chunk, namespace_pin)?;
        builder.add(0, chunk_index, data)?;
    }
    let (tree, height) = builder.finish()?;
    let size = u64::try_from(plaintext.len())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    if size == 0 {
        return Ok(String::new());
    }
    write_file_root_with_pin(
        base_path,
        key,
        &FileRoot {
            format_version: FORMAT_VERSION,
            size,
            height,
            tree,
        },
        namespace_pin,
    )
}

fn prune_after(
    base_path: &Path,
    key: &[u8; 32],
    reference: ObjectRef,
    height: u8,
    max_chunk: u64,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<Option<ObjectRef>> {
    let original = read_tree_with_pin(base_path, key, &reference, height, namespace_pin)?;
    let max_slot = digit(max_chunk, height);
    let mut node = original.clone();
    node.slots.retain(|entry| entry.slot <= max_slot);
    if height > 0
        && let Ok(index) = node
            .slots
            .binary_search_by_key(&max_slot, |entry| entry.slot)
    {
        let child = prune_after(
            base_path,
            key,
            node.slots[index].child,
            height - 1,
            max_chunk,
            namespace_pin,
        )?;
        match child {
            Some(child) => node.slots[index].child = child,
            None => {
                node.slots.remove(index);
            }
        }
    }
    if node.slots.is_empty() {
        Ok(None)
    } else if node == original {
        Ok(Some(reference))
    } else {
        write_tree_with_pin(base_path, key, &node, namespace_pin).map(Some)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn truncate_file(
    base_path: &Path,
    key: &[u8; 32],
    encoded_root: &str,
    old_size: u64,
    new_size: u64,
) -> std::io::Result<String> {
    truncate_file_with_pin(base_path, key, encoded_root, old_size, new_size, None)
}

pub(crate) fn truncate_file_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    encoded_root: &str,
    old_size: u64,
    new_size: u64,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<String> {
    if old_size == new_size {
        return Ok(encoded_root.to_string());
    }
    if let Some(pin) = namespace_pin {
        pin.verify(base_path)?;
    }
    let mut root = load_file_root_with_pin(base_path, key, encoded_root, old_size, namespace_pin)?;
    if new_size == 0 {
        root.tree = None;
        root.height = 0;
    } else if new_size < old_size {
        let max_chunk = (new_size - 1) / CHUNK_SIZE as u64;
        if let Some(tree) = root.tree
            && required_height(max_chunk) <= root.height
        {
            root.tree = prune_after(base_path, key, tree, root.height, max_chunk, namespace_pin)?;
        }
        let tail_len = (new_size % CHUNK_SIZE as u64) as usize;
        if tail_len != 0 {
            let mut tail = load_chunk(base_path, key, &root, max_chunk, namespace_pin)?;
            if tail.len() > tail_len {
                tail.truncate(tail_len);
                let data_ref = if tail.iter().all(|byte| *byte == 0) {
                    None
                } else {
                    Some(write_object_with_pin(
                        base_path,
                        key,
                        ObjectKind::Data,
                        &tail,
                        namespace_pin,
                    )?)
                };
                root.tree = cow_set_chunk(
                    base_path,
                    key,
                    root.tree,
                    root.height,
                    max_chunk,
                    data_ref,
                    namespace_pin,
                )?;
            }
        }
    }
    if root.tree.is_none() {
        root.height = 0;
    }
    root.size = new_size;
    let encoded = write_file_root_with_pin(base_path, key, &root, namespace_pin)?;
    if let Some(pin) = namespace_pin {
        pin.verify(base_path)?;
    }
    Ok(encoded)
}

fn write_generation(
    base_path: &Path,
    key: &[u8; 32],
    index_json: &[u8],
    previous: Option<&CommitState>,
    initial_lineage: Option<[u8; 16]>,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<(ObjectRef, u64, [u8; 16])> {
    if index_json.len() as u64 > ObjectKind::Index.max_plaintext_len() {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
    }
    let index =
        write_object_with_pin(base_path, key, ObjectKind::Index, index_json, namespace_pin)?;
    let number = previous
        .map_or(Ok(1), |state| state.number.checked_add(1).ok_or(()))
        .map_err(|()| std::io::Error::from_raw_os_error(libc::EOVERFLOW))?;
    if previous.is_some() && initial_lineage.is_some() {
        return Err(io_invalid(
            "an existing v2 lineage cannot be replaced during commit",
        ));
    }
    let lineage_id = previous.map(|state| state.lineage_id).unwrap_or_else(|| {
        let mut lineage = [0u8; 16];
        OsRng.fill_bytes(&mut lineage);
        lineage
    });
    let lineage_id = initial_lineage.unwrap_or(lineage_id);
    let generation = Generation {
        format_version: FORMAT_VERSION,
        number,
        lineage_id,
        index,
        previous: previous.map(|state| state.generation),
        origin: previous.map(|state| state.origin.unwrap_or(state.generation)),
    };
    let reference = write_object_with_pin(
        base_path,
        key,
        ObjectKind::Generation,
        &serialize_metadata(&generation, "generation")?,
        namespace_pin,
    )?;
    Ok((reference, number, lineage_id))
}

fn prepare_root(
    key: &[u8; 32],
    generation: ObjectRef,
) -> std::io::Result<(Vec<u8>, RecoveryFingerprint)> {
    let pointer = RootPointer {
        magic: ROOT_MAGIC.to_string(),
        format_version: FORMAT_VERSION,
        generation,
    };
    let plaintext = serialize_metadata(&pointer, "root pointer")?;
    let ciphertext = encrypt_bytes(key, &plaintext, ROOT_AAD).map_err(std::io::Error::other)?;
    let fingerprint = ciphertext_bytes_fingerprint(&ciphertext).map_err(std::io::Error::other)?;
    Ok((ciphertext, fingerprint))
}

fn root_fingerprint(base_path: &Path) -> std::io::Result<Option<RecoveryFingerprint>> {
    let path = base_path.join(ROOT_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let bytes = read_bounded_backing_file(&path, MAX_ROOT_CIPHERTEXT)?;
            ciphertext_bytes_fingerprint(&bytes)
                .map(Some)
                .map_err(std::io::Error::other)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn validate_manifest(manifest: &WriteManifest) -> std::io::Result<()> {
    let transaction_hex = to_hex(&manifest.transaction_id);
    let canonical_ready_names = manifest.root_ready_name
        == format!("{ROOT_READY_PREFIX}{transaction_hex}.ready")
        && manifest.manifest_ready_name
            == format!("{MANIFEST_READY_PREFIX}{transaction_hex}.ready");
    let legacy_ready_names = manifest.root_ready_name
        == format!("{LEGACY_ROOT_READY_PREFIX}{transaction_hex}.ready")
        && manifest.manifest_ready_name
            == format!("{LEGACY_MANIFEST_READY_PREFIX}{transaction_hex}.ready");
    if manifest.manifest_version != MANIFEST_VERSION
        || manifest.generation_number == 0
        || ((manifest.generation_number == 1) != manifest.old_root.is_none())
        || (manifest.generation_number == 1
            && (manifest.previous_generation.is_some() || manifest.origin_generation.is_some()))
        || (manifest.generation_number > 1
            && (manifest.previous_generation.is_none() || manifest.origin_generation.is_none()))
        || !manifest.kdf_fingerprint.is_exact()
        || manifest
            .old_root
            .as_ref()
            .is_some_and(|value| !value.has_full_content_identity())
        || !manifest.new_root.has_full_content_identity()
        || (!canonical_ready_names && !legacy_ready_names)
    {
        return Err(io_invalid("authenticated v2 write manifest is malformed"));
    }
    Ok(())
}

fn decode_manifest_ciphertext(
    key: &[u8; 32],
    ciphertext: Vec<u8>,
) -> std::io::Result<WriteManifest> {
    let plaintext = decrypt_bytes_owned(key, ciphertext, MANIFEST_AAD)
        .map_err(|error| io_invalid(format!("authenticate v2 write manifest: {error}")))?;
    let manifest: WriteManifest = serde_json::from_slice(&plaintext)
        .map_err(|error| io_invalid(format!("parse authenticated v2 write manifest: {error}")))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Validate retained normal-write manifests before treating an absent
/// canonical manifest as a completed transaction. This closes the race where
/// a sync provider replaces `_write.manifest` between our byte comparison and
/// namespace move: the raced bytes remain under the transaction-bound
/// retained name and are rejected here on the next mount.
fn audit_manifest_evidence(
    base_path: &Path,
    key: &[u8; 32],
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<()> {
    let evidence = namespace_pin.map_or_else(
        || selected_object_directory(base_path).map(|path| path.join(EVIDENCE_DIRECTORY)),
        |pin| Ok(pin.evidence_path.clone()),
    )?;
    let mut validated_generations = HashSet::new();
    if let Some(pin) = namespace_pin {
        pin.for_each_evidence_entry(base_path, |raw_name| {
            audit_manifest_evidence_entry(
                base_path,
                &evidence,
                key,
                raw_name,
                Some(pin),
                &mut validated_generations,
            )
        })
    } else {
        let entries = match fs::read_dir(&evidence) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        for entry in entries {
            let raw_name = entry?.file_name();
            audit_manifest_evidence_entry(
                base_path,
                &evidence,
                key,
                &raw_name,
                None,
                &mut validated_generations,
            )?;
        }
        Ok(())
    }
}

fn audit_manifest_evidence_entry(
    base_path: &Path,
    evidence: &Path,
    key: &[u8; 32],
    raw_name: &OsStr,
    namespace_pin: Option<&V2NamespacePin>,
    validated_generations: &mut HashSet<ObjectRef>,
) -> std::io::Result<()> {
    let Some(name) = raw_name.to_str().map(str::to_string) else {
        return Err(io_invalid(
            "v2 evidence directory contains a non-UTF-8 entry",
        ));
    };
    let Some(rest) = name.strip_prefix("normal-") else {
        return Ok(());
    };
    let transaction_hex = rest
        .get(..32)
        .ok_or_else(|| io_invalid("v2 evidence has a truncated transaction name"))?;
    let transaction_id = from_hex::<16>(transaction_hex)
        .ok_or_else(|| io_invalid("v2 manifest evidence has an invalid transaction name"))?;
    let suffix = rest
        .get(32..)
        .ok_or_else(|| io_invalid("v2 evidence has an invalid transaction name"))?;
    let numbered_retained = |value: &str| {
        value.strip_prefix("retained-").is_some_and(|number| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        })
    };
    let manifest_suffix = suffix.strip_prefix("-manifest.");
    let manifest_ready_suffix = suffix.strip_prefix("-manifest-ready.");
    let root_suffix = suffix.strip_prefix("-root.");
    let allowed = manifest_suffix
        .is_some_and(|value| value == "durable" || value == "retained" || numbered_retained(value))
        || manifest_ready_suffix
            .is_some_and(|value| value == "retained" || numbered_retained(value))
        || root_suffix.is_some_and(|value| value == "retained" || numbered_retained(value));
    if !allowed {
        return Err(io_invalid(format!(
            "v2 evidence directory contains an unexpected or provider-conflicted transaction entry {name:?}"
        )));
    }
    let read_evidence = |name: &OsStr| match namespace_pin {
        Some(pin) => pin.read_evidence_file(name, MAX_MANIFEST_CIPHERTEXT),
        None => read_bounded_regular(&evidence.join(name), MAX_MANIFEST_CIPHERTEXT),
    };
    let Some(manifest_suffix) = manifest_suffix else {
        if let Some(ready_suffix) = manifest_ready_suffix {
            let ciphertext = read_evidence(raw_name)?;
            let manifest = decode_manifest_ciphertext(key, ciphertext).map_err(|error| {
                io_invalid(format!(
                    "retained v2 manifest-ready evidence {} is not authentic: {error}",
                    evidence.join(raw_name).display()
                ))
            })?;
            if manifest.transaction_id != transaction_id {
                return Err(io_invalid(format!(
                    "retained v2 manifest-ready evidence {} is bound to a different transaction",
                    evidence.join(raw_name).display()
                )));
            }
            validate_manifest_new_lineage(
                base_path,
                key,
                &manifest,
                namespace_pin,
                validated_generations,
            )
            .map_err(|error| {
                io_invalid(format!(
                    "retained v2 manifest-ready evidence {} does not retain its complete authenticated new-generation lineage: {error}",
                    evidence.join(raw_name).display()
                ))
            })?;
            debug_assert!(ready_suffix == "retained" || numbered_retained(ready_suffix));
        }
        return Ok(());
    };
    let ciphertext = read_evidence(raw_name)?;
    let manifest = decode_manifest_ciphertext(key, ciphertext.clone()).map_err(|error| {
        io_invalid(format!(
            "retained v2 manifest evidence {} is not authentic: {error}",
            evidence.join(raw_name).display()
        ))
    })?;
    if manifest.transaction_id != transaction_id {
        return Err(io_invalid(format!(
            "retained v2 manifest evidence {} is bound to a different transaction",
            evidence.join(raw_name).display()
        )));
    }
    if let Some(expected_old_root) = manifest.old_root.as_ref() {
        let root_name = OsString::from(format!("normal-{transaction_hex}-root.retained"));
        let root_bytes = match namespace_pin {
            Some(pin) => pin.read_evidence_file(&root_name, MAX_ROOT_CIPHERTEXT),
            None => read_bounded_regular(&evidence.join(&root_name), MAX_ROOT_CIPHERTEXT),
        }
        .map_err(|error| {
            io_invalid(format!(
                "completed v2 manifest evidence {} has no readable displaced-root evidence: {error}",
                evidence.join(raw_name).display()
            ))
        })?;
        let actual_old_root =
            ciphertext_bytes_fingerprint(&root_bytes).map_err(std::io::Error::other)?;
        if &actual_old_root != expected_old_root {
            return Err(io_invalid(format!(
                "displaced-root evidence for completed v2 manifest {} differs from its authenticated old root",
                evidence.join(raw_name).display()
            )));
        }
        let (old_index, old_state) = match namespace_pin {
            Some(pin) => load_root_bytes_with_pin(base_path, key, root_bytes, Some(pin)),
            None => load_root_bytes(base_path, key, root_bytes),
        }
        .map_err(|error| {
            io_invalid(format!(
                "displaced-root evidence for completed v2 manifest {} cannot load its authenticated generation: {error}",
                evidence.join(raw_name).display()
            ))
        })?;
        validate_completed_manifest_old_lineage(
            base_path,
            key,
            &manifest,
            &old_index,
            &old_state,
            namespace_pin,
            validated_generations,
        )
        .map_err(|error| {
            io_invalid(format!(
                "displaced-root evidence for completed v2 manifest {} does not retain a complete authenticated generation lineage: {error}",
                evidence.join(raw_name).display()
            ))
        })?;
    }
    validate_manifest_new_lineage(
        base_path,
        key,
        &manifest,
        namespace_pin,
        validated_generations,
    )
    .map_err(|error| {
        io_invalid(format!(
            "retained v2 manifest evidence {} does not retain its complete authenticated new-generation lineage: {error}",
            evidence.join(raw_name).display()
        ))
    })?;
    if manifest_suffix != "durable" {
        let durable_name = OsString::from(format!("normal-{transaction_hex}-manifest.durable"));
        let expected = read_evidence(&durable_name).map_err(|error| {
            io_invalid(format!(
                "retained v2 manifest evidence {} has no readable durable anchor: {error}",
                evidence.join(raw_name).display()
            ))
        })?;
        if ciphertext != expected {
            return Err(io_invalid(format!(
                "retained v2 manifest evidence {} differs from its durable transaction anchor",
                evidence.join(raw_name).display()
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_noreplace(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let source = CString::new(source.as_os_str().as_bytes())?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_noreplace(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let source = CString::new(source.as_os_str().as_bytes())?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_noreplace(_source: &Path, _target: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace rename is unavailable",
    ))
}

#[cfg(target_os = "linux")]
fn renameat_noreplace(
    source_directory: &File,
    source_name: &OsStr,
    target_directory: &File,
    target_name: &OsStr,
) -> std::io::Result<()> {
    let source_name = c_name(source_name, "v2 evidence source name")?;
    let target_name = c_name(target_name, "v2 evidence target name")?;
    let result = unsafe {
        libc::renameat2(
            source_directory.as_raw_fd(),
            source_name.as_ptr(),
            target_directory.as_raw_fd(),
            target_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn renameat_noreplace(
    source_directory: &File,
    source_name: &OsStr,
    target_directory: &File,
    target_name: &OsStr,
) -> std::io::Result<()> {
    let source_name = c_name(source_name, "v2 evidence source name")?;
    let target_name = c_name(target_name, "v2 evidence target name")?;
    let result = unsafe {
        libc::renameatx_np(
            source_directory.as_raw_fd(),
            source_name.as_ptr(),
            target_directory.as_raw_fd(),
            target_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn renameat_noreplace(
    _source_directory: &File,
    _source_name: &OsStr,
    _target_directory: &File,
    _target_name: &OsStr,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic pinned no-replace rename is unavailable",
    ))
}

#[cfg(unix)]
fn linkat_noreplace(
    source_directory: &File,
    source_name: &OsStr,
    target_directory: &File,
    target_name: &OsStr,
) -> std::io::Result<()> {
    let source_name = c_name(source_name, "v2 evidence source name")?;
    let target_name = c_name(target_name, "v2 evidence target name")?;
    let result = unsafe {
        libc::linkat(
            source_directory.as_raw_fd(),
            source_name.as_ptr(),
            target_directory.as_raw_fd(),
            target_name.as_ptr(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn linkat_noreplace(
    _source_directory: &File,
    _source_name: &OsStr,
    _target_directory: &File,
    _target_name: &OsStr,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic pinned evidence linking is unavailable",
    ))
}

#[cfg(target_os = "linux")]
fn rename_exchange(first: &Path, second: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let first = CString::new(first.as_os_str().as_bytes())?;
    let second = CString::new(second.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            first.as_ptr(),
            libc::AT_FDCWD,
            second.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_exchange(first: &Path, second: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let first = CString::new(first.as_os_str().as_bytes())?;
    let second = CString::new(second.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            first.as_ptr(),
            libc::AT_FDCWD,
            second.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_exchange(_first: &Path, _second: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic exchange rename is unavailable",
    ))
}

pub(crate) fn publish_noreplace(source: &Path, target: &Path) -> std::io::Result<bool> {
    match rename_noreplace(source, target) {
        Ok(()) => {
            fault::checkpoint(DurabilityEvent::Rename, "publish authenticated v2 manifest")?;
            Ok(false)
        }
        Err(rename_error) if rename_error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(rename_error)
        }
        Err(rename_error) => match fs::hard_link(source, target) {
            Ok(()) => {
                fault::checkpoint(DurabilityEvent::Rename, "publish authenticated v2 manifest")?;
                Ok(true)
            }
            Err(link_error) => Err(std::io::Error::other(format!(
                "cannot publish {} without replacement (no-replace rename: {rename_error}; hard link: {link_error})",
                target.display()
            ))),
        },
    }
}

fn fingerprint_file(path: &Path, max_len: u64) -> std::io::Result<RecoveryFingerprint> {
    let bytes = read_bounded_regular(path, max_len)?;
    ciphertext_bytes_fingerprint(&bytes).map_err(std::io::Error::other)
}

/// Publish the staged root without ever overwriting unexamined bytes. Updates
/// exchange the staged and canonical names atomically, leaving the displaced
/// old root at the staging name. An initial generation uses no-replace
/// publication. Thus every namespace state contains either the complete old
/// root, the complete new root, or both.
fn publish_root(
    base_path: &Path,
    root_ready: &Path,
    manifest: &WriteManifest,
) -> std::io::Result<bool> {
    let root_path = base_path.join(ROOT_FILE);
    if root_fingerprint(base_path)? != manifest.old_root
        || fingerprint_file(root_ready, MAX_ROOT_CIPHERTEXT)? != manifest.new_root
    {
        return Err(io_invalid(
            "canonical or staged v2 root changed immediately before atomic publication",
        ));
    }
    let retained_ready = if manifest.old_root.is_some() {
        rename_exchange(root_ready, &root_path)?;
        fault::checkpoint(
            DurabilityEvent::Rename,
            "atomically exchange authenticated v2 root",
        )?;
        true
    } else {
        publish_noreplace(root_ready, &root_path)?
    };
    File::open(base_path)?.sync_all()?;
    fault::checkpoint(
        DurabilityEvent::DirectorySync,
        "persist authenticated v2 root publication",
    )?;

    // Inspect the displaced name first. If it is the exact old root, we can
    // safely restore it even when the new canonical name became unreadable due
    // to a same-path provider race.
    let displaced = if retained_ready {
        fingerprint_file(root_ready, MAX_ROOT_CIPHERTEXT).map(Some)
    } else {
        Ok(None)
    };
    let canonical = root_fingerprint(base_path);
    let expected_displaced = manifest.old_root.as_ref().unwrap_or(&manifest.new_root);
    if canonical
        .as_ref()
        .is_ok_and(|value| value.as_ref() == Some(&manifest.new_root))
        && displaced
            .as_ref()
            .is_ok_and(|value| !retained_ready || value.as_ref() == Some(expected_displaced))
    {
        return Ok(retained_ready);
    }

    // If the atomic exchange displaced the exact authenticated old root, put
    // it back before failing. Whatever raced into the canonical name is moved
    // to the staging name and remains evidence. A crash around either exchange
    // is still recoverable from the durable manifest.
    if manifest.old_root.is_some()
        && displaced
            .as_ref()
            .is_ok_and(|value| value.as_ref() == manifest.old_root.as_ref())
        && backing_entry_exists(root_ready)?
        && backing_entry_exists(&root_path)?
    {
        rename_exchange(root_ready, &root_path)?;
        fault::checkpoint(
            DurabilityEvent::Rename,
            "roll back conflicted authenticated v2 root exchange",
        )?;
        File::open(base_path)?.sync_all()?;
        fault::checkpoint(
            DurabilityEvent::DirectorySync,
            "persist conflicted v2 root rollback",
        )?;
    }
    Err(io_invalid(
        "v2 root publication encountered changed canonical or staging bytes; preserving all generations and transaction evidence",
    ))
}

fn evidence_name(stem: &str, suffix: &str) -> std::io::Result<String> {
    if stem.is_empty()
        || stem.len() > 160
        || !stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(io_invalid("invalid v2 evidence name"));
    }
    if suffix.is_empty()
        || suffix.len() > 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(io_invalid("invalid v2 evidence suffix"));
    }
    Ok(format!("{stem}.{suffix}"))
}

fn evidence_path(base_path: &Path, stem: &str, suffix: &str) -> std::io::Result<PathBuf> {
    Ok(selected_object_directory(base_path)?
        .join(EVIDENCE_DIRECTORY)
        .join(evidence_name(stem, suffix)?))
}

fn retained_fingerprint_with_pin(
    base_path: &Path,
    evidence_stem: &str,
    max_len: u64,
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<Option<RecoveryFingerprint>> {
    namespace_pin.verify(base_path)?;
    let retained = OsString::from(evidence_name(evidence_stem, "retained")?);
    let fingerprint = match namespace_pin.read_evidence_file(&retained, max_len) {
        Ok(bytes) => ciphertext_bytes_fingerprint(&bytes)
            .map(Some)
            .map_err(std::io::Error::other),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }?;
    namespace_pin.verify(base_path)?;
    Ok(fingerprint)
}

fn verify_retained(path: &Path, expected: &[u8]) -> std::io::Result<()> {
    let actual = read_bounded_regular(path, expected.len() as u64)?;
    if actual != expected {
        return Err(io_invalid(format!(
            "retained transaction evidence {} differs from its authenticated expected bytes",
            path.display()
        )));
    }
    Ok(())
}

fn verify_retained_at(
    namespace_pin: &V2NamespacePin,
    name: &OsStr,
    expected: &[u8],
) -> std::io::Result<()> {
    let actual = namespace_pin.read_evidence_file(name, expected.len() as u64)?;
    if actual != expected {
        return Err(io_invalid(format!(
            "retained pinned transaction evidence {name:?} differs from its authenticated expected bytes"
        )));
    }
    Ok(())
}

fn source_parent_and_name(path: &Path) -> std::io::Result<(File, OsString)> {
    let parent = path
        .parent()
        .ok_or_else(|| io_invalid("v2 transaction evidence has no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io_invalid("v2 transaction evidence has no file name"))?
        .to_os_string();
    Ok((open_directory_nofollow(parent)?, name))
}

pub(crate) fn retain_known_file_with_pin(
    base_path: &Path,
    path: &Path,
    expected: &[u8],
    evidence_stem: &str,
    context: &str,
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<()> {
    namespace_pin.verify(base_path)?;
    let retained = OsString::from(evidence_name(evidence_stem, "retained")?);
    let (source_parent, source_name) = source_parent_and_name(path)?;
    match read_bounded_regular_at(&source_parent, &source_name, expected.len() as u64) {
        Ok(actual) if actual == expected => {}
        Ok(_) => {
            return Err(io_invalid(format!(
                "refusing to retain changed v2 transaction evidence as if it were known {}",
                path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match namespace_pin.evidence_entry_exists(&retained)? {
                true => {
                    verify_retained_at(namespace_pin, &retained, expected)?;
                    namespace_pin.evidence.sync_all()?;
                    fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
                    source_parent.sync_all()?;
                    fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
                    namespace_pin.verify(base_path)
                }
                false => Err(namespace_changed(format!(
                    "known v2 transaction evidence {} disappeared before it reached the pinned evidence directory",
                    path.display()
                ))),
            };
        }
        Err(error) => return Err(error),
    }
    let target = if !namespace_pin.evidence_entry_exists(&retained)? {
        retained
    } else {
        verify_retained_at(namespace_pin, &retained, expected)?;
        let mut duplicate = None;
        for number in 1..=1024u16 {
            let candidate =
                OsString::from(evidence_name(evidence_stem, &format!("retained-{number}"))?);
            if namespace_pin.evidence_entry_exists(&candidate)? {
                verify_retained_at(namespace_pin, &candidate, expected)?;
            } else {
                duplicate = Some(candidate);
                break;
            }
        }
        duplicate.ok_or_else(|| io_invalid("too many replayed v2 evidence names"))?
    };
    #[cfg(test)]
    namespace_test_hook::checkpoint("before pinned v2 evidence rename");
    renameat_noreplace(
        &source_parent,
        &source_name,
        &namespace_pin.evidence,
        &target,
    )?;
    fault::checkpoint(DurabilityEvent::Rename, context)?;
    fault::checkpoint(DurabilityEvent::Cleanup, context)?;
    namespace_pin.evidence.sync_all()?;
    fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
    source_parent.sync_all()?;
    fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
    #[cfg(test)]
    namespace_test_hook::checkpoint("before pinned v2 evidence target verification");
    verify_retained_at(namespace_pin, &target, expected)?;
    namespace_pin.verify(base_path)
}

pub(crate) fn retain_untrusted_file_with_pin(
    base_path: &Path,
    path: &Path,
    expected: &[u8],
    evidence_stem: &str,
    context: &str,
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<()> {
    namespace_pin.verify(base_path)?;
    let retained = OsString::from(evidence_name(evidence_stem, "untrusted")?);
    let (source_parent, source_name) = source_parent_and_name(path)?;
    match read_bounded_regular_at(&source_parent, &source_name, expected.len() as u64) {
        Ok(bytes) if bytes == expected => {}
        Ok(_) => {
            return Err(namespace_changed(format!(
                "untrusted v2 transaction evidence {} changed before pinned retention",
                path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if namespace_pin.evidence_entry_exists(&retained)? {
                verify_retained_at(namespace_pin, &retained, expected)?;
                namespace_pin.evidence.sync_all()?;
                fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
                source_parent.sync_all()?;
                fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
                namespace_pin.verify(base_path)?;
                return Ok(());
            } else {
                return Err(namespace_changed(format!(
                    "untrusted v2 transaction evidence {} disappeared before it reached the pinned evidence directory",
                    path.display()
                )));
            }
        }
        Err(error) => return Err(error),
    }
    let target = if !namespace_pin.evidence_entry_exists(&retained)? {
        retained
    } else {
        let mut duplicate = None;
        for number in 1..=1024u16 {
            let candidate = OsString::from(evidence_name(
                evidence_stem,
                &format!("untrusted-{number}"),
            )?);
            if !namespace_pin.evidence_entry_exists(&candidate)? {
                duplicate = Some(candidate);
                break;
            }
        }
        duplicate.ok_or_else(|| io_invalid("too many replayed untrusted v2 evidence names"))?
    };
    #[cfg(test)]
    namespace_test_hook::checkpoint("before pinned v2 untrusted evidence rename");
    renameat_noreplace(
        &source_parent,
        &source_name,
        &namespace_pin.evidence,
        &target,
    )?;
    fault::checkpoint(DurabilityEvent::Rename, context)?;
    fault::checkpoint(DurabilityEvent::Cleanup, context)?;
    namespace_pin.evidence.sync_all()?;
    fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
    source_parent.sync_all()?;
    fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
    #[cfg(test)]
    namespace_test_hook::checkpoint("before pinned v2 untrusted evidence target verification");
    verify_retained_at(namespace_pin, &target, expected)?;
    namespace_pin.verify(base_path)
}

pub(crate) fn retain_known_file(
    base_path: &Path,
    path: &Path,
    expected: &[u8],
    evidence_stem: &str,
    context: &str,
) -> std::io::Result<()> {
    ensure_layout(base_path)?;
    let retained = evidence_path(base_path, evidence_stem, "retained")?;
    match read_bounded_regular(path, expected.len() as u64) {
        Ok(actual) if actual == expected => {}
        Ok(_) => {
            return Err(io_invalid(format!(
                "refusing to retain changed v2 transaction evidence as if it were known {}",
                path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match backing_entry_exists(&retained)? {
                true => verify_retained(&retained, expected),
                false => Ok(()),
            };
        }
        Err(error) => return Err(error),
    }
    // A crash after destination-directory fsync but before source-directory
    // fsync may legitimately replay the old source name while an exact retained
    // name is already durable. Move each replay to a monotonically numbered,
    // transaction-bound duplicate instead of unlinking it. Normal cleanup uses
    // only `.retained`; extra names are created only after such a replay.
    let target = if !backing_entry_exists(&retained)? {
        retained
    } else {
        verify_retained(&retained, expected)?;
        let mut duplicate = None;
        for number in 1..=1024u16 {
            let candidate = evidence_path(base_path, evidence_stem, &format!("retained-{number}"))?;
            if backing_entry_exists(&candidate)? {
                verify_retained(&candidate, expected)?;
            } else {
                duplicate = Some(candidate);
                break;
            }
        }
        duplicate.ok_or_else(|| io_invalid("too many replayed v2 evidence names"))?
    };
    let source_parent = path
        .parent()
        .ok_or_else(|| io_invalid("v2 transaction evidence has no parent directory"))?;
    let evidence = selected_object_directory(base_path)?.join(EVIDENCE_DIRECTORY);
    rename_noreplace(path, &target)?;
    fault::checkpoint(DurabilityEvent::Rename, context)?;
    fault::checkpoint(DurabilityEvent::Cleanup, context)?;
    File::open(&evidence)?.sync_all()?;
    fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
    if source_parent != evidence {
        File::open(source_parent)?.sync_all()?;
        fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
    }
    verify_retained(&target, expected)
}

pub(crate) fn retain_untrusted_file(
    base_path: &Path,
    path: &Path,
    evidence_stem: &str,
    context: &str,
) -> std::io::Result<()> {
    ensure_layout(base_path)?;
    let retained = evidence_path(base_path, evidence_stem, "untrusted")?;
    if !backing_entry_exists(path)? {
        return Ok(());
    }
    let target = if !backing_entry_exists(&retained)? {
        retained
    } else {
        let mut duplicate = None;
        for number in 1..=1024u16 {
            let candidate =
                evidence_path(base_path, evidence_stem, &format!("untrusted-{number}"))?;
            if !backing_entry_exists(&candidate)? {
                duplicate = Some(candidate);
                break;
            }
        }
        duplicate.ok_or_else(|| io_invalid("too many replayed untrusted v2 evidence names"))?
    };
    let source_parent = path
        .parent()
        .ok_or_else(|| io_invalid("untrusted v2 evidence has no parent directory"))?;
    let evidence = selected_object_directory(base_path)?.join(EVIDENCE_DIRECTORY);
    rename_noreplace(path, &target)?;
    fault::checkpoint(DurabilityEvent::Rename, context)?;
    fault::checkpoint(DurabilityEvent::Cleanup, context)?;
    File::open(&evidence)?.sync_all()?;
    fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
    if source_parent != evidence {
        File::open(source_parent)?.sync_all()?;
        fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
    }
    Ok(())
}

fn retain_manifest_last(
    base_path: &Path,
    path: &Path,
    expected: &[u8],
    evidence_stem: &str,
) -> std::io::Result<()> {
    ensure_layout(base_path)?;
    let durable = evidence_path(base_path, evidence_stem, "durable")?;
    match fs::hard_link(path, &durable) {
        Ok(()) => {
            fault::checkpoint(
                DurabilityEvent::Write,
                "create durable v2 manifest evidence link",
            )?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_retained(&durable, expected)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            verify_retained(&durable, expected)?;
            return Ok(());
        }
        Err(link_error) => match write_new_file(
            &durable,
            expected,
            "write durable v2 manifest evidence copy",
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_retained(&durable, expected)?;
            }
            Err(error) => {
                return Err(std::io::Error::other(format!(
                    "cannot preserve durable manifest evidence (hard link: {link_error}; copy: {error})"
                )));
            }
        },
    }
    verify_retained(&durable, expected)?;
    File::open(&durable)?.sync_all()?;
    fault::checkpoint(
        DurabilityEvent::FileSync,
        "persist durable v2 manifest evidence link",
    )?;
    let evidence = selected_object_directory(base_path)?.join(EVIDENCE_DIRECTORY);
    File::open(&evidence)?.sync_all()?;
    fault::checkpoint(
        DurabilityEvent::DirectorySync,
        "persist durable v2 manifest evidence name",
    )?;
    retain_known_file(
        base_path,
        path,
        expected,
        evidence_stem,
        "retain committed v2 write manifest last",
    )
}

fn retain_manifest_last_with_pin(
    base_path: &Path,
    path: &Path,
    expected: &[u8],
    evidence_stem: &str,
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<()> {
    namespace_pin.verify(base_path)?;
    let durable = OsString::from(evidence_name(evidence_stem, "durable")?);
    let (source_parent, source_name) = source_parent_and_name(path)?;
    let source_bytes =
        read_bounded_regular_at(&source_parent, &source_name, expected.len() as u64)?;
    if source_bytes != expected {
        return Err(io_invalid(format!(
            "refusing to retain changed v2 manifest {} as authenticated durable evidence",
            path.display()
        )));
    }
    if namespace_pin.evidence_entry_exists(&durable)? {
        verify_retained_at(namespace_pin, &durable, expected)?;
    } else {
        #[cfg(test)]
        namespace_test_hook::checkpoint("before pinned v2 manifest evidence link");
        match linkat_noreplace(
            &source_parent,
            &source_name,
            &namespace_pin.evidence,
            &durable,
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_retained_at(namespace_pin, &durable, expected)?;
            }
            Err(error) => return Err(error),
        }
        fault::checkpoint(
            DurabilityEvent::Write,
            "create durable pinned v2 manifest evidence link",
        )?;
    }
    verify_retained_at(namespace_pin, &durable, expected)?;
    let durable_file = openat_nofollow(&namespace_pin.evidence, &durable, libc::O_RDONLY, 0)?;
    durable_file.sync_all()?;
    fault::checkpoint(
        DurabilityEvent::FileSync,
        "persist durable pinned v2 manifest evidence",
    )?;
    namespace_pin.evidence.sync_all()?;
    fault::checkpoint(
        DurabilityEvent::DirectorySync,
        "persist durable pinned v2 manifest evidence name",
    )?;
    retain_known_file_with_pin(
        base_path,
        path,
        expected,
        evidence_stem,
        "retain committed v2 write manifest last",
        namespace_pin,
    )
}

fn read_manifest(
    base_path: &Path,
    key: &[u8; 32],
) -> std::io::Result<Option<(WriteManifest, Vec<u8>)>> {
    let path = base_path.join(WRITE_MANIFEST);
    let ciphertext = match read_bounded_regular(&path, MAX_MANIFEST_CIPHERTEXT) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let manifest = decode_manifest_ciphertext(key, ciphertext.clone())?;
    Ok(Some((manifest, ciphertext)))
}

pub(crate) fn authenticate_recovery_intent_before_probe(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<()> {
    namespace_pin.verify(base_path)?;
    audit_manifest_evidence(base_path, key, Some(namespace_pin))?;
    let Some((manifest, _)) = read_manifest(base_path, key)? else {
        return Err(io_invalid(
            "v2 recovery intent disappeared before atomic-exchange preflight",
        ));
    };
    if &manifest.kdf_fingerprint != kdf_fingerprint {
        return Err(io_invalid(
            "KDF metadata differs from the authenticated v2 write manifest",
        ));
    }
    let current = root_fingerprint(base_path)?;
    if current != manifest.old_root && current.as_ref() != Some(&manifest.new_root) {
        return Err(io_invalid(
            "canonical v2 root is neither the authenticated old nor new generation",
        ));
    }
    namespace_pin.verify(base_path)
}

fn read_generation_record(
    base_path: &Path,
    key: &[u8; 32],
    reference: ObjectRef,
) -> std::io::Result<Generation> {
    read_generation_record_with_pin(base_path, key, reference, None)
}

fn read_generation_record_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    reference: ObjectRef,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<Generation> {
    let generation_bytes = read_object_with_pin(
        base_path,
        key,
        ObjectKind::Generation,
        &reference,
        namespace_pin,
    )?;
    let generation: Generation = serde_json::from_slice(&generation_bytes)
        .map_err(|error| io_invalid(format!("parse authenticated v2 generation: {error}")))?;
    if generation.format_version != FORMAT_VERSION || generation.number == 0 {
        return Err(io_invalid("authenticated v2 generation is malformed"));
    }
    if generation.previous == Some(reference) {
        return Err(io_invalid("authenticated v2 generation references itself"));
    }
    if (generation.number == 1 && (generation.previous.is_some() || generation.origin.is_some()))
        || (generation.number > 1 && (generation.previous.is_none() || generation.origin.is_none()))
    {
        return Err(io_invalid(
            "authenticated v2 generation has inconsistent parent/origin metadata",
        ));
    }
    Ok(generation)
}

fn load_generation_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    reference: ObjectRef,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<(Generation, DiskIndex)> {
    let generation = read_generation_record_with_pin(base_path, key, reference, namespace_pin)?;
    let index_bytes = read_object_with_pin(
        base_path,
        key,
        ObjectKind::Index,
        &generation.index,
        namespace_pin,
    )?;
    let index: DiskIndex = serde_json::from_slice(&index_bytes)
        .map_err(|error| io_invalid(format!("parse authenticated v2 index: {error}")))?;
    validate_disk_index_v2(&index).map_err(io_invalid)?;
    Ok((generation, index))
}

fn load_root_bytes(
    base_path: &Path,
    key: &[u8; 32],
    ciphertext: Vec<u8>,
) -> std::io::Result<(DiskIndex, CommitState)> {
    load_root_bytes_with_pin(base_path, key, ciphertext, None)
}

fn load_root_bytes_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    ciphertext: Vec<u8>,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<(DiskIndex, CommitState)> {
    let fingerprint = ciphertext_bytes_fingerprint(&ciphertext).map_err(std::io::Error::other)?;
    let plaintext = decrypt_bytes_owned(key, ciphertext, ROOT_AAD).map_err(io_invalid)?;
    let pointer: RootPointer = serde_json::from_slice(&plaintext)
        .map_err(|error| io_invalid(format!("parse authenticated v2 root: {error}")))?;
    if pointer.magic != ROOT_MAGIC || pointer.format_version != FORMAT_VERSION {
        return Err(io_invalid(
            "authenticated v2 root has an unsupported format",
        ));
    }
    let (generation, index) =
        load_generation_with_pin(base_path, key, pointer.generation, namespace_pin)?;
    Ok((
        index,
        CommitState {
            number: generation.number,
            generation: pointer.generation,
            parent: generation.previous,
            origin: generation.origin,
            lineage_id: generation.lineage_id,
            root_fingerprint: fingerprint,
        },
    ))
}

fn validate_manifest_new_lineage(
    base_path: &Path,
    key: &[u8; 32],
    manifest: &WriteManifest,
    namespace_pin: Option<&V2NamespacePin>,
    validated_generations: &mut HashSet<ObjectRef>,
) -> std::io::Result<()> {
    let (generation, index) =
        load_generation_with_pin(base_path, key, manifest.new_generation, namespace_pin)?;
    if generation.number != manifest.generation_number
        || generation.lineage_id != manifest.lineage_id
        || generation.previous != manifest.previous_generation
        || generation.origin != manifest.origin_generation
    {
        return Err(io_invalid(
            "new generation does not match its authenticated write manifest",
        ));
    }
    let expected_origin = manifest
        .origin_generation
        .unwrap_or(manifest.new_generation);
    validate_complete_generation_lineage(
        base_path,
        key,
        &index,
        manifest.new_generation,
        generation.number,
        generation.previous,
        generation.lineage_id,
        expected_origin,
        namespace_pin,
        validated_generations,
    )
}

fn validate_completed_manifest_old_lineage(
    base_path: &Path,
    key: &[u8; 32],
    manifest: &WriteManifest,
    old_index: &DiskIndex,
    old_state: &CommitState,
    namespace_pin: Option<&V2NamespacePin>,
    validated_generations: &mut HashSet<ObjectRef>,
) -> std::io::Result<()> {
    let expected_previous = manifest
        .previous_generation
        .ok_or_else(|| io_invalid("completed update manifest has no previous generation"))?;
    let expected_origin = manifest
        .origin_generation
        .ok_or_else(|| io_invalid("completed update manifest has no origin generation"))?;
    if old_state.generation != expected_previous
        || old_state.number.checked_add(1) != Some(manifest.generation_number)
        || old_state.lineage_id != manifest.lineage_id
        || old_state.origin.unwrap_or(old_state.generation) != expected_origin
    {
        return Err(io_invalid(
            "displaced root does not match the manifest's authenticated parent lineage",
        ));
    }

    validate_complete_generation_lineage(
        base_path,
        key,
        old_index,
        old_state.generation,
        old_state.number,
        old_state.parent,
        old_state.lineage_id,
        expected_origin,
        namespace_pin,
        validated_generations,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_complete_generation_lineage(
    base_path: &Path,
    key: &[u8; 32],
    first_index: &DiskIndex,
    first_reference: ObjectRef,
    first_number: u64,
    first_previous: Option<ObjectRef>,
    lineage_id: [u8; 16],
    expected_origin: ObjectRef,
    namespace_pin: Option<&V2NamespacePin>,
    validated_generations: &mut HashSet<ObjectRef>,
) -> std::io::Result<()> {
    let validate_files = |index: &DiskIndex| {
        match namespace_pin {
            Some(pin) => validate_reachable_v2_files_with_pin(base_path, key, index, pin),
            None => validate_reachable_v2_files(base_path, key, index),
        }
        .map_err(io_invalid)
    };
    let remember = |reference: ObjectRef,
                    validated: &mut HashSet<ObjectRef>|
     -> std::io::Result<bool> {
        if validated.contains(&reference) {
            return Ok(false);
        }
        if validated.len() >= MAX_EVIDENCE_ENTRIES {
            return Err(io_invalid(
                "authenticated v2 generation lineage exceeds the retained-evidence safety limit",
            ));
        }
        validated
            .try_reserve(1)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
        Ok(validated.insert(reference))
    };

    let mut current_reference = first_reference;
    let mut current_number = first_number;
    let mut current_previous = first_previous;
    if !remember(current_reference, validated_generations)? {
        return Ok(());
    }
    validate_files(first_index)?;
    loop {
        if current_number == 1 {
            if current_reference != expected_origin || current_previous.is_some() {
                return Err(io_invalid(
                    "authenticated v2 generation lineage does not terminate at its declared origin",
                ));
            }
            return Ok(());
        }

        let parent_reference = current_previous.ok_or_else(|| {
            io_invalid("authenticated v2 generation lineage has a missing parent")
        })?;
        let (parent, parent_index) =
            load_generation_with_pin(base_path, key, parent_reference, namespace_pin)?;
        if parent.number.checked_add(1) != Some(current_number)
            || parent.lineage_id != lineage_id
            || parent.origin.unwrap_or(parent_reference) != expected_origin
        {
            return Err(io_invalid(
                "authenticated v2 generation lineage has an inconsistent parent",
            ));
        }
        if !remember(parent_reference, validated_generations)? {
            return Ok(());
        }
        validate_files(&parent_index)?;
        current_reference = parent_reference;
        current_number = parent.number;
        current_previous = parent.previous;
    }
}

fn validate_pending_manifest_lineages(
    base_path: &Path,
    key: &[u8; 32],
    manifest: &WriteManifest,
    current: &Option<RecoveryFingerprint>,
    root_ready: &Path,
    root_evidence_stem: &str,
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<()> {
    if current != &manifest.old_root && current.as_ref() != Some(&manifest.new_root) {
        return Err(io_invalid(
            "canonical v2 root is neither the authenticated old nor new generation; preserving conflict evidence",
        ));
    }

    let mut validated_generations = HashSet::new();
    if let Some(expected_old_root) = manifest.old_root.as_ref() {
        let (old_index, old_state) = if current.as_ref() == Some(expected_old_root) {
            let loaded = load_with_pin(base_path, key, namespace_pin).map_err(|error| {
                io_invalid(format!(
                    "pending v2 write intent does not retain its complete authenticated old-generation lineage: {error}"
                ))
            })?;
            if &loaded.1.root_fingerprint != expected_old_root {
                return Err(io_invalid(
                    "canonical displaced root changed during pending-manifest validation",
                ));
            }
            loaded
        } else {
            let root_bytes = if backing_entry_exists(root_ready)? {
                read_bounded_regular(root_ready, MAX_ROOT_CIPHERTEXT)?
            } else {
                let retained = OsString::from(evidence_name(root_evidence_stem, "retained")?);
                namespace_pin
                    .read_evidence_file(&retained, MAX_ROOT_CIPHERTEXT)
                    .map_err(|error| {
                        io_invalid(format!(
                            "pending v2 write intent has no readable displaced-root evidence: {error}"
                        ))
                    })?
            };
            let actual =
                ciphertext_bytes_fingerprint(&root_bytes).map_err(std::io::Error::other)?;
            if &actual != expected_old_root {
                return Err(io_invalid(
                    "pending v2 write intent's displaced-root evidence differs from its authenticated old root",
                ));
            }
            load_root_bytes_with_pin(base_path, key, root_bytes, Some(namespace_pin)).map_err(
                |error| {
                    io_invalid(format!(
                        "pending v2 write intent does not retain its complete authenticated old-generation lineage: {error}"
                    ))
                },
            )?
        };
        validate_completed_manifest_old_lineage(
            base_path,
            key,
            manifest,
            &old_index,
            &old_state,
            Some(namespace_pin),
            &mut validated_generations,
        )
        .map_err(|error| {
            io_invalid(format!(
                "pending v2 write intent does not retain its complete authenticated old-generation lineage: {error}"
            ))
        })?;
    }
    validate_manifest_new_lineage(
        base_path,
        key,
        manifest,
        Some(namespace_pin),
        &mut validated_generations,
    )
    .map_err(|error| {
        io_invalid(format!(
            "pending v2 write intent does not retain its complete authenticated new-generation lineage: {error}"
        ))
    })?;
    namespace_pin.verify(base_path)
}

pub(crate) fn load(base_path: &Path, key: &[u8; 32]) -> std::io::Result<(DiskIndex, CommitState)> {
    let path = base_path.join(ROOT_FILE);
    let ciphertext = read_bounded_backing_file(&path, MAX_ROOT_CIPHERTEXT)?;
    load_root_bytes(base_path, key, ciphertext)
}

pub(crate) fn load_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<(DiskIndex, CommitState)> {
    namespace_pin.verify(base_path)?;
    let path = base_path.join(ROOT_FILE);
    let ciphertext = read_bounded_backing_file(&path, MAX_ROOT_CIPHERTEXT)?;
    let loaded = load_root_bytes_with_pin(base_path, key, ciphertext, Some(namespace_pin))?;
    namespace_pin.verify(base_path)?;
    Ok(loaded)
}

pub(crate) fn validate_lineage_origin(
    base_path: &Path,
    key: &[u8; 32],
    current: &CommitState,
    origin: ObjectRef,
    lineage_id: [u8; 16],
) -> std::io::Result<()> {
    validate_lineage_origin_internal(base_path, key, current, origin, lineage_id, None)
}

pub(crate) fn validate_lineage_origin_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    current: &CommitState,
    origin: ObjectRef,
    lineage_id: [u8; 16],
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<()> {
    validate_lineage_origin_internal(
        base_path,
        key,
        current,
        origin,
        lineage_id,
        Some(namespace_pin),
    )
}

fn validate_lineage_origin_internal(
    base_path: &Path,
    key: &[u8; 32],
    current: &CommitState,
    origin: ObjectRef,
    lineage_id: [u8; 16],
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<()> {
    if current.lineage_id != lineage_id || current.number == 0 {
        return Err(io_invalid("current v2 generation has the wrong lineage"));
    }
    let current_origin = current.origin.unwrap_or(current.generation);
    if current_origin != origin {
        return Err(io_invalid(
            "current v2 generation has a different authenticated origin",
        ));
    }
    let origin_generation = read_generation_record_with_pin(base_path, key, origin, namespace_pin)?;
    if origin_generation.number != 1
        || origin_generation.previous.is_some()
        || origin_generation.origin.is_some()
        || origin_generation.lineage_id != lineage_id
    {
        return Err(io_invalid(
            "authenticated migration origin is not a valid first v2 generation",
        ));
    }
    Ok(())
}

pub(crate) fn validate_migration_target_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    current: &CommitState,
    lineage_id: [u8; 16],
    expected_index: &DiskIndex,
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<ObjectRef> {
    validate_migration_target_internal(
        base_path,
        key,
        current,
        lineage_id,
        expected_index,
        Some(namespace_pin),
    )
}

fn validate_migration_target_internal(
    base_path: &Path,
    key: &[u8; 32],
    current: &CommitState,
    lineage_id: [u8; 16],
    expected_index: &DiskIndex,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<ObjectRef> {
    let origin = current.origin.unwrap_or(current.generation);
    validate_lineage_origin_internal(base_path, key, current, origin, lineage_id, namespace_pin)?;
    let (_, origin_index) = load_generation_with_pin(base_path, key, origin, namespace_pin)?;
    if &origin_index != expected_index {
        return Err(io_invalid(
            "authenticated v2 lineage origin differs from the migration plan and receipts",
        ));
    }
    Ok(origin)
}

fn commit_with_phase_and_lineage(
    base_path: &Path,
    key: &[u8; 32],
    index_json: &[u8],
    previous: Option<&CommitState>,
    kdf_fingerprint: &RecoveryFingerprint,
    initial_lineage: Option<[u8; 16]>,
    namespace_pin: Option<&V2NamespacePin>,
) -> Result<CommitState, CommitFailure> {
    let mut recovery_required = false;
    let mut own_intent_may_be_durable = false;
    let result = (|| -> std::io::Result<CommitState> {
        if let Some(pin) = namespace_pin {
            pin.verify_at(base_path, "before v2 commit")?;
        }
        match backing_entry_exists(&base_path.join(WRITE_MANIFEST)) {
            Ok(true) => {
                recovery_required = true;
                return Err(io_invalid(
                    "an authenticated v2 write manifest is already pending recovery",
                ));
            }
            Ok(false) => {}
            Err(error) => {
                return Err(error);
            }
        }
        let expected_old = previous.map(|state| state.root_fingerprint.clone());
        if root_fingerprint(base_path)? != expected_old {
            recovery_required = true;
            return Err(io_invalid(
                "v2 root changed before copy-on-write generation preparation",
            ));
        }
        let (generation, number, lineage_id) = write_generation(
            base_path,
            key,
            index_json,
            previous,
            initial_lineage,
            namespace_pin,
        )?;
        if let Some(pin) = namespace_pin {
            pin.verify_at(base_path, "after v2 generation preparation")?;
        }
        let (root_ciphertext, new_root) = prepare_root(key, generation)?;

        let mut transaction_id = [0u8; 16];
        OsRng.fill_bytes(&mut transaction_id);
        let transaction_hex = to_hex(&transaction_id);
        let root_ready_name = format!("{ROOT_READY_PREFIX}{transaction_hex}.ready");
        let manifest_ready_name = format!("{MANIFEST_READY_PREFIX}{transaction_hex}.ready");
        let root_ready = base_path.join(&root_ready_name);
        write_new_file(&root_ready, &root_ciphertext, "stage authenticated v2 root")?;

        let manifest = WriteManifest {
            manifest_version: MANIFEST_VERSION,
            transaction_id,
            kdf_fingerprint: kdf_fingerprint.clone(),
            old_root: expected_old.clone(),
            new_root: new_root.clone(),
            previous_generation: previous.map(|state| state.generation),
            origin_generation: previous.map(|state| state.origin.unwrap_or(state.generation)),
            new_generation: generation,
            generation_number: number,
            lineage_id,
            root_ready_name,
            manifest_ready_name: manifest_ready_name.clone(),
        };
        let evidence_prefix = format!("normal-{}", to_hex(&manifest.transaction_id));
        validate_manifest(&manifest)?;
        let manifest_json = serde_json::to_vec(&manifest)
            .map_err(|error| io_invalid(format!("serialize v2 write manifest: {error}")))?;
        let manifest_ciphertext =
            encrypt_bytes(key, &manifest_json, MANIFEST_AAD).map_err(std::io::Error::other)?;
        if manifest_ciphertext.len() as u64 > MAX_MANIFEST_CIPHERTEXT {
            return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
        }
        let manifest_ready = base_path.join(&manifest_ready_name);
        write_new_file(
            &manifest_ready,
            &manifest_ciphertext,
            "stage authenticated v2 write manifest",
        )?;
        let manifest_path = base_path.join(WRITE_MANIFEST);
        if root_fingerprint(base_path)? != expected_old {
            recovery_required = true;
            return Err(io_invalid(
                "v2 root changed during generation preparation; refusing to publish write intent",
            ));
        }
        if let Err(error) = ensure_no_index_siblings(base_path) {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                recovery_required = true;
            }
            return Err(error);
        }
        let pre_intent_kdf = exact_fingerprint(&base_path.join("_kdf.json")).map_err(|error| {
            io_invalid(format!(
                "cannot revalidate KDF immediately before v2 write intent: {error}"
            ))
        })?;
        if &pre_intent_kdf != kdf_fingerprint {
            recovery_required = true;
            return Err(io_invalid(
                "KDF metadata changed during generation preparation; refusing to publish write intent",
            ));
        }
        if let Some(pin) = namespace_pin {
            pin.verify_at(base_path, "before v2 write intent publication")?;
        }
        // From this point onward, even an error returned immediately after a
        // completed namespace operation may have published authenticated intent.
        // The caller must latch read-only and recover before retrying.
        recovery_required = true;
        let retained_ready = match publish_noreplace(&manifest_ready, &manifest_path) {
            Ok(retained) => {
                own_intent_may_be_durable = true;
                retained
            }
            Err(error) => {
                own_intent_may_be_durable =
                    read_bounded_regular(&manifest_path, MAX_MANIFEST_CIPHERTEXT)
                        .is_ok_and(|actual| actual == manifest_ciphertext);
                return Err(error);
            }
        };
        File::open(base_path)?.sync_all()?;
        fault::checkpoint(
            DurabilityEvent::DirectorySync,
            "persist authenticated v2 write manifest",
        )?;
        if retained_ready {
            let evidence_stem = format!("{evidence_prefix}-manifest-ready");
            match namespace_pin {
                Some(pin) => retain_known_file_with_pin(
                    base_path,
                    &manifest_ready,
                    &manifest_ciphertext,
                    &evidence_stem,
                    "retain published v2 manifest staging evidence",
                    pin,
                )?,
                None => retain_known_file(
                    base_path,
                    &manifest_ready,
                    &manifest_ciphertext,
                    &evidence_stem,
                    "retain published v2 manifest staging evidence",
                )?,
            }
        }

        if let Some(pin) = namespace_pin {
            pin.verify_at(base_path, "after v2 write intent publication")?;
        }

        if root_fingerprint(base_path)? != expected_old {
            return Err(io_invalid(
                "v2 root changed after manifest publication; preserving all transaction evidence",
            ));
        }
        ensure_no_index_siblings(base_path)?;
        let actual_kdf = exact_fingerprint(&base_path.join("_kdf.json")).map_err(|error| {
            io_invalid(format!(
                "cannot revalidate KDF metadata before v2 root publication: {error}"
            ))
        })?;
        if &actual_kdf != kdf_fingerprint {
            return Err(io_invalid(
                "KDF metadata changed after manifest publication; preserving all transaction evidence",
            ));
        }
        if let Some(pin) = namespace_pin {
            pin.verify_at(base_path, "before v2 root publication")?;
        }
        let retained_root_ready = publish_root(base_path, &root_ready, &manifest)?;
        if let Some(pin) = namespace_pin {
            pin.verify_at(base_path, "after v2 root publication")?;
        }
        ensure_no_index_siblings(base_path)?;
        let actual_kdf = exact_fingerprint(&base_path.join("_kdf.json")).map_err(|error| {
            io_invalid(format!(
                "cannot revalidate KDF metadata after v2 root publication: {error}"
            ))
        })?;
        if &actual_kdf != kdf_fingerprint {
            return Err(io_invalid(
                "KDF metadata changed across v2 root publication; preserving both roots and all transaction evidence",
            ));
        }
        if retained_root_ready {
            let expected = manifest.old_root.as_ref().unwrap_or(&manifest.new_root);
            let displaced = read_bounded_regular(&root_ready, MAX_ROOT_CIPHERTEXT)?;
            if ciphertext_bytes_fingerprint(&displaced).map_err(std::io::Error::other)? != *expected
            {
                return Err(io_invalid(
                    "displaced v2 root changed before evidence retention; preserving the write manifest",
                ));
            }
            let evidence_stem = format!("{evidence_prefix}-root");
            match namespace_pin {
                Some(pin) => retain_known_file_with_pin(
                    base_path,
                    &root_ready,
                    &displaced,
                    &evidence_stem,
                    "retain displaced authenticated v2 root evidence",
                    pin,
                )?,
                None => retain_known_file(
                    base_path,
                    &root_ready,
                    &displaced,
                    &evidence_stem,
                    "retain displaced authenticated v2 root evidence",
                )?,
            }
        }
        if root_fingerprint(base_path)?.as_ref() != Some(&new_root) {
            return Err(io_invalid(
                "canonical v2 root changed before manifest-last completion; preserving transaction evidence",
            ));
        }
        ensure_no_index_siblings(base_path)?;
        if exact_fingerprint(&base_path.join("_kdf.json"))
            .map_err(|error| io_invalid(format!("revalidate KDF before manifest-last: {error}")))?
            != *kdf_fingerprint
        {
            return Err(io_invalid(
                "KDF metadata changed before manifest-last completion; preserving transaction evidence",
            ));
        }
        if let Some(pin) = namespace_pin {
            pin.verify_at(base_path, "before v2 manifest completion")?;
        }
        let manifest_evidence_stem = format!("{evidence_prefix}-manifest");
        match namespace_pin {
            Some(pin) => retain_manifest_last_with_pin(
                base_path,
                &manifest_path,
                &manifest_ciphertext,
                &manifest_evidence_stem,
                pin,
            )?,
            None => retain_manifest_last(
                base_path,
                &manifest_path,
                &manifest_ciphertext,
                &manifest_evidence_stem,
            )?,
        }
        if let Some(pin) = namespace_pin {
            pin.verify_at(base_path, "after v2 manifest completion")?;
        }
        Ok(CommitState {
            number,
            generation,
            parent: previous.map(|state| state.generation),
            origin: manifest.origin_generation,
            lineage_id: manifest.lineage_id,
            root_fingerprint: new_root,
        })
    })();
    result.map_err(|error| CommitFailure {
        error,
        recovery_required,
        own_intent_may_be_durable,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn commit_with_phase(
    base_path: &Path,
    key: &[u8; 32],
    index_json: &[u8],
    previous: Option<&CommitState>,
    kdf_fingerprint: &RecoveryFingerprint,
) -> Result<CommitState, CommitFailure> {
    if previous.is_none()
        && !backing_entry_exists(&base_path.join(ROOT_FILE)).unwrap_or(true)
        && let Err(error) = ensure_layout(base_path)
    {
        return Err(CommitFailure {
            error,
            recovery_required: false,
            own_intent_may_be_durable: false,
        });
    }
    let namespace_pin = V2NamespacePin::capture(base_path).map_err(|error| CommitFailure {
        error,
        recovery_required: false,
        own_intent_may_be_durable: false,
    })?;
    commit_with_phase_and_lineage(
        base_path,
        key,
        index_json,
        previous,
        kdf_fingerprint,
        None,
        Some(&namespace_pin),
    )
}

pub(crate) fn commit_with_phase_pinned(
    base_path: &Path,
    key: &[u8; 32],
    index_json: &[u8],
    previous: Option<&CommitState>,
    kdf_fingerprint: &RecoveryFingerprint,
    namespace_pin: &V2NamespacePin,
) -> Result<CommitState, CommitFailure> {
    commit_with_phase_and_lineage(
        base_path,
        key,
        index_json,
        previous,
        kdf_fingerprint,
        None,
        Some(namespace_pin),
    )
}

#[allow(dead_code)]
pub(crate) fn commit_initial_lineage(
    base_path: &Path,
    key: &[u8; 32],
    index_json: &[u8],
    kdf_fingerprint: &RecoveryFingerprint,
    lineage_id: [u8; 16],
) -> std::io::Result<CommitState> {
    ensure_layout(base_path)?;
    let namespace_pin = V2NamespacePin::capture(base_path)?;
    commit_initial_lineage_pinned(
        base_path,
        key,
        index_json,
        kdf_fingerprint,
        lineage_id,
        &namespace_pin,
    )
}

pub(crate) fn commit_initial_lineage_pinned(
    base_path: &Path,
    key: &[u8; 32],
    index_json: &[u8],
    kdf_fingerprint: &RecoveryFingerprint,
    lineage_id: [u8; 16],
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<CommitState> {
    commit_with_phase_and_lineage(
        base_path,
        key,
        index_json,
        None,
        kdf_fingerprint,
        Some(lineage_id),
        Some(namespace_pin),
    )
    .map_err(|failure| failure.error)
}

#[cfg(test)]
pub(crate) fn commit(
    base_path: &Path,
    key: &[u8; 32],
    index_json: &[u8],
    previous: Option<&CommitState>,
    kdf_fingerprint: &RecoveryFingerprint,
) -> std::io::Result<CommitState> {
    commit_with_phase(base_path, key, index_json, previous, kdf_fingerprint)
        .map_err(|failure| failure.error)
}

pub(crate) fn recover(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
) -> std::io::Result<bool> {
    recover_with_optional_pin(base_path, key, kdf_fingerprint, None)
}

pub(crate) fn recover_with_namespace_pin(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<bool> {
    recover_with_optional_pin(base_path, key, kdf_fingerprint, Some(namespace_pin))
}

fn recover_with_optional_pin(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<bool> {
    let audit_owned_pin = if namespace_pin.is_none()
        && backing_entry_exists(&selected_object_directory(base_path)?)?
    {
        Some(V2NamespacePin::capture(base_path)?)
    } else {
        None
    };
    let namespace_pin = namespace_pin.or(audit_owned_pin.as_ref());
    audit_manifest_evidence(base_path, key, namespace_pin)?;
    let Some((manifest, manifest_ciphertext)) = read_manifest(base_path, key)? else {
        return Ok(false);
    };
    let recovery_owned_pin;
    let namespace_pin = match namespace_pin {
        Some(pin) => pin,
        None => {
            recovery_owned_pin = V2NamespacePin::capture(base_path)?;
            &recovery_owned_pin
        }
    };
    namespace_pin.verify_at(base_path, "before v2 recovery")?;
    let evidence_prefix = format!("normal-{}", to_hex(&manifest.transaction_id));
    ensure_no_index_siblings(base_path)?;
    fault::checkpoint(DurabilityEvent::Recovery, "authenticate v2 write intent")?;
    if &manifest.kdf_fingerprint != kdf_fingerprint {
        return Err(io_invalid(
            "KDF metadata differs from the authenticated v2 write manifest",
        ));
    }
    let root_ready = base_path.join(&manifest.root_ready_name);
    let manifest_ready = base_path.join(&manifest.manifest_ready_name);
    let root_evidence_stem = format!("{evidence_prefix}-root");
    let current = root_fingerprint(base_path)?;
    validate_pending_manifest_lineages(
        base_path,
        key,
        &manifest,
        &current,
        &root_ready,
        &root_evidence_stem,
        namespace_pin,
    )?;
    fault::checkpoint(
        DurabilityEvent::Recovery,
        "validate pending v2 manifest lineages",
    )?;
    let retained_root_ready;
    if current == manifest.old_root {
        match &manifest.old_root {
            Some(_) => {
                let (_old_index, old_state) = load_with_pin(base_path, key, namespace_pin)?;
                if Some(old_state.generation) != manifest.previous_generation
                    || old_state.number.checked_add(1) != Some(manifest.generation_number)
                    || old_state.lineage_id != manifest.lineage_id
                    || Some(old_state.origin.unwrap_or(old_state.generation))
                        != manifest.origin_generation
                {
                    return Err(io_invalid(
                        "authenticated v2 recovery intent is not a direct child of the canonical old generation",
                    ));
                }
            }
            None => {
                if manifest.previous_generation.is_some() || manifest.generation_number != 1 {
                    return Err(io_invalid(
                        "authenticated initial v2 recovery intent has a parent generation",
                    ));
                }
            }
        }
        let ready = read_bounded_regular(&root_ready, MAX_ROOT_CIPHERTEXT)?;
        let ready_fingerprint =
            ciphertext_bytes_fingerprint(&ready).map_err(std::io::Error::other)?;
        if ready_fingerprint != manifest.new_root {
            return Err(io_invalid(
                "staged v2 root differs from authenticated recovery intent",
            ));
        }
        let (ready_index, state) =
            load_root_bytes_with_pin(base_path, key, ready, Some(namespace_pin))?;
        if state.generation != manifest.new_generation
            || state.number != manifest.generation_number
            || state.parent != manifest.previous_generation
            || state.origin != manifest.origin_generation
            || state.lineage_id != manifest.lineage_id
        {
            return Err(io_invalid(
                "staged v2 root generation differs from authenticated recovery intent",
            ));
        }
        validate_disk_index_v2(&ready_index).map_err(io_invalid)?;
        validate_reachable_v2_files_with_pin(base_path, key, &ready_index, namespace_pin).map_err(
            |error| {
                io_invalid(format!(
                    "staged v2 recovery generation is not completely materialized: {error}"
                ))
            },
        )?;
        namespace_pin.verify_at(base_path, "after staged recovery generation validation")?;
        fault::checkpoint(DurabilityEvent::Recovery, "validate old v2 generation")?;
        namespace_pin.verify_at(base_path, "before v2 recovery root publication")?;
        retained_root_ready = publish_root(base_path, &root_ready, &manifest)?;
        namespace_pin.verify_at(base_path, "after v2 recovery root publication")?;
    } else if current != Some(manifest.new_root.clone()) {
        return Err(io_invalid(
            "canonical v2 root is neither the authenticated old nor new generation; preserving conflict evidence",
        ));
    } else {
        retained_root_ready = backing_entry_exists(&root_ready)?;
        if retained_root_ready {
            let expected = manifest.old_root.as_ref().unwrap_or(&manifest.new_root);
            if fingerprint_file(&root_ready, MAX_ROOT_CIPHERTEXT)? != *expected {
                return Err(io_invalid(
                    "v2 root staging name differs from the authenticated displaced root; preserving all evidence",
                ));
            }
        } else {
            let retained = retained_fingerprint_with_pin(
                base_path,
                &root_evidence_stem,
                MAX_ROOT_CIPHERTEXT,
                namespace_pin,
            )?;
            let expected = manifest.old_root.as_ref().unwrap_or(&manifest.new_root);
            if retained.as_ref().is_some_and(|actual| actual != expected) {
                return Err(io_invalid(
                    "retained v2 root evidence differs from the authenticated write manifest",
                ));
            }
            if manifest.old_root.is_some() && retained.is_none() {
                return Err(io_invalid(
                    "authenticated old v2 root is missing from both its staging and retained evidence names",
                ));
            }
        }
    }
    ensure_no_index_siblings(base_path)?;
    let actual_kdf = exact_fingerprint(&base_path.join("_kdf.json")).map_err(|error| {
        io_invalid(format!(
            "cannot revalidate KDF metadata during v2 recovery: {error}"
        ))
    })?;
    if &actual_kdf != kdf_fingerprint {
        return Err(io_invalid(
            "KDF metadata changed during v2 recovery; preserving both roots and all transaction evidence",
        ));
    }
    namespace_pin.verify_at(base_path, "before canonical v2 recovery validation")?;
    fault::checkpoint(DurabilityEvent::Recovery, "validate new v2 generation")?;
    let (index, state) = load_with_pin(base_path, key, namespace_pin)?;
    validate_disk_index_v2(&index).map_err(io_invalid)?;
    validate_reachable_v2_files_with_pin(base_path, key, &index, namespace_pin).map_err(
        |error| {
            io_invalid(format!(
                "canonical v2 recovery generation is not completely materialized: {error}"
            ))
        },
    )?;
    if state.generation != manifest.new_generation
        || state.number != manifest.generation_number
        || state.lineage_id != manifest.lineage_id
    {
        return Err(io_invalid(
            "canonical v2 root does not name the authenticated recovery generation",
        ));
    }
    if state.parent != manifest.previous_generation {
        return Err(io_invalid(
            "canonical v2 generation parent differs from authenticated recovery intent",
        ));
    }
    if state.origin != manifest.origin_generation {
        return Err(io_invalid(
            "canonical v2 generation origin differs from authenticated recovery intent",
        ));
    }
    namespace_pin.verify_at(base_path, "after canonical v2 recovery validation")?;

    if retained_root_ready {
        let expected = manifest.old_root.as_ref().unwrap_or(&manifest.new_root);
        let displaced = read_bounded_regular(&root_ready, MAX_ROOT_CIPHERTEXT)?;
        if ciphertext_bytes_fingerprint(&displaced).map_err(std::io::Error::other)? != *expected {
            return Err(io_invalid(
                "displaced v2 root changed before recovery evidence retention",
            ));
        }
        retain_known_file_with_pin(
            base_path,
            &root_ready,
            &displaced,
            &root_evidence_stem,
            "retain verified displaced v2 root evidence",
            namespace_pin,
        )?;
    }
    if backing_entry_exists(&manifest_ready)? {
        retain_known_file_with_pin(
            base_path,
            &manifest_ready,
            &manifest_ciphertext,
            &format!("{evidence_prefix}-manifest-ready"),
            "retain verified duplicate v2 manifest staging evidence",
            namespace_pin,
        )?;
    }
    if root_fingerprint(base_path)?.as_ref() != Some(&manifest.new_root) {
        return Err(io_invalid(
            "canonical v2 root changed before recovery manifest-last completion",
        ));
    }
    ensure_no_index_siblings(base_path)?;
    if exact_fingerprint(&base_path.join("_kdf.json")).map_err(|error| {
        io_invalid(format!(
            "revalidate KDF before recovery manifest-last: {error}"
        ))
    })? != *kdf_fingerprint
    {
        return Err(io_invalid(
            "KDF metadata changed before recovery manifest-last completion",
        ));
    }
    namespace_pin.verify_at(base_path, "before v2 recovery manifest completion")?;
    retain_manifest_last_with_pin(
        base_path,
        &base_path.join(WRITE_MANIFEST),
        &manifest_ciphertext,
        &format!("{evidence_prefix}-manifest"),
        namespace_pin,
    )?;
    namespace_pin.verify_at(base_path, "after v2 recovery manifest completion")?;
    fault::checkpoint(DurabilityEvent::Recovery, "finish v2 recovery")?;
    Ok(true)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_reachable_file(
    base_path: &Path,
    key: &[u8; 32],
    encoded_root: &str,
    size: u64,
) -> std::io::Result<()> {
    validate_reachable_file_internal(base_path, key, encoded_root, size, None)
}

pub(crate) fn validate_reachable_file_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    encoded_root: &str,
    size: u64,
    namespace_pin: &V2NamespacePin,
) -> std::io::Result<()> {
    validate_reachable_file_internal(base_path, key, encoded_root, size, Some(namespace_pin))
}

fn validate_reachable_file_internal(
    base_path: &Path,
    key: &[u8; 32],
    encoded_root: &str,
    size: u64,
    namespace_pin: Option<&V2NamespacePin>,
) -> std::io::Result<()> {
    let root = load_file_root_with_pin(base_path, key, encoded_root, size, namespace_pin)?;
    if size == 0 && root.tree.is_some() {
        return Err(io_invalid("empty v2 file retains a data tree"));
    }
    let Some(last_chunk) = size.checked_sub(1).map(|last| last / CHUNK_SIZE as u64) else {
        return Ok(());
    };
    let tail_len = ((size - 1) % CHUNK_SIZE as u64 + 1) as usize;
    #[allow(clippy::too_many_arguments)]
    fn visit(
        base_path: &Path,
        key: &[u8; 32],
        reference: ObjectRef,
        height: u8,
        prefix: u64,
        last_chunk: u64,
        tail_len: usize,
        namespace_pin: Option<&V2NamespacePin>,
    ) -> std::io::Result<()> {
        let node = read_tree_with_pin(base_path, key, &reference, height, namespace_pin)?;
        for slot in node.slots {
            let chunk_prefix = prefix | (u64::from(slot.slot) << (u32::from(height) * 8));
            if chunk_prefix > last_chunk {
                return Err(io_invalid("v2 file tree references data beyond EOF"));
            }
            if height == 0 {
                let chunk = read_object_with_pin(
                    base_path,
                    key,
                    ObjectKind::Data,
                    &slot.child,
                    namespace_pin,
                )?;
                let maximum = if chunk_prefix == last_chunk {
                    tail_len
                } else {
                    CHUNK_SIZE
                };
                if chunk.is_empty() || chunk.len() > maximum || chunk.iter().all(|byte| *byte == 0)
                {
                    return Err(io_invalid(
                        "v2 file tree references a noncanonical or oversized data chunk",
                    ));
                }
            } else {
                visit(
                    base_path,
                    key,
                    slot.child,
                    height - 1,
                    chunk_prefix,
                    last_chunk,
                    tail_len,
                    namespace_pin,
                )?;
            }
        }
        Ok(())
    }
    if let Some(tree) = root.tree {
        visit(
            base_path,
            key,
            tree,
            root.height,
            0,
            last_chunk,
            tail_len,
            namespace_pin,
        )?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "v2_process_crash_tests.rs"]
mod process_crash_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{FORMAT_VERSION as KDF_FORMAT_VERSION, KdfParams, SALT_LEN, derive_key};
    use crate::fault::{DurabilityEvent, FaultInjectionGuard};
    use crate::fs::{DirChild, InodeEntry, InodeKind};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn test_directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "zerotrust-drive-v2-{label}-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn test_key() -> [u8; 32] {
        derive_key(
            "v2-test-passphrase",
            &KdfParams {
                format_version: KDF_FORMAT_VERSION,
                algorithm: "argon2id".to_string(),
                salt: vec![7; SALT_LEN],
                m_cost: 8,
                t_cost: 1,
                p_cost: 1,
            },
        )
    }

    fn kdf_fingerprint() -> RecoveryFingerprint {
        RecoveryFingerprint::Exact {
            bytes: b"authenticated-test-kdf".to_vec(),
        }
    }

    #[test]
    fn manifest_validation_accepts_legacy_appledouble_staging_names_only_as_a_pair() {
        let transaction_id = [0xabu8; 16];
        let transaction_hex = to_hex(&transaction_id);
        let reference = ObjectRef {
            id: [1; 16],
            digest: [2; 32],
        };
        let root = ciphertext_bytes_fingerprint(&[3; 40]).unwrap();
        let mut manifest = WriteManifest {
            manifest_version: MANIFEST_VERSION,
            transaction_id,
            kdf_fingerprint: kdf_fingerprint(),
            old_root: None,
            new_root: root,
            previous_generation: None,
            origin_generation: None,
            new_generation: reference,
            generation_number: 1,
            lineage_id: [4; 16],
            root_ready_name: format!("{ROOT_READY_PREFIX}{transaction_hex}.ready"),
            manifest_ready_name: format!("{MANIFEST_READY_PREFIX}{transaction_hex}.ready"),
        };
        validate_manifest(&manifest).unwrap();

        manifest.root_ready_name = format!("{LEGACY_ROOT_READY_PREFIX}{transaction_hex}.ready");
        manifest.manifest_ready_name =
            format!("{LEGACY_MANIFEST_READY_PREFIX}{transaction_hex}.ready");
        validate_manifest(&manifest).unwrap();

        manifest.manifest_ready_name = format!("{MANIFEST_READY_PREFIX}{transaction_hex}.ready");
        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn legacy_dot_object_directory_remains_readable_and_writable() {
        let directory = test_directory("legacy-object-directory");
        fs::create_dir_all(directory.join(LEGACY_OBJECT_DIRECTORY)).unwrap();
        ensure_layout(&directory).unwrap();
        assert_eq!(
            selected_object_directory(&directory).unwrap(),
            directory.join(LEGACY_OBJECT_DIRECTORY)
        );
        assert!(!directory.join(OBJECT_DIRECTORY).exists());

        let key = test_key();
        let (root, size) = write_file_range(&directory, &key, "", 0, 0, b"legacy").unwrap();
        assert_eq!(
            read_file_range(&directory, &key, &root, size, 0, 6).unwrap(),
            b"legacy"
        );
        assert!(
            fs::read_dir(
                directory
                    .join(LEGACY_OBJECT_DIRECTORY)
                    .join(OBJECTS_DIRECTORY)
            )
            .unwrap()
            .next()
            .is_some()
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn simultaneous_current_and_legacy_object_directories_are_preserved_as_conflict() {
        let directory = test_directory("dual-object-directories");
        fs::create_dir_all(directory.join(OBJECT_DIRECTORY)).unwrap();
        fs::create_dir_all(directory.join(LEGACY_OBJECT_DIRECTORY)).unwrap();

        let error = ensure_layout(&directory).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(directory.join(OBJECT_DIRECTORY).exists());
        assert!(directory.join(LEGACY_OBJECT_DIRECTORY).exists());

        fs::remove_dir_all(directory).unwrap();
    }

    fn index_with_file(name: &str) -> DiskIndex {
        let root = InodeEntry {
            name: String::new(),
            kind: InodeKind::Directory,
            disk_filename: String::new(),
            size: 0,
            perm: 0o755,
            uid: 501,
            gid: 20,
            atime_secs: 1,
            mtime_secs: 1,
            ctime_secs: 1,
            nlink: 2,
            parent: 1,
        };
        let file = InodeEntry {
            name: name.to_string(),
            kind: InodeKind::File,
            disk_filename: String::new(),
            size: 0,
            perm: 0o600,
            uid: 501,
            gid: 20,
            atime_secs: 1,
            mtime_secs: 1,
            ctime_secs: 1,
            nlink: 1,
            parent: 1,
        };
        DiskIndex {
            next_inode: 3,
            next_file_id: 1,
            inodes: HashMap::from([(1, root), (2, file)]),
            children: HashMap::from([(
                1,
                vec![DirChild {
                    name: name.to_string(),
                    inode: 2,
                }],
            )]),
        }
    }

    fn copy_directory(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_directory(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    fn commit_index(
        directory: &Path,
        key: &[u8; 32],
        index: &DiskIndex,
        previous: Option<&CommitState>,
    ) -> std::io::Result<CommitState> {
        let kdf_path = directory.join("_kdf.json");
        if !kdf_path.exists() {
            fs::write(&kdf_path, b"authenticated-test-kdf")?;
        }
        let json = serde_json::to_vec(index).unwrap();
        commit(directory, key, &json, previous, &kdf_fingerprint())
    }

    fn replace_selected_namespace(directory: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let canonical = selected_object_directory(directory).unwrap();
        let displaced = directory.join("provider-displaced-namespace-evidence");
        let replacement = directory.join("provider-replacement-evidence");
        fs::rename(&canonical, &displaced).unwrap();
        fs::create_dir(&canonical).unwrap();
        fs::create_dir(canonical.join(OBJECTS_DIRECTORY)).unwrap();
        fs::create_dir(canonical.join(EVIDENCE_DIRECTORY)).unwrap();
        (canonical, displaced, replacement)
    }

    fn restore_displaced_namespace(paths: &(PathBuf, PathBuf, PathBuf)) {
        fs::rename(&paths.0, &paths.2).unwrap();
        fs::rename(&paths.1, &paths.0).unwrap();
    }

    fn replace_evidence_directory(directory: &Path) -> (PathBuf, PathBuf) {
        let namespace = selected_object_directory(directory).unwrap();
        let canonical = namespace.join(EVIDENCE_DIRECTORY);
        let displaced = namespace.join("provider-displaced-evidence");
        fs::rename(&canonical, &displaced).unwrap();
        fs::create_dir(&canonical).unwrap();
        fs::write(canonical.join("provider-sentinel.keep"), b"preserve").unwrap();
        (canonical, displaced)
    }

    fn replace_objects_directory(directory: &Path) -> (PathBuf, PathBuf) {
        let namespace = selected_object_directory(directory).unwrap();
        let canonical = namespace.join(OBJECTS_DIRECTORY);
        let displaced = namespace.join("provider-displaced-objects");
        fs::rename(&canonical, &displaced).unwrap();
        fs::create_dir(&canonical).unwrap();
        fs::write(canonical.join("provider-sentinel.keep"), b"preserve").unwrap();
        (canonical, displaced)
    }

    #[test]
    fn pinned_object_publication_rejects_a_replaced_final_name_without_retrying() {
        let directory = test_directory("pinned-object-name-race");
        fs::create_dir_all(&directory).unwrap();
        ensure_layout(&directory).unwrap();
        let pin = V2NamespacePin::capture(&directory).unwrap();
        let objects = directory.join(OBJECT_DIRECTORY).join(OBJECTS_DIRECTORY);
        let action_objects = objects.clone();
        let hook = namespace_test_hook::Guard::arm(
            "before pinned v2 object name verification",
            move || {
                let created = fs::read_dir(&action_objects)
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .path();
                fs::rename(&created, action_objects.join("provider-displaced.keep")).unwrap();
                fs::write(&created, b"provider replacement").unwrap();
            },
        );
        let error = write_object_with_pin(
            &directory,
            &test_key(),
            ObjectKind::Data,
            b"authenticated local bytes",
            Some(&pin),
        )
        .unwrap_err();
        drop(hook);
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(objects.join("provider-displaced.keep"))
                .unwrap()
                .len(),
            V1_CIPHERTEXT_OVERHEAD as usize + b"authenticated local bytes".len()
        );
        assert!(fs::read_dir(&objects).unwrap().count() >= 2);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pinned_root_load_rejects_replaced_generation_object_namespace() {
        let directory = test_directory("pinned-root-load-object-race");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();
        let index = index_with_file("generation.txt");
        commit_index(&directory, &key, &index, None).unwrap();
        let pin = V2NamespacePin::capture(&directory).unwrap();
        let action_directory = directory.clone();
        let hook = namespace_test_hook::Guard::arm("before pinned v2 object read", move || {
            replace_objects_directory(&action_directory);
        });
        let error = load_with_pin(&directory, &key, &pin).unwrap_err();
        drop(hook);
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        let namespace = directory.join(OBJECT_DIRECTORY);
        assert!(
            fs::read_dir(namespace.join("provider-displaced-objects"))
                .unwrap()
                .count()
                >= 2
        );
        assert_eq!(
            fs::read(
                namespace
                    .join(OBJECTS_DIRECTORY)
                    .join("provider-sentinel.keep")
            )
            .unwrap(),
            b"preserve"
        );
        drop(pin);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pinned_existing_exchange_probe_never_recreates_missing_layout() {
        let directory = test_directory("pinned-probe-missing-layout");
        fs::create_dir_all(&directory).unwrap();
        ensure_layout(&directory).unwrap();
        let pin = V2NamespacePin::capture(&directory).unwrap();
        let evidence = directory.join(OBJECT_DIRECTORY).join(EVIDENCE_DIRECTORY);
        fs::remove_dir(&evidence).unwrap();
        let error = probe_atomic_exchange_with_pin(&directory, &pin).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(
            !evidence.exists(),
            "existing-store probe recreated missing evidence"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pinned_evidence_audit_detects_directory_replacement_without_scanning_it() {
        let directory = test_directory("pinned-evidence-audit-race");
        fs::create_dir_all(&directory).unwrap();
        ensure_layout(&directory).unwrap();
        let pin = V2NamespacePin::capture(&directory).unwrap();
        let action_directory = directory.clone();
        let hook =
            namespace_test_hook::Guard::arm("before pinned v2 evidence inventory", move || {
                replace_evidence_directory(&action_directory);
            });
        let error = audit_manifest_evidence(&directory, &test_key(), Some(&pin)).unwrap_err();
        drop(hook);
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(
                directory
                    .join(OBJECT_DIRECTORY)
                    .join(EVIDENCE_DIRECTORY)
                    .join("provider-sentinel.keep")
            )
            .unwrap(),
            b"preserve"
        );
        drop(pin);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pinned_known_evidence_uses_retained_directory_and_fails_closed_on_replacement() {
        let directory = test_directory("pinned-known-evidence-race");
        fs::create_dir_all(&directory).unwrap();
        ensure_layout(&directory).unwrap();
        let stage = directory.join("transaction.ready");
        fs::write(&stage, b"authenticated evidence").unwrap();
        let pin = V2NamespacePin::capture(&directory).unwrap();
        let action_directory = directory.clone();
        let hook = namespace_test_hook::Guard::arm("before pinned v2 evidence rename", move || {
            replace_evidence_directory(&action_directory);
        });
        let error = retain_known_file_with_pin(
            &directory,
            &stage,
            b"authenticated evidence",
            "normal-00112233445566778899aabbccddeeff-root",
            "test pinned evidence retention",
            &pin,
        )
        .unwrap_err();
        drop(hook);
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        let namespace = directory.join(OBJECT_DIRECTORY);
        assert_eq!(
            fs::read(
                namespace
                    .join("provider-displaced-evidence")
                    .join("normal-00112233445566778899aabbccddeeff-root.retained")
            )
            .unwrap(),
            b"authenticated evidence"
        );
        assert_eq!(
            fs::read(
                namespace
                    .join(EVIDENCE_DIRECTORY)
                    .join("provider-sentinel.keep")
            )
            .unwrap(),
            b"preserve"
        );
        drop(pin);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pinned_manifest_evidence_link_cannot_be_diverted() {
        let directory = test_directory("pinned-manifest-evidence-race");
        fs::create_dir_all(&directory).unwrap();
        ensure_layout(&directory).unwrap();
        let manifest = directory.join(WRITE_MANIFEST);
        fs::write(&manifest, b"authenticated manifest").unwrap();
        let pin = V2NamespacePin::capture(&directory).unwrap();
        let action_directory = directory.clone();
        let hook =
            namespace_test_hook::Guard::arm("before pinned v2 manifest evidence link", move || {
                replace_evidence_directory(&action_directory);
            });
        let error = retain_manifest_last_with_pin(
            &directory,
            &manifest,
            b"authenticated manifest",
            "normal-00112233445566778899aabbccddeeff-manifest",
            &pin,
        )
        .unwrap_err();
        drop(hook);
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        let namespace = directory.join(OBJECT_DIRECTORY);
        assert_eq!(
            fs::read(
                namespace
                    .join("provider-displaced-evidence")
                    .join("normal-00112233445566778899aabbccddeeff-manifest.durable")
            )
            .unwrap(),
            b"authenticated manifest"
        );
        assert_eq!(
            fs::read(
                namespace
                    .join(EVIDENCE_DIRECTORY)
                    .join("provider-sentinel.keep")
            )
            .unwrap(),
            b"preserve"
        );
        assert_eq!(fs::read(&manifest).unwrap(), b"authenticated manifest");
        drop(pin);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pinned_evidence_collision_and_missing_source_preserve_every_name() {
        let directory = test_directory("pinned-evidence-collision");
        fs::create_dir_all(&directory).unwrap();
        ensure_layout(&directory).unwrap();
        let pin = V2NamespacePin::capture(&directory).unwrap();
        let stage = directory.join("transaction.ready");
        fs::write(&stage, b"authenticated evidence").unwrap();
        let evidence = directory.join(OBJECT_DIRECTORY).join(EVIDENCE_DIRECTORY);
        let target = evidence.join("normal-00112233445566778899aabbccddeeff-root.retained");
        let action_target = target.clone();
        let hook = namespace_test_hook::Guard::arm("before pinned v2 evidence rename", move || {
            fs::write(&action_target, b"provider conflict").unwrap();
        });
        let error = retain_known_file_with_pin(
            &directory,
            &stage,
            b"authenticated evidence",
            "normal-00112233445566778899aabbccddeeff-root",
            "test pinned evidence collision",
            &pin,
        )
        .unwrap_err();
        drop(hook);
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&stage).unwrap(), b"authenticated evidence");
        assert_eq!(fs::read(&target).unwrap(), b"provider conflict");

        let untrusted_stage = directory.join("untrusted.ready");
        fs::write(&untrusted_stage, b"observed partial bytes").unwrap();
        let action_untrusted_stage = untrusted_stage.clone();
        let hook = namespace_test_hook::Guard::arm(
            "before pinned v2 untrusted evidence rename",
            move || {
                fs::write(&action_untrusted_stage, b"provider replacement bytes").unwrap();
            },
        );
        let error = retain_untrusted_file_with_pin(
            &directory,
            &untrusted_stage,
            b"observed partial bytes",
            "migration-00112233445566778899aabbccddeeff-partial",
            "test changed untrusted evidence",
            &pin,
        )
        .unwrap_err();
        drop(hook);
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            fs::read(evidence.join("migration-00112233445566778899aabbccddeeff-partial.untrusted"))
                .unwrap(),
            b"provider replacement bytes"
        );

        let missing = directory.join("missing.ready");
        assert!(
            retain_known_file_with_pin(
                &directory,
                &missing,
                b"missing evidence",
                "normal-ffeeddccbbaa99887766554433221100-root",
                "test missing known evidence",
                &pin,
            )
            .is_err()
        );
        assert!(
            retain_untrusted_file_with_pin(
                &directory,
                &missing,
                b"missing untrusted evidence",
                "migration-ffeeddccbbaa99887766554433221100-partial",
                "test missing untrusted evidence",
                &pin,
            )
            .is_err()
        );
        drop(pin);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pinned_commit_refuses_namespace_replacement_before_root_publication() {
        let directory = test_directory("pinned-commit-namespace-race");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();
        let (file_root, size) =
            write_file_range(&directory, &key, "", 0, 0, b"old content").unwrap();
        let mut old_index = index_with_file("old.txt");
        old_index.inodes.get_mut(&2).unwrap().disk_filename = file_root;
        old_index.inodes.get_mut(&2).unwrap().size = size;
        let old_state = commit_index(&directory, &key, &old_index, None).unwrap();
        let old_root = fs::read(directory.join(ROOT_FILE)).unwrap();

        let mut new_index = old_index.clone();
        new_index.inodes.get_mut(&2).unwrap().name = "new.txt".to_string();
        new_index.children.get_mut(&1).unwrap()[0].name = "new.txt".to_string();
        let json = serde_json::to_vec(&new_index).unwrap();
        let pin = V2NamespacePin::capture(&directory).unwrap();
        let action_directory = directory.clone();
        let hook = namespace_test_hook::Guard::arm("before v2 root publication", move || {
            replace_selected_namespace(&action_directory);
        });
        let failure = commit_with_phase_pinned(
            &directory,
            &key,
            &json,
            Some(&old_state),
            &kdf_fingerprint(),
            &pin,
        )
        .unwrap_err();
        drop(hook);
        assert_eq!(failure.error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(failure.recovery_required);
        assert_eq!(fs::read(directory.join(ROOT_FILE)).unwrap(), old_root);
        assert!(directory.join(WRITE_MANIFEST).exists());

        let paths = (
            directory.join(OBJECT_DIRECTORY),
            directory.join("provider-displaced-namespace-evidence"),
            directory.join("provider-replacement-evidence"),
        );
        drop(pin);
        restore_displaced_namespace(&paths);
        recover(&directory, &key, &kdf_fingerprint()).unwrap();
        assert_eq!(load(&directory, &key).unwrap().0, new_index);
        assert!(
            paths.2.is_dir(),
            "provider replacement evidence was discarded"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pinned_commit_latches_replacement_at_manifest_last_boundary() {
        let directory = test_directory("pinned-commit-manifest-last-race");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&directory, &key, &old_index, None).unwrap();
        let old_root = fs::read(directory.join(ROOT_FILE)).unwrap();
        let new_index = index_with_file("new.txt");
        let json = serde_json::to_vec(&new_index).unwrap();
        let pin = V2NamespacePin::capture(&directory).unwrap();
        let action_directory = directory.clone();
        let hook = namespace_test_hook::Guard::arm("after v2 manifest completion", move || {
            replace_selected_namespace(&action_directory);
        });
        let failure = commit_with_phase_pinned(
            &directory,
            &key,
            &json,
            Some(&old_state),
            &kdf_fingerprint(),
            &pin,
        )
        .unwrap_err();
        drop(hook);
        assert_eq!(failure.error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(failure.recovery_required);
        assert!(failure.own_intent_may_be_durable);
        assert_ne!(fs::read(directory.join(ROOT_FILE)).unwrap(), old_root);

        let paths = (
            directory.join(OBJECT_DIRECTORY),
            directory.join("provider-displaced-namespace-evidence"),
            directory.join("provider-replacement-evidence"),
        );
        drop(pin);
        restore_displaced_namespace(&paths);
        assert_eq!(load(&directory, &key).unwrap().0, new_index);
        assert!(!recover(&directory, &key, &kdf_fingerprint()).unwrap());
        assert!(
            paths.2.is_dir(),
            "provider replacement evidence was discarded"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pinned_recovery_refuses_namespace_replacement_before_root_publication() {
        let directory = test_directory("pinned-recovery-namespace-race");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&directory, &key, &old_index, None).unwrap();
        let old_root = fs::read(directory.join(ROOT_FILE)).unwrap();
        let new_index = index_with_file("new.txt");

        let trace = test_directory("pinned-recovery-trace");
        copy_directory(&directory, &trace);
        let recorder = FaultInjectionGuard::record();
        let (_, trace_state) = load(&trace, &key).unwrap();
        commit_index(&trace, &key, &new_index, Some(&trace_state)).unwrap();
        let manifest_publish = recorder
            .events()
            .iter()
            .position(|event| *event == DurabilityEvent::Rename)
            .unwrap()
            + 1;
        drop(recorder);
        fs::remove_dir_all(trace).unwrap();

        let injector = FaultInjectionGuard::fail_at(manifest_publish);
        assert!(commit_index(&directory, &key, &new_index, Some(&old_state)).is_err());
        drop(injector);
        assert!(directory.join(WRITE_MANIFEST).exists());

        let pin = V2NamespacePin::capture(&directory).unwrap();
        let action_directory = directory.clone();
        let hook =
            namespace_test_hook::Guard::arm("before v2 recovery root publication", move || {
                replace_selected_namespace(&action_directory);
            });
        let error =
            recover_with_namespace_pin(&directory, &key, &kdf_fingerprint(), &pin).unwrap_err();
        drop(hook);
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(directory.join(ROOT_FILE)).unwrap(), old_root);

        let paths = (
            directory.join(OBJECT_DIRECTORY),
            directory.join("provider-displaced-namespace-evidence"),
            directory.join("provider-replacement-evidence"),
        );
        drop(pin);
        restore_displaced_namespace(&paths);
        recover(&directory, &key, &kdf_fingerprint()).unwrap();
        assert_eq!(load(&directory, &key).unwrap().0, new_index);
        assert!(
            paths.2.is_dir(),
            "provider replacement evidence was discarded"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn chunk_tree_random_io_and_truncate_are_file_size_independent() {
        let directory = test_directory("chunk-tree");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();

        let (low_root, low_size) = write_file_range(&directory, &key, "", 0, 0, b"head").unwrap();
        let far_sparse_size = CHUNK_SIZE as u64 * TREE_FANOUT + 4;
        let low_root =
            truncate_file(&directory, &key, &low_root, low_size, far_sparse_size).unwrap();
        assert_eq!(
            read_file_range(
                &directory,
                &key,
                &low_root,
                far_sparse_size,
                CHUNK_SIZE as u64 * TREE_FANOUT,
                4,
            )
            .unwrap(),
            b"\0\0\0\0",
            "sparse growth must not alias chunk zero at the next radix span"
        );
        assert_eq!(
            read_file_range(&directory, &key, &low_root, far_sparse_size, 0, 4).unwrap(),
            b"head"
        );

        let chunk_200 = CHUNK_SIZE as u64 * 200;
        let (short_tree, short_size) =
            write_file_range(&directory, &key, "", 0, chunk_200, b"survives").unwrap();
        let grown_size = CHUNK_SIZE as u64 * 301 + 1;
        let short_tree =
            truncate_file(&directory, &key, &short_tree, short_size, grown_size).unwrap();
        let shrunk_size = CHUNK_SIZE as u64 * 260 + 1;
        let short_tree =
            truncate_file(&directory, &key, &short_tree, grown_size, shrunk_size).unwrap();
        assert_eq!(
            read_file_range(&directory, &key, &short_tree, shrunk_size, chunk_200, 8,).unwrap(),
            b"survives",
            "shrinking above a short radix tree must not wrap the EOF digit and prune live chunks"
        );

        let first = write_object(&directory, &key, ObjectKind::Data, b"a").unwrap();
        let far = write_object(&directory, &key, ObjectKind::Data, b"b").unwrap();
        let mut builder = StreamingTreeBuilder::new(&directory, &key);
        builder.add(0, 0, first).unwrap();
        builder.add(0, 300, far).unwrap();
        let (tree, height) = builder.finish().unwrap();
        assert_eq!(height, 1);
        let streamed_size = CHUNK_SIZE as u64 * 300 + 1;
        let streamed_root = write_file_root(
            &directory,
            &key,
            &FileRoot {
                format_version: FORMAT_VERSION,
                size: streamed_size,
                height,
                tree,
            },
        )
        .unwrap();
        validate_reachable_file(&directory, &key, &streamed_root, streamed_size).unwrap();
        assert_eq!(
            read_file_range(&directory, &key, &streamed_root, streamed_size, 0, 1).unwrap(),
            b"a"
        );
        assert_eq!(
            read_file_range(
                &directory,
                &key,
                &streamed_root,
                streamed_size,
                CHUNK_SIZE as u64 * 300,
                1,
            )
            .unwrap(),
            b"b"
        );

        let zero_offset = CHUNK_SIZE as u64 * TREE_FANOUT;
        let (zero_root, zero_size) =
            write_file_range(&directory, &key, "", 0, zero_offset, b"\0\0\0\0").unwrap();
        validate_reachable_file(&directory, &key, &zero_root, zero_size).unwrap();
        assert_eq!(
            read_file_range(&directory, &key, &zero_root, zero_size, zero_offset, 4).unwrap(),
            b"\0\0\0\0"
        );
        let (populated_root, populated_size) =
            write_file_range(&directory, &key, "", 0, zero_offset, b"data").unwrap();
        let (cleared_root, cleared_size) = write_file_range(
            &directory,
            &key,
            &populated_root,
            populated_size,
            zero_offset,
            b"\0\0\0\0",
        )
        .unwrap();
        validate_reachable_file(&directory, &key, &cleared_root, cleared_size).unwrap();
        assert_eq!(
            read_file_range(
                &directory,
                &key,
                &cleared_root,
                cleared_size,
                zero_offset,
                4,
            )
            .unwrap(),
            b"\0\0\0\0"
        );

        let far_offset = CHUNK_SIZE as u64 * 3 + 17;
        let (root, size) = write_file_range(&directory, &key, "", 0, far_offset, b"tail").unwrap();
        assert_eq!(size, far_offset + 4);
        assert_eq!(
            read_file_range(&directory, &key, &root, size, far_offset - 3, 7).unwrap(),
            b"\0\0\0tail"
        );

        let (root, size) = write_file_range(
            &directory,
            &key,
            &root,
            size,
            CHUNK_SIZE as u64 - 2,
            b"abcdef",
        )
        .unwrap();
        let object_count = fs::read_dir(directory.join(OBJECT_DIRECTORY).join(OBJECTS_DIRECTORY))
            .unwrap()
            .count();
        let (same_root, same_size) = write_file_range(
            &directory,
            &key,
            &root,
            size,
            CHUNK_SIZE as u64 - 2,
            b"abcdef",
        )
        .unwrap();
        assert_eq!((same_root, same_size), (root.clone(), size));
        assert_eq!(
            fs::read_dir(directory.join(OBJECT_DIRECTORY).join(OBJECTS_DIRECTORY),)
                .unwrap()
                .count(),
            object_count,
            "an identical write must not create immutable cloud objects"
        );
        assert_eq!(
            read_file_range(&directory, &key, &root, size, CHUNK_SIZE as u64 - 4, 10,).unwrap(),
            b"\0\0abcdef\0\0"
        );

        let shrunk_size = CHUNK_SIZE as u64 + 1;
        let root = truncate_file(&directory, &key, &root, size, shrunk_size).unwrap();
        let grown_size = far_offset + 4;
        let root = truncate_file(&directory, &key, &root, shrunk_size, grown_size).unwrap();
        assert_eq!(
            read_file_range(&directory, &key, &root, grown_size, far_offset, 4).unwrap(),
            b"\0\0\0\0"
        );
        validate_reachable_file(&directory, &key, &root, grown_size).unwrap();

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cached_read_fills_a_complete_request_across_chunk_boundaries() {
        let directory = test_directory("cached-cross-chunk-read");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();

        let first = vec![0x5a; CHUNK_SIZE];
        let tail = vec![0xa5; 8 * 1024];
        let (root, size) = write_file_range(&directory, &key, "", 0, 0, &first).unwrap();
        let (root, size) =
            write_file_range(&directory, &key, &root, size, CHUNK_SIZE as u64, &tail).unwrap();

        let requested = CHUNK_SIZE + tail.len();
        let data = read_file_range(&directory, &key, &root, size, 0, requested).unwrap();
        assert_eq!(data.len(), requested);
        assert_eq!(&data[..CHUNK_SIZE], first.as_slice());
        assert_eq!(&data[CHUNK_SIZE..], tail.as_slice());

        let oversized = MAX_FUSE_READ_SIZE + 1;
        let sparse_root = truncate_file(&directory, &key, &root, size, oversized as u64).unwrap();
        let error = read_file_range(
            &directory,
            &key,
            &sparse_root,
            oversized as u64,
            0,
            oversized,
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EFBIG));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn every_commit_checkpoint_recovers_to_exact_old_or_new_generation() {
        let baseline = test_directory("crash-baseline");
        fs::create_dir_all(&baseline).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&baseline, &key, &old_index, None).unwrap();
        let old_root_bytes = fs::read(baseline.join(ROOT_FILE)).unwrap();
        let new_index = index_with_file("new.txt");

        let successful = test_directory("crash-success");
        copy_directory(&baseline, &successful);
        let (_, successful_old) = load(&successful, &key).unwrap();
        let recorder = FaultInjectionGuard::record();
        commit_index(&successful, &key, &new_index, Some(&successful_old)).unwrap();
        let events = recorder.events();
        drop(recorder);
        assert!(events.contains(&DurabilityEvent::Write));
        assert!(events.contains(&DurabilityEvent::FileSync));
        assert!(events.contains(&DurabilityEvent::Rename));
        assert!(events.contains(&DurabilityEvent::DirectorySync));
        assert!(events.contains(&DurabilityEvent::Cleanup));
        fs::remove_dir_all(successful).unwrap();

        for checkpoint in 1..=events.len() {
            let crashed = test_directory(&format!("commit-crash-{checkpoint}"));
            copy_directory(&baseline, &crashed);
            fs::write(crashed.join("conflict-evidence.keep"), b"preserve me").unwrap();
            let (_, state) = load(&crashed, &key).unwrap();
            let injector = FaultInjectionGuard::fail_at(checkpoint);
            let result = commit_index(&crashed, &key, &new_index, Some(&state));
            drop(injector);
            assert!(result.is_err(), "checkpoint {checkpoint} was not exercised");

            recover(&crashed, &key, &kdf_fingerprint()).unwrap();
            let (visible, visible_state) = load(&crashed, &key).unwrap();
            assert!(
                visible == old_index || visible == new_index,
                "checkpoint {checkpoint} exposed a mixed/unknown generation"
            );
            if visible == old_index {
                assert_eq!(
                    fs::read(crashed.join(ROOT_FILE)).unwrap(),
                    old_root_bytes,
                    "checkpoint {checkpoint} changed the exact old root bytes"
                );
            } else {
                assert_eq!(visible_state.number, old_state.number + 1);
                assert_eq!(visible_state.parent, Some(old_state.generation));
                assert_eq!(visible_state.origin, Some(old_state.generation));
                assert_eq!(visible_state.lineage_id, old_state.lineage_id);
            }
            assert_eq!(
                fs::read(crashed.join("conflict-evidence.keep")).unwrap(),
                b"preserve me"
            );
            fs::remove_dir_all(crashed).unwrap();
        }

        assert_eq!(old_state.number, 1);
        fs::remove_dir_all(baseline).unwrap();
    }

    #[test]
    fn pre_intent_staging_orphans_are_preserved_without_blocking_retry() {
        let baseline = test_directory("pre-intent-orphan-baseline");
        fs::create_dir_all(&baseline).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&baseline, &key, &old_index, None).unwrap();
        let new_index = index_with_file("new.txt");

        let trace = test_directory("pre-intent-orphan-trace");
        copy_directory(&baseline, &trace);
        let (_, trace_state) = load(&trace, &key).unwrap();
        let recorder = FaultInjectionGuard::record();
        commit_index(&trace, &key, &new_index, Some(&trace_state)).unwrap();
        let manifest_publish = recorder
            .events()
            .iter()
            .position(|event| *event == DurabilityEvent::Rename)
            .unwrap()
            + 1;
        drop(recorder);
        fs::remove_dir_all(trace).unwrap();

        let injector = FaultInjectionGuard::fail_at(manifest_publish - 1);
        assert!(commit_index(&baseline, &key, &new_index, Some(&old_state)).is_err());
        drop(injector);
        assert!(!baseline.join(WRITE_MANIFEST).exists());
        let orphans: Vec<_> = fs::read_dir(&baseline)
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("_z2-") && name.ends_with(".ready"))
            })
            .map(|entry| (entry.file_name(), fs::read(entry.path()).unwrap()))
            .collect();
        assert!(orphans.len() >= 2, "root and manifest staging must survive");

        assert!(!recover(&baseline, &key, &kdf_fingerprint()).unwrap());
        commit_index(&baseline, &key, &new_index, Some(&old_state)).unwrap();
        assert_eq!(load(&baseline, &key).unwrap().0, new_index);
        for (name, bytes) in orphans {
            assert_eq!(
                fs::read(baseline.join(name)).unwrap(),
                bytes,
                "pre-intent staging evidence must not be deleted or replaced"
            );
        }

        fs::remove_dir_all(baseline).unwrap();
    }

    #[test]
    fn recovery_is_fault_injected_and_idempotent_without_discarding_evidence() {
        let baseline = test_directory("recovery-baseline");
        fs::create_dir_all(&baseline).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&baseline, &key, &old_index, None).unwrap();
        let new_index = index_with_file("new.txt");

        // The first namespace event is authenticated manifest publication.
        // Fail immediately afterward to leave a durable roll-forward intent
        // while the old root remains canonical.
        let trace_dir = test_directory("recovery-trace");
        copy_directory(&baseline, &trace_dir);
        let recorder = FaultInjectionGuard::record();
        commit_index(&trace_dir, &key, &new_index, Some(&old_state)).unwrap();
        let commit_events = recorder.events();
        drop(recorder);
        fs::remove_dir_all(trace_dir).unwrap();
        let manifest_publish = commit_events
            .iter()
            .position(|event| *event == DurabilityEvent::Rename)
            .unwrap()
            + 1;

        let pending = test_directory("recovery-pending");
        copy_directory(&baseline, &pending);
        let injector = FaultInjectionGuard::fail_at(manifest_publish);
        assert!(commit_index(&pending, &key, &new_index, Some(&old_state)).is_err());
        drop(injector);
        assert!(pending.join(WRITE_MANIFEST).exists());
        assert_eq!(load(&pending, &key).unwrap().0.inodes[&2].name, "old.txt");

        let recovery_trace = test_directory("recovery-count");
        copy_directory(&pending, &recovery_trace);
        let recorder = FaultInjectionGuard::record();
        recover(&recovery_trace, &key, &kdf_fingerprint()).unwrap();
        let recovery_events = recorder.events();
        drop(recorder);
        assert!(recovery_events.contains(&DurabilityEvent::Recovery));
        fs::remove_dir_all(recovery_trace).unwrap();

        for checkpoint in 1..=recovery_events.len() {
            let crashed = test_directory(&format!("recovery-crash-{checkpoint}"));
            copy_directory(&pending, &crashed);
            fs::write(crashed.join("provider-conflict.keep"), b"evidence").unwrap();
            let injector = FaultInjectionGuard::fail_at(checkpoint);
            let result = recover(&crashed, &key, &kdf_fingerprint());
            drop(injector);
            assert!(
                result.is_err(),
                "recovery checkpoint {checkpoint} was not hit"
            );
            recover(&crashed, &key, &kdf_fingerprint()).unwrap();
            assert!(!recover(&crashed, &key, &kdf_fingerprint()).unwrap());
            assert_eq!(load(&crashed, &key).unwrap().0, new_index);
            assert_eq!(
                fs::read(crashed.join("provider-conflict.keep")).unwrap(),
                b"evidence"
            );
            fs::remove_dir_all(crashed).unwrap();
        }

        fs::remove_dir_all(pending).unwrap();
        fs::remove_dir_all(baseline).unwrap();
    }

    #[test]
    fn recovery_refuses_a_provider_root_sibling_without_discarding_it() {
        let baseline = test_directory("provider-sibling-baseline");
        fs::create_dir_all(&baseline).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&baseline, &key, &old_index, None).unwrap();
        let new_index = index_with_file("new.txt");

        let trace = test_directory("provider-sibling-trace");
        copy_directory(&baseline, &trace);
        let recorder = FaultInjectionGuard::record();
        commit_index(&trace, &key, &new_index, Some(&old_state)).unwrap();
        let manifest_publish = recorder
            .events()
            .iter()
            .position(|event| *event == DurabilityEvent::Rename)
            .unwrap()
            + 1;
        drop(recorder);
        fs::remove_dir_all(trace).unwrap();

        let injector = FaultInjectionGuard::fail_at(manifest_publish);
        assert!(commit_index(&baseline, &key, &new_index, Some(&old_state)).is_err());
        drop(injector);
        let sibling = baseline.join("_root (conflicted copy).age");
        fs::write(&sibling, b"provider evidence").unwrap();

        let error = recover(&baseline, &key, &kdf_fingerprint()).unwrap_err();
        assert!(error.to_string().contains("cloud-conflict"), "{error}");
        assert_eq!(load(&baseline, &key).unwrap().0, old_index);
        assert_eq!(fs::read(&sibling).unwrap(), b"provider evidence");
        assert!(baseline.join(WRITE_MANIFEST).exists());

        fs::remove_dir_all(baseline).unwrap();
    }

    #[test]
    fn recovery_keeps_old_root_until_every_new_object_is_materialized() {
        let directory = test_directory("partial-new-generation");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&directory, &key, &old_index, None).unwrap();
        let old_root = fs::read(directory.join(ROOT_FILE)).unwrap();

        let mut new_index = index_with_file("new.txt");
        let (file_root, size) =
            write_file_range(&directory, &key, "", 0, 0, b"must arrive first").unwrap();
        let root = load_file_root(&directory, &key, &file_root, size).unwrap();
        let data = get_chunk_ref(&directory, &key, root.tree, root.height, 0, None)
            .unwrap()
            .unwrap();
        let entry = new_index.inodes.get_mut(&2).unwrap();
        entry.disk_filename = file_root;
        entry.size = size;

        let trace = test_directory("partial-new-generation-trace");
        copy_directory(&directory, &trace);
        let recorder = FaultInjectionGuard::record();
        let (_, trace_state) = load(&trace, &key).unwrap();
        commit_index(&trace, &key, &new_index, Some(&trace_state)).unwrap();
        let manifest_publish = recorder
            .events()
            .iter()
            .position(|event| *event == DurabilityEvent::Rename)
            .unwrap()
            + 1;
        drop(recorder);
        fs::remove_dir_all(trace).unwrap();

        let injector = FaultInjectionGuard::fail_at(manifest_publish);
        assert!(commit_index(&directory, &key, &new_index, Some(&old_state)).is_err());
        drop(injector);
        assert!(directory.join(WRITE_MANIFEST).exists());
        fs::remove_file(object_path(&directory, &data).unwrap()).unwrap();

        let error = recover(&directory, &key, &kdf_fingerprint()).unwrap_err();
        assert!(
            error.to_string().contains("not completely materialized"),
            "{error}"
        );
        assert_eq!(
            fs::read(directory.join(ROOT_FILE)).unwrap(),
            old_root,
            "recovery must not publish an incomplete new generation"
        );
        assert!(directory.join(WRITE_MANIFEST).exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn remount_audits_manifest_evidence_moved_by_a_provider_race() {
        let directory = test_directory("manifest-evidence-audit");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();
        commit_index(&directory, &key, &index_with_file("committed.txt"), None).unwrap();

        let evidence = directory.join(OBJECT_DIRECTORY).join(EVIDENCE_DIRECTORY);
        let retained = fs::read_dir(&evidence)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("normal-") && name.ends_with("-manifest.retained")
                    })
            })
            .expect("successful commit must retain its canonical manifest");
        fs::remove_file(&retained).unwrap();
        fs::write(&retained, b"provider replacement evidence").unwrap();

        let error = recover(&directory, &key, &kdf_fingerprint()).unwrap_err();
        assert!(error.to_string().contains("is not authentic"), "{error}");
        assert_eq!(
            fs::read(&retained).unwrap(),
            b"provider replacement evidence",
            "foreign conflict evidence must remain available for reconciliation"
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn completed_update_manifest_requires_exact_displaced_root_evidence() {
        let directory = test_directory("completed-manifest-root-evidence");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();
        let old_state = commit_index(&directory, &key, &index_with_file("old.txt"), None).unwrap();
        commit_index(
            &directory,
            &key,
            &index_with_file("new.txt"),
            Some(&old_state),
        )
        .unwrap();
        let visible_root = fs::read(directory.join(ROOT_FILE)).unwrap();
        let evidence = directory.join(OBJECT_DIRECTORY).join(EVIDENCE_DIRECTORY);
        let retained_root = fs::read_dir(&evidence)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("normal-") && name.ends_with("-root.retained")
                    })
            })
            .expect("completed update must retain its displaced root");
        fs::remove_file(&retained_root).unwrap();
        File::open(&evidence).unwrap().sync_all().unwrap();

        let error = recover(&directory, &key, &kdf_fingerprint()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no readable displaced-root evidence"),
            "{error}"
        );
        assert_eq!(
            fs::read(directory.join(ROOT_FILE)).unwrap(),
            visible_root,
            "evidence audit must not alter the visible root"
        );
        assert!(!retained_root.exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn completed_update_manifest_requires_complete_displaced_generation() {
        let directory = test_directory("completed-manifest-old-generation");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();
        let old_state = commit_index(&directory, &key, &index_with_file("old.txt"), None).unwrap();
        let new_index = index_with_file("new.txt");
        commit_index(&directory, &key, &new_index, Some(&old_state)).unwrap();
        let evidence = directory.join(OBJECT_DIRECTORY).join(EVIDENCE_DIRECTORY);
        let update_transaction = fs::read_dir(&evidence)
            .unwrap()
            .filter_map(Result::ok)
            .find_map(|entry| {
                let name = entry.file_name();
                let name = name.to_str()?;
                if !name.ends_with("-manifest.durable") {
                    return None;
                }
                let manifest =
                    decode_manifest_ciphertext(&key, fs::read(entry.path()).ok()?).ok()?;
                (manifest.generation_number == 2)
                    .then(|| format!("normal-{}", to_hex(&manifest.transaction_id)))
            })
            .expect("the update must retain a durable manifest anchor");
        for entry in fs::read_dir(&evidence).unwrap() {
            let entry = entry.unwrap();
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with(&update_transaction)
            {
                fs::remove_file(entry.path()).unwrap();
            }
        }
        File::open(&evidence).unwrap().sync_all().unwrap();
        let old_generation = object_path(&directory, &old_state.generation).unwrap();
        fs::remove_file(&old_generation).unwrap();
        File::open(old_generation.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
        assert_eq!(
            load(&directory, &key).unwrap().0,
            new_index,
            "the current head alone does not dereference its previous generation"
        );

        let error = recover(&directory, &key, &kdf_fingerprint()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot load its authenticated generation"),
            "{error}"
        );
        assert!(!old_generation.exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn completed_update_manifest_requires_complete_displaced_ancestry() {
        let directory = test_directory("completed-manifest-old-ancestry");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();
        let first = commit_index(&directory, &key, &index_with_file("first.txt"), None).unwrap();
        let second = commit_index(
            &directory,
            &key,
            &index_with_file("second.txt"),
            Some(&first),
        )
        .unwrap();
        let current_index = index_with_file("third.txt");
        commit_index(&directory, &key, &current_index, Some(&second)).unwrap();

        let evidence = directory.join(OBJECT_DIRECTORY).join(EVIDENCE_DIRECTORY);
        let latest_transaction = fs::read_dir(&evidence)
            .unwrap()
            .filter_map(Result::ok)
            .find_map(|entry| {
                let name = entry.file_name();
                let name = name.to_str()?;
                if !name.ends_with("-manifest.durable") {
                    return None;
                }
                let manifest =
                    decode_manifest_ciphertext(&key, fs::read(entry.path()).ok()?).ok()?;
                (manifest.generation_number == 3)
                    .then(|| format!("normal-{}", to_hex(&manifest.transaction_id)))
            })
            .expect("the third commit must retain a durable manifest anchor");
        for entry in fs::read_dir(&evidence).unwrap() {
            let entry = entry.unwrap();
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with(&latest_transaction)
            {
                fs::remove_file(entry.path()).unwrap();
            }
        }
        File::open(&evidence).unwrap().sync_all().unwrap();

        let first_generation = object_path(&directory, &first.generation).unwrap();
        fs::remove_file(&first_generation).unwrap();
        File::open(first_generation.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
        assert_eq!(
            load(&directory, &key).unwrap().0,
            current_index,
            "the current and immediate previous generation do not dereference older ancestry"
        );

        let error = recover(&directory, &key, &kdf_fingerprint()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("complete authenticated generation lineage"),
            "{error}"
        );
        assert!(
            !first_generation.exists(),
            "the failed audit must not fabricate missing ancestry"
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn retained_manifest_ready_requires_complete_new_generation_lineage() {
        let directory = test_directory("manifest-ready-new-lineage");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&directory, &key, &old_index, None).unwrap();
        let new_index = index_with_file("unpublished.txt");

        let trace = test_directory("manifest-ready-new-lineage-trace");
        copy_directory(&directory, &trace);
        let (_, trace_state) = load(&trace, &key).unwrap();
        let recorder = FaultInjectionGuard::record();
        commit_index(&trace, &key, &new_index, Some(&trace_state)).unwrap();
        let manifest_publish = recorder
            .events()
            .iter()
            .position(|event| *event == DurabilityEvent::Rename)
            .unwrap()
            + 1;
        drop(recorder);
        fs::remove_dir_all(trace).unwrap();

        let injector = FaultInjectionGuard::fail_at(manifest_publish - 1);
        assert!(commit_index(&directory, &key, &new_index, Some(&old_state)).is_err());
        drop(injector);
        assert!(!directory.join(WRITE_MANIFEST).exists());
        let manifest_ready = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap())
            .find(|entry| {
                entry.file_name().to_str().is_some_and(|name| {
                    name.starts_with(MANIFEST_READY_PREFIX) && name.ends_with(".ready")
                })
            })
            .expect("the failed pre-intent commit must retain its manifest-ready file");
        let manifest_ciphertext = fs::read(manifest_ready.path()).unwrap();
        let manifest = decode_manifest_ciphertext(&key, manifest_ciphertext).unwrap();
        let evidence = directory.join(OBJECT_DIRECTORY).join(EVIDENCE_DIRECTORY);
        let retained_name = format!(
            "normal-{}-manifest-ready.retained",
            to_hex(&manifest.transaction_id)
        );
        fs::rename(manifest_ready.path(), evidence.join(retained_name)).unwrap();
        File::open(&evidence).unwrap().sync_all().unwrap();
        File::open(&directory).unwrap().sync_all().unwrap();

        let missing_generation = object_path(&directory, &manifest.new_generation).unwrap();
        fs::remove_file(&missing_generation).unwrap();
        File::open(missing_generation.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
        assert_eq!(
            load(&directory, &key).unwrap().0,
            old_index,
            "the unpublished branch must not change the canonical root"
        );

        let error = recover(&directory, &key, &kdf_fingerprint()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("complete authenticated new-generation lineage"),
            "{error}"
        );
        assert!(
            !missing_generation.exists(),
            "the failed audit must not fabricate discarded conflict evidence"
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pending_manifest_fails_first_recovery_when_displaced_lineage_is_missing() {
        let directory = test_directory("pending-manifest-missing-old-lineage");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&directory, &key, &old_index, None).unwrap();
        let new_index = index_with_file("new.txt");

        let trace = test_directory("pending-manifest-missing-old-lineage-trace");
        copy_directory(&directory, &trace);
        let (_, trace_state) = load(&trace, &key).unwrap();
        let recorder = FaultInjectionGuard::record();
        commit_index(&trace, &key, &new_index, Some(&trace_state)).unwrap();
        let root_evidence_durable = recorder
            .checkpoints()
            .iter()
            .rposition(|checkpoint| {
                checkpoint.context == "retain displaced authenticated v2 root evidence"
            })
            .expect("the update must durably retain its displaced root")
            + 1;
        drop(recorder);
        fs::remove_dir_all(trace).unwrap();

        let injector = FaultInjectionGuard::fail_at(root_evidence_durable);
        assert!(commit_index(&directory, &key, &new_index, Some(&old_state)).is_err());
        drop(injector);
        let (manifest, _) = read_manifest(&directory, &key)
            .unwrap()
            .expect("the interrupted commit must retain canonical write intent");
        let transaction_hex = to_hex(&manifest.transaction_id);
        let retained_root_name = format!("normal-{transaction_hex}-root.retained");
        let evidence = directory.join(OBJECT_DIRECTORY).join(EVIDENCE_DIRECTORY);
        for entry in fs::read_dir(&evidence).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() != OsStr::new(&retained_root_name) {
                fs::remove_file(entry.path()).unwrap();
            }
        }
        File::open(&evidence).unwrap().sync_all().unwrap();
        assert!(evidence.join(&retained_root_name).exists());

        let missing_generation = object_path(&directory, &old_state.generation).unwrap();
        fs::remove_file(&missing_generation).unwrap();
        File::open(missing_generation.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
        let visible_root = fs::read(directory.join(ROOT_FILE)).unwrap();
        assert_eq!(
            load(&directory, &key).unwrap().0,
            new_index,
            "the current snapshot alone does not dereference its displaced ancestry"
        );

        let error = recover(&directory, &key, &kdf_fingerprint()).unwrap_err();
        assert!(
            error.to_string().contains(
                "pending v2 write intent does not retain its complete authenticated old-generation lineage"
            ),
            "{error}"
        );
        assert_eq!(
            fs::read(directory.join(ROOT_FILE)).unwrap(),
            visible_root,
            "the first failed recovery must not mutate the visible new root"
        );
        assert!(directory.join(WRITE_MANIFEST).exists());
        assert!(evidence.join(retained_root_name).exists());

        fs::remove_dir_all(directory).unwrap();
    }
}
