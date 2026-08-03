// Copyright 2026 Alex O <info@lifub.com>

//! Capability-rooted backing-store access and macOS coordination primitives.
//!
//! The direct backend is wired only for pinned v2 immutable-object
//! publication. macOS coordinated mode remains deliberately disabled until
//! every backing path has moved behind `StoreRoot`; partial coordination would
//! advertise a guarantee the process does not provide. The native shim remains
//! a tested foundation for that later mechanical extraction. Coordinators for
//! one store share a purpose identifier to avoid lock inversion inside the
//! process. Each `StoreRoot` serializes its own accessors, but callers must
//! acquire the existing process-wide one-writer/persistence lock first because
//! separately opened roots are not mutually excluded by this local guard.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

thread_local! {
    /// A coordinated accessor may not enter another `StoreRoot` operation on
    /// the same thread. Foundation coordination and the per-root mutex are
    /// synchronous and non-reentrant; returning WouldBlock is safer than a
    /// callback deadlock.
    static IN_STORE_OPERATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccessIntent {
    Read,
    Write,
    Delete,
    Move,
    Replace,
}

#[derive(Default)]
struct MoveControl {
    moved: bool,
}

impl MoveControl {
    #[cfg(unix)]
    fn rename_exact(
        &mut self,
        source_parent: &DirCap,
        source_name: &OsStr,
        destination_parent: &DirCap,
        destination_name: &OsStr,
    ) -> io::Result<()> {
        if self.moved {
            return Err(io::Error::other(
                "an exact coordinated move may run only once",
            ));
        }
        validate_component(source_name, "move source")?;
        validate_component(destination_name, "move destination")?;
        let source_name = CString::new(source_name.as_bytes())?;
        let destination_name = CString::new(destination_name.as_bytes())?;
        let result = unsafe {
            libc::renameat(
                source_parent.as_file().as_raw_fd(),
                source_name.as_ptr(),
                destination_parent.as_file().as_raw_fd(),
                destination_name.as_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // There is no panic-capable operation between successful renameat and
        // this assignment. The native callback can therefore notify
        // presenters correctly even if later fsync/checkpoint code panics.
        self.moved = true;
        Ok(())
    }

    #[cfg(not(unix))]
    fn rename_exact(
        &mut self,
        _source_parent: &DirCap,
        _source_name: &OsStr,
        _destination_parent: &DirCap,
        _destination_name: &OsStr,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "exact backing-store moves require Unix renameat semantics",
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct RelativeStorePath(PathBuf);

impl RelativeStorePath {
    pub(crate) fn new(path: &Path) -> io::Result<Self> {
        if path.as_os_str().is_empty() || path.is_absolute() {
            return Err(invalid_input(
                "a backing-store entry must be a nonempty relative path",
            ));
        }

        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Normal(value) => normalized.push(value),
                Component::CurDir
                | Component::ParentDir
                | Component::RootDir
                | Component::Prefix(_) => {
                    return Err(invalid_input(
                        "a backing-store path may contain only normal relative components",
                    ));
                }
            }
        }
        if normalized.as_os_str() != path.as_os_str() {
            return Err(invalid_input(
                "a backing-store path must already be in canonical relative form",
            ));
        }
        Ok(Self(normalized))
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }
}

impl TryFrom<&Path> for RelativeStorePath {
    type Error = io::Error;

    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn from_file(file: &File, context: &str) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{context} is not a directory"),
            ));
        }
        #[cfg(unix)]
        {
            if metadata.ino() == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("{context} has no stable inode identity"),
                ));
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "backing-store directory capabilities require Unix inode identity",
            ))
        }
    }
}

#[derive(Debug)]
pub(crate) struct DirCap {
    file: Arc<File>,
    relative_path: PathBuf,
    identity: DirectoryIdentity,
    root_identity: DirectoryIdentity,
}

impl DirCap {
    pub(crate) fn as_file(&self) -> &File {
        &self.file
    }

    pub(crate) fn relative_path(&self) -> &Path {
        &self.relative_path
    }
}

#[derive(Debug)]
pub(crate) struct StoreEntry {
    parent: DirCap,
    name: OsString,
    relative_path: RelativeStorePath,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExactStoreOperation {
    pub(crate) path: PathBuf,
    pub(crate) is_directory: bool,
    pub(crate) intent: AccessIntent,
}

impl StoreEntry {
    pub(crate) fn parent(&self) -> &DirCap {
        &self.parent
    }

    pub(crate) fn name(&self) -> &OsStr {
        &self.name
    }

    pub(crate) fn relative_path(&self) -> &RelativeStorePath {
        &self.relative_path
    }
}

#[derive(Debug)]
enum Coordination {
    Direct,
    #[cfg(target_os = "macos")]
    Mac(MacCoordinator),
    #[cfg(test)]
    Fake(Arc<FakeCoordinator>),
}

#[derive(Debug)]
pub(crate) struct StoreRoot {
    presentation_root: PathBuf,
    root: Arc<File>,
    identity: DirectoryIdentity,
    coordination: Coordination,
    operation_guard: Mutex<()>,
    #[cfg(test)]
    exact_one_operations: Mutex<Vec<ExactStoreOperation>>,
}

struct StoreOperationGuard<'a> {
    _mutex_guard: MutexGuard<'a, ()>,
}

impl Drop for StoreOperationGuard<'_> {
    fn drop(&mut self) {
        IN_STORE_OPERATION.with(|active| {
            debug_assert!(
                active.get(),
                "backing-store operation guard lost its thread marker"
            );
            active.set(false);
        });
    }
}

impl StoreRoot {
    pub(crate) fn open_direct(path: &Path) -> io::Result<Self> {
        Self::open_with(path, Coordination::Direct)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn open_macos(path: &Path) -> io::Result<Self> {
        Self::open_with(path, Coordination::Mac(MacCoordinator::new()?))
    }

    fn open_with(path: &Path, coordination: Coordination) -> io::Result<Self> {
        let presentation_root = std::fs::canonicalize(path)?;
        if !presentation_root.is_absolute() {
            return Err(invalid_input(
                "the backing-store presentation root must be absolute",
            ));
        }
        let root = Arc::new(open_directory_absolute(&presentation_root)?);
        let identity = DirectoryIdentity::from_file(&root, "backing-store root")?;
        let store = Self {
            presentation_root,
            root,
            identity,
            coordination,
            operation_guard: Mutex::new(()),
            #[cfg(test)]
            exact_one_operations: Mutex::new(Vec::new()),
        };
        store.verify_root()?;
        Ok(store)
    }

    pub(crate) fn presentation_root(&self) -> &Path {
        &self.presentation_root
    }

    #[cfg(test)]
    pub(crate) fn exact_one_operations(&self) -> Vec<ExactStoreOperation> {
        self.exact_one_operations.lock().unwrap().clone()
    }

    pub(crate) fn entry(&self, relative_path: RelativeStorePath) -> io::Result<StoreEntry> {
        let name = relative_path
            .as_path()
            .file_name()
            .ok_or_else(|| invalid_input("a backing-store entry has no final component"))?
            .to_os_string();
        validate_component(&name, "backing-store entry")?;
        let parent_path = relative_path
            .as_path()
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let parent = self.open_directory_cap(parent_path)?;
        Ok(StoreEntry {
            parent,
            name,
            relative_path,
        })
    }

    pub(crate) fn coordinate_root<T>(
        &self,
        intent: AccessIntent,
        body: impl FnOnce(&File) -> io::Result<T>,
    ) -> io::Result<T> {
        if intent == AccessIntent::Move {
            return Err(invalid_input(
                "a move requires explicit source and destination entries",
            ));
        }
        let _operation_guard = self.lock_operations()?;
        let expected = self.presentation_root.clone();
        self.coordination
            .coordinate_one(&expected, true, intent, |adjusted| {
                reject_adjusted_url(&expected, adjusted)?;
                self.verify_root()?;
                let result = body(&self.root);
                let verification = self.verify_root();
                combine_operation_and_verification(result, verification)
            })
    }

    pub(crate) fn coordinate_one<T>(
        &self,
        entry: &StoreEntry,
        is_directory: bool,
        intent: AccessIntent,
        body: impl FnOnce(&DirCap, &OsStr) -> io::Result<T>,
    ) -> io::Result<T> {
        // The body must perform only the announced exact-item operation and
        // its associated file/parent fsyncs. It must not resolve the supplied
        // name through a process-relative path or recursively coordinate.
        if intent == AccessIntent::Move {
            return Err(invalid_input(
                "a move requires explicit source and destination entries",
            ));
        }
        let _operation_guard = self.lock_operations()?;
        self.ensure_entry_belongs(entry)?;
        let expected = self.presentation_root.join(entry.relative_path.as_path());
        #[cfg(test)]
        self.exact_one_operations
            .lock()
            .unwrap()
            .push(ExactStoreOperation {
                path: expected.clone(),
                is_directory,
                intent,
            });
        self.coordination
            .coordinate_one(&expected, is_directory, intent, |adjusted| {
                reject_adjusted_url(&expected, adjusted)?;
                self.verify_parent(&entry.parent)?;
                let result = body(&entry.parent, &entry.name);
                let verification = self.verify_parent(&entry.parent);
                combine_operation_and_verification(result, verification)
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn coordinate_two<T>(
        &self,
        first: &StoreEntry,
        first_is_directory: bool,
        first_intent: AccessIntent,
        second: &StoreEntry,
        second_is_directory: bool,
        second_intent: AccessIntent,
        body: impl FnOnce(&DirCap, &OsStr, &DirCap, &OsStr) -> io::Result<T>,
    ) -> io::Result<T> {
        // Both retained parent capabilities stay valid for the complete
        // synchronous accessor. A move has additional Foundation notification
        // semantics and must use `coordinate_move` instead.
        self.ensure_entry_belongs(first)?;
        self.ensure_entry_belongs(second)?;
        if first_intent == AccessIntent::Move || second_intent == AccessIntent::Move {
            return Err(invalid_input(
                "generic two-item coordination cannot express whether a move completed",
            ));
        }
        let _operation_guard = self.lock_operations()?;
        if first_intent == AccessIntent::Read && second_intent == AccessIntent::Read {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "safe synchronous two-item coordination requires at least one write intent",
            ));
        }
        let first_expected = self.presentation_root.join(first.relative_path.as_path());
        let second_expected = self.presentation_root.join(second.relative_path.as_path());
        if same_path(&first_expected, &second_expected) {
            return Err(invalid_input(
                "two-item coordination requires two distinct exact paths",
            ));
        }
        self.coordination.coordinate_two(
            &first_expected,
            first_is_directory,
            first_intent,
            &second_expected,
            second_is_directory,
            second_intent,
            |first_adjusted, second_adjusted| {
                reject_adjusted_url(&first_expected, first_adjusted)?;
                reject_adjusted_url(&second_expected, second_adjusted)?;
                self.verify_parent(&first.parent)?;
                self.verify_parent(&second.parent)?;
                let result = body(&first.parent, &first.name, &second.parent, &second.name);
                let first_verification = self.verify_parent(&first.parent);
                let second_verification = self.verify_parent(&second.parent);
                combine_operation_and_verification(
                    combine_operation_and_verification(result, first_verification),
                    second_verification,
                )
            },
        )
    }

    pub(crate) fn coordinate_move<T>(
        &self,
        source: &StoreEntry,
        source_is_directory: bool,
        destination: &StoreEntry,
        destination_is_directory: bool,
        after_move: impl FnOnce(&DirCap, &DirCap) -> io::Result<T>,
    ) -> io::Result<T> {
        // This layer owns the rename boundary. `after_move` runs only after a
        // successful exact renameat and is where callers retain parent fsync
        // and deterministic durability checkpoints. A later error or panic is
        // still classified as moved for Foundation presenter notification.
        let _operation_guard = self.lock_operations()?;
        self.ensure_entry_belongs(source)?;
        self.ensure_entry_belongs(destination)?;
        if source_is_directory != destination_is_directory {
            return Err(invalid_input(
                "move source and destination must describe the same item kind",
            ));
        }
        let source_expected = self.presentation_root.join(source.relative_path.as_path());
        let destination_expected = self
            .presentation_root
            .join(destination.relative_path.as_path());
        if same_path(&source_expected, &destination_expected) {
            return Err(invalid_input(
                "a move requires distinct source and destination paths",
            ));
        }
        self.coordination.coordinate_move(
            &source_expected,
            source_is_directory,
            &destination_expected,
            destination_is_directory,
            |source_adjusted, destination_adjusted, move_control| {
                reject_adjusted_url(&source_expected, source_adjusted)?;
                reject_adjusted_url(&destination_expected, destination_adjusted)?;
                self.verify_parent(&source.parent)?;
                self.verify_parent(&destination.parent)?;
                move_control.rename_exact(
                    &source.parent,
                    &source.name,
                    &destination.parent,
                    &destination.name,
                )?;
                let outcome = after_move(&source.parent, &destination.parent);
                let source_verification = self.verify_parent(&source.parent);
                let destination_verification = self.verify_parent(&destination.parent);
                let verification = combine_operation_and_verification(
                    source_verification,
                    destination_verification,
                );
                combine_operation_and_verification(outcome, verification)
            },
        )
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn query_root_ubiquity(&self) -> io::Result<UbiquityStatus> {
        let _operation_guard = self.lock_operations()?;
        self.verify_root()?;
        let status = MacCoordinator::query_ubiquity(&self.presentation_root, true)?;
        self.verify_root()?;
        Ok(status)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn query_entry_ubiquity(
        &self,
        entry: &StoreEntry,
        is_directory: bool,
    ) -> io::Result<UbiquityStatus> {
        let _operation_guard = self.lock_operations()?;
        self.ensure_entry_belongs(entry)?;
        self.verify_parent(&entry.parent)?;
        let path = self.presentation_root.join(entry.relative_path.as_path());
        let status = MacCoordinator::query_ubiquity(&path, is_directory)?;
        self.verify_parent(&entry.parent)?;
        Ok(status)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn start_entry_download(
        &self,
        entry: &StoreEntry,
        is_directory: bool,
    ) -> io::Result<()> {
        let _operation_guard = self.lock_operations()?;
        self.ensure_entry_belongs(entry)?;
        self.verify_parent(&entry.parent)?;
        let path = self.presentation_root.join(entry.relative_path.as_path());
        MacCoordinator::start_download(&path, is_directory)?;
        self.verify_parent(&entry.parent)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn start_root_download(&self) -> io::Result<()> {
        let _operation_guard = self.lock_operations()?;
        self.verify_root()?;
        MacCoordinator::start_download(&self.presentation_root, true)?;
        self.verify_root()
    }

    fn ensure_entry_belongs(&self, entry: &StoreEntry) -> io::Result<()> {
        if entry.parent.root_identity != self.identity {
            return Err(namespace_changed(
                "a backing-store entry belongs to a different capability root",
            ));
        }
        Ok(())
    }

    fn lock_operations(&self) -> io::Result<StoreOperationGuard<'_>> {
        // Callers must acquire the process-wide one-writer/persistence lock
        // before entering this per-StoreRoot guard. The local guard prevents
        // same-purpose coordinators on one instance from racing; the external
        // lock still excludes separately opened StoreRoot instances.
        if IN_STORE_OPERATION.with(std::cell::Cell::get) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "recursive backing-store coordination is forbidden",
            ));
        }
        let mutex_guard = self.operation_guard.lock().map_err(|_| {
            io::Error::other("backing-store operation guard was poisoned by an earlier panic")
        })?;
        IN_STORE_OPERATION.with(|active| active.set(true));
        Ok(StoreOperationGuard {
            _mutex_guard: mutex_guard,
        })
    }

    fn open_directory_cap(&self, relative_path: &Path) -> io::Result<DirCap> {
        let file = self.walk_directory(relative_path)?;
        let identity = DirectoryIdentity::from_file(&file, "backing-store parent")?;
        Ok(DirCap {
            file: Arc::new(file),
            relative_path: relative_path.to_path_buf(),
            identity,
            root_identity: self.identity,
        })
    }

    fn walk_directory(&self, relative_path: &Path) -> io::Result<File> {
        let mut current = self.root.try_clone()?;
        for component in relative_path.components() {
            let Component::Normal(name) = component else {
                return Err(invalid_input(
                    "a backing-store parent contains a non-normal component",
                ));
            };
            current = open_directory_at(&current, name)?;
        }
        Ok(current)
    }

    fn verify_root(&self) -> io::Result<()> {
        let retained = DirectoryIdentity::from_file(&self.root, "retained backing-store root")?;
        let visible_file = open_directory_absolute(&self.presentation_root)?;
        let visible = DirectoryIdentity::from_file(&visible_file, "visible backing-store root")?;
        if retained != self.identity || visible != self.identity {
            return Err(namespace_changed(
                "the backing-store presentation root changed inode identity",
            ));
        }
        Ok(())
    }

    fn verify_parent(&self, parent: &DirCap) -> io::Result<()> {
        self.verify_root()?;
        if parent.root_identity != self.identity {
            return Err(namespace_changed(
                "the backing-store parent belongs to another root",
            ));
        }
        let retained = DirectoryIdentity::from_file(&parent.file, "retained backing-store parent")?;
        let visible_file = self.walk_directory(&parent.relative_path)?;
        let visible = DirectoryIdentity::from_file(&visible_file, "visible backing-store parent")?;
        if retained != parent.identity || visible != parent.identity {
            return Err(namespace_changed(
                "a backing-store parent directory changed inode identity",
            ));
        }
        Ok(())
    }
}

impl Coordination {
    fn coordinate_one<T>(
        &self,
        path: &Path,
        is_directory: bool,
        intent: AccessIntent,
        body: impl FnOnce(&Path) -> io::Result<T>,
    ) -> io::Result<T> {
        match self {
            Self::Direct => body(path),
            #[cfg(target_os = "macos")]
            Self::Mac(coordinator) => coordinator.coordinate_one(path, is_directory, intent, body),
            #[cfg(test)]
            Self::Fake(coordinator) => coordinator.coordinate_one(path, is_directory, intent, body),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn coordinate_two<T>(
        &self,
        first_path: &Path,
        first_is_directory: bool,
        first_intent: AccessIntent,
        second_path: &Path,
        second_is_directory: bool,
        second_intent: AccessIntent,
        body: impl FnOnce(&Path, &Path) -> io::Result<T>,
    ) -> io::Result<T> {
        match self {
            Self::Direct => body(first_path, second_path),
            #[cfg(target_os = "macos")]
            Self::Mac(coordinator) => coordinator.coordinate_two(
                first_path,
                first_is_directory,
                first_intent,
                second_path,
                second_is_directory,
                second_intent,
                body,
            ),
            #[cfg(test)]
            Self::Fake(coordinator) => coordinator.coordinate_two(
                first_path,
                first_is_directory,
                first_intent,
                second_path,
                second_is_directory,
                second_intent,
                body,
            ),
        }
    }

    fn coordinate_move<T>(
        &self,
        source_path: &Path,
        source_is_directory: bool,
        destination_path: &Path,
        destination_is_directory: bool,
        body: impl FnOnce(&Path, &Path, &mut MoveControl) -> io::Result<T>,
    ) -> io::Result<T> {
        match self {
            Self::Direct => body(source_path, destination_path, &mut MoveControl::default()),
            #[cfg(target_os = "macos")]
            Self::Mac(coordinator) => coordinator.coordinate_move(
                source_path,
                source_is_directory,
                destination_path,
                destination_is_directory,
                body,
            ),
            #[cfg(test)]
            Self::Fake(coordinator) => coordinator.coordinate_move(
                source_path,
                source_is_directory,
                destination_path,
                destination_is_directory,
                body,
            ),
        }
    }
}

#[derive(Debug)]
struct OperationAndVerificationError {
    operation: io::Error,
    verification: io::Error,
}

impl std::fmt::Display for OperationAndVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "operation failed: {}; namespace verification also failed: {}",
            self.operation, self.verification
        )
    }
}

impl std::error::Error for OperationAndVerificationError {}

fn combined_io_error(operation: io::Error, verification: io::Error) -> io::Error {
    io::Error::new(
        verification.kind(),
        OperationAndVerificationError {
            operation,
            verification,
        },
    )
}

fn combine_operation_and_verification<T>(
    operation: io::Result<T>,
    verification: io::Result<()>,
) -> io::Result<T> {
    match (operation, verification) {
        (Err(operation), Err(verification)) => Err(combined_io_error(operation, verification)),
        (Ok(_), Err(error)) => Err(error),
        (result, Ok(())) => result,
    }
}

fn reject_adjusted_url(expected: &Path, adjusted: &Path) -> io::Result<()> {
    if same_path(expected, adjusted) {
        Ok(())
    } else {
        Err(namespace_changed(format!(
            "Foundation adjusted coordinated path {} to {}; refusing to abandon the pinned capability root",
            expected.display(),
            adjusted.display()
        )))
    }
}

fn same_path(first: &Path, second: &Path) -> bool {
    #[cfg(unix)]
    {
        first.as_os_str().as_bytes() == second.as_os_str().as_bytes()
    }
    #[cfg(not(unix))]
    {
        first == second
    }
}

fn validate_component(name: &OsStr, label: &str) -> io::Result<()> {
    if name.is_empty() {
        return Err(invalid_input(format!("{label} is empty")));
    }
    #[cfg(unix)]
    if name.as_bytes().contains(&b'/') || name.as_bytes().contains(&0) {
        return Err(invalid_input(format!(
            "{label} is not one NUL-free filesystem component"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn open_directory_absolute(path: &Path) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(not(unix))]
fn open_directory_absolute(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "backing-store directory capabilities require Unix open semantics",
    ))
}

#[cfg(unix)]
fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    validate_component(name, "backing-store directory")?;
    let name = CString::new(name.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(not(unix))]
fn open_directory_at(_parent: &File, _name: &OsStr) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "backing-store directory capabilities require Unix openat semantics",
    ))
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn namespace_changed(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, message.into())
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DownloadStatus {
    NotApplicable,
    Current,
    Stale,
    NotDownloaded,
    Unknown,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UbiquityStatus {
    pub(crate) is_ubiquitous: bool,
    pub(crate) download_status: DownloadStatus,
    pub(crate) download_requested: bool,
    pub(crate) is_downloading: bool,
    pub(crate) is_uploaded: Option<bool>,
    pub(crate) is_uploading: bool,
    pub(crate) has_unresolved_conflicts: Option<bool>,
    pub(crate) download_error: Option<String>,
    pub(crate) upload_error: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MacFileCoordinationError {
    pub(crate) native_kind: i32,
    pub(crate) domain: String,
    pub(crate) code: i64,
    pub(crate) message: String,
}

#[cfg(target_os = "macos")]
impl std::fmt::Display for MacFileCoordinationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "macOS file coordination failed (kind {}, {} code {}): {}",
            self.native_kind, self.domain, self.code, self.message
        )
    }
}

#[cfg(target_os = "macos")]
impl std::error::Error for MacFileCoordinationError {}

#[cfg(target_os = "macos")]
mod macos {
    use super::{
        AccessIntent, DownloadStatus, MacFileCoordinationError, MoveControl, UbiquityStatus,
        combine_operation_and_verification,
    };
    use std::ffi::{CStr, c_char, c_int, c_void};
    use std::io;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::path::{Path, PathBuf};

    const ERROR_DOMAIN_CAPACITY: usize = 128;
    const ERROR_MESSAGE_CAPACITY: usize = 1024;

    #[repr(C)]
    struct NativeError {
        kind: i32,
        code: i64,
        domain: [c_char; ERROR_DOMAIN_CAPACITY],
        message: [c_char; ERROR_MESSAGE_CAPACITY],
    }

    #[repr(C)]
    struct NativeUbiquityStatus {
        is_ubiquitous: i32,
        download_status: i32,
        download_requested: i32,
        is_downloading: i32,
        is_uploaded: i32,
        is_uploading: i32,
        has_unresolved_conflicts: i32,
        download_error: [c_char; ERROR_MESSAGE_CAPACITY],
        upload_error: [c_char; ERROR_MESSAGE_CAPACITY],
    }

    type NativeAccessor = unsafe extern "C" fn(
        context: *mut c_void,
        first_path: *const u8,
        first_path_len: usize,
        second_path: *const u8,
        second_path_len: usize,
    ) -> c_int;

    unsafe extern "C" {
        fn ztd_mac_coordinate_one(
            purpose: *const u8,
            purpose_len: usize,
            path: *const u8,
            path_len: usize,
            is_directory: i32,
            intent: i32,
            accessor: NativeAccessor,
            context: *mut c_void,
            error: *mut NativeError,
        ) -> i32;

        fn ztd_mac_coordinate_two(
            purpose: *const u8,
            purpose_len: usize,
            first_path: *const u8,
            first_path_len: usize,
            first_is_directory: i32,
            first_intent: i32,
            second_path: *const u8,
            second_path_len: usize,
            second_is_directory: i32,
            second_intent: i32,
            accessor: NativeAccessor,
            context: *mut c_void,
            error: *mut NativeError,
        ) -> i32;

        fn ztd_mac_coordinate_move(
            purpose: *const u8,
            purpose_len: usize,
            source_path: *const u8,
            source_path_len: usize,
            source_is_directory: i32,
            destination_path: *const u8,
            destination_path_len: usize,
            destination_is_directory: i32,
            accessor: NativeAccessor,
            context: *mut c_void,
            error: *mut NativeError,
        ) -> i32;

        fn ztd_mac_query_ubiquity(
            path: *const u8,
            path_len: usize,
            is_directory: i32,
            status: *mut NativeUbiquityStatus,
            error: *mut NativeError,
        ) -> i32;

        fn ztd_mac_start_download(
            path: *const u8,
            path_len: usize,
            is_directory: i32,
            error: *mut NativeError,
        ) -> i32;
    }

    #[derive(Debug)]
    pub(super) struct MacCoordinator {
        purpose: Vec<u8>,
    }

    impl MacCoordinator {
        pub(super) fn new() -> io::Result<Self> {
            let mut random = [0u8; 16];
            let result =
                unsafe { libc::getentropy(random.as_mut_ptr().cast::<c_void>(), random.len()) };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut purpose = b"net.lifub.zerotrust-drive.".to_vec();
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for byte in random {
                purpose.push(HEX[(byte >> 4) as usize]);
                purpose.push(HEX[(byte & 0x0f) as usize]);
            }
            Ok(Self { purpose })
        }

        pub(super) fn coordinate_one<T, F>(
            &self,
            path: &Path,
            is_directory: bool,
            intent: AccessIntent,
            body: F,
        ) -> io::Result<T>
        where
            F: FnOnce(&Path) -> io::Result<T>,
        {
            let path_bytes = path.as_os_str().as_bytes();
            let mut state = OneCallbackState {
                body: Some(body),
                result: None,
            };
            let mut native_error = zeroed_native_error();
            let status = unsafe {
                ztd_mac_coordinate_one(
                    self.purpose.as_ptr(),
                    self.purpose.len(),
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    i32::from(is_directory),
                    native_intent(intent),
                    one_callback::<F, T>,
                    (&mut state as *mut OneCallbackState<F, T>).cast::<c_void>(),
                    &mut native_error,
                )
            };
            finish_callback(status, state.result, &native_error)
        }

        #[allow(clippy::too_many_arguments)]
        pub(super) fn coordinate_two<T, F>(
            &self,
            first_path: &Path,
            first_is_directory: bool,
            first_intent: AccessIntent,
            second_path: &Path,
            second_is_directory: bool,
            second_intent: AccessIntent,
            body: F,
        ) -> io::Result<T>
        where
            F: FnOnce(&Path, &Path) -> io::Result<T>,
        {
            let first_bytes = first_path.as_os_str().as_bytes();
            let second_bytes = second_path.as_os_str().as_bytes();
            let mut state = TwoCallbackState {
                body: Some(body),
                result: None,
            };
            let mut native_error = zeroed_native_error();
            let status = unsafe {
                ztd_mac_coordinate_two(
                    self.purpose.as_ptr(),
                    self.purpose.len(),
                    first_bytes.as_ptr(),
                    first_bytes.len(),
                    i32::from(first_is_directory),
                    native_intent(first_intent),
                    second_bytes.as_ptr(),
                    second_bytes.len(),
                    i32::from(second_is_directory),
                    native_intent(second_intent),
                    two_callback::<F, T>,
                    (&mut state as *mut TwoCallbackState<F, T>).cast::<c_void>(),
                    &mut native_error,
                )
            };
            finish_callback(status, state.result, &native_error)
        }

        pub(super) fn coordinate_move<T, F>(
            &self,
            source_path: &Path,
            source_is_directory: bool,
            destination_path: &Path,
            destination_is_directory: bool,
            body: F,
        ) -> io::Result<T>
        where
            F: FnOnce(&Path, &Path, &mut MoveControl) -> io::Result<T>,
        {
            let source_bytes = source_path.as_os_str().as_bytes();
            let destination_bytes = destination_path.as_os_str().as_bytes();
            let mut state = MoveCallbackState {
                body: Some(body),
                result: None,
            };
            let mut native_error = zeroed_native_error();
            let status = unsafe {
                ztd_mac_coordinate_move(
                    self.purpose.as_ptr(),
                    self.purpose.len(),
                    source_bytes.as_ptr(),
                    source_bytes.len(),
                    i32::from(source_is_directory),
                    destination_bytes.as_ptr(),
                    destination_bytes.len(),
                    i32::from(destination_is_directory),
                    move_callback::<F, T>,
                    (&mut state as *mut MoveCallbackState<F, T>).cast::<c_void>(),
                    &mut native_error,
                )
            };
            finish_callback(status, state.result, &native_error)
        }

        pub(super) fn query_ubiquity(
            path: &Path,
            is_directory: bool,
        ) -> io::Result<UbiquityStatus> {
            let path = path.as_os_str().as_bytes();
            let mut status = zeroed_native_ubiquity_status();
            let mut native_error = zeroed_native_error();
            let result = unsafe {
                ztd_mac_query_ubiquity(
                    path.as_ptr(),
                    path.len(),
                    i32::from(is_directory),
                    &mut status,
                    &mut native_error,
                )
            };
            if result != 0 {
                return Err(native_io_error(&native_error));
            }
            let download_status = match status.download_status {
                0 => DownloadStatus::NotApplicable,
                1 => DownloadStatus::Current,
                2 => DownloadStatus::Stale,
                3 => DownloadStatus::NotDownloaded,
                _ => DownloadStatus::Unknown,
            };
            Ok(UbiquityStatus {
                is_ubiquitous: status.is_ubiquitous != 0,
                download_status,
                download_requested: status.download_requested != 0,
                is_downloading: status.is_downloading != 0,
                is_uploaded: match status.is_uploaded {
                    0 => Some(false),
                    1 => Some(true),
                    _ => None,
                },
                is_uploading: status.is_uploading != 0,
                has_unresolved_conflicts: match status.has_unresolved_conflicts {
                    0 => Some(false),
                    1 => Some(true),
                    _ => None,
                },
                download_error: native_optional_string(&status.download_error),
                upload_error: native_optional_string(&status.upload_error),
            })
        }

        pub(super) fn start_download(path: &Path, is_directory: bool) -> io::Result<()> {
            let path = path.as_os_str().as_bytes();
            let mut native_error = zeroed_native_error();
            let result = unsafe {
                ztd_mac_start_download(
                    path.as_ptr(),
                    path.len(),
                    i32::from(is_directory),
                    &mut native_error,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(native_io_error(&native_error))
            }
        }
    }

    struct OneCallbackState<F, T> {
        body: Option<F>,
        result: Option<io::Result<T>>,
    }

    struct TwoCallbackState<F, T> {
        body: Option<F>,
        result: Option<io::Result<T>>,
    }

    struct MoveCallbackState<F, T> {
        body: Option<F>,
        result: Option<io::Result<T>>,
    }

    // Safety: Foundation invokes this callback synchronously before the FFI
    // function returns. `context` points to a live stack value for that exact
    // call. No Rust reference is retained by Objective-C, and every panic is
    // caught before it can unwind across the C ABI.
    unsafe extern "C" fn one_callback<F, T>(
        context: *mut c_void,
        first_path: *const u8,
        first_path_len: usize,
        _second_path: *const u8,
        _second_path_len: usize,
    ) -> c_int
    where
        F: FnOnce(&Path) -> io::Result<T>,
    {
        let state = unsafe { &mut *context.cast::<OneCallbackState<F, T>>() };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let path = unsafe { copied_path(first_path, first_path_len) }?;
            let body = state
                .body
                .take()
                .ok_or_else(|| io::Error::other("coordinated accessor ran more than once"))?;
            body(&path)
        }));
        match outcome {
            Ok(result) => {
                let success = result.is_ok();
                state.result = Some(result);
                if success { 0 } else { 1 }
            }
            Err(_) => {
                state.result = Some(Err(io::Error::other(
                    "panic inside macOS coordinated accessor",
                )));
                1
            }
        }
    }

    // Safety: the same synchronous-lifetime and unwind-containment invariants
    // as `one_callback` apply to both adjusted path byte slices.
    unsafe extern "C" fn two_callback<F, T>(
        context: *mut c_void,
        first_path: *const u8,
        first_path_len: usize,
        second_path: *const u8,
        second_path_len: usize,
    ) -> c_int
    where
        F: FnOnce(&Path, &Path) -> io::Result<T>,
    {
        let state = unsafe { &mut *context.cast::<TwoCallbackState<F, T>>() };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let first = unsafe { copied_path(first_path, first_path_len) }?;
            let second = unsafe { copied_path(second_path, second_path_len) }?;
            let body = state
                .body
                .take()
                .ok_or_else(|| io::Error::other("coordinated accessor ran more than once"))?;
            body(&first, &second)
        }));
        match outcome {
            Ok(result) => {
                let success = result.is_ok();
                state.result = Some(result);
                if success { 0 } else { 1 }
            }
            Err(_) => {
                state.result = Some(Err(io::Error::other(
                    "panic inside macOS coordinated accessor",
                )));
                1
            }
        }
    }

    // Status 2 tells the native shim that the namespace move completed even
    // though a later durability operation failed. The backend-controlled
    // rename boundary removes any need to guess after a panic.
    unsafe extern "C" fn move_callback<F, T>(
        context: *mut c_void,
        source_path: *const u8,
        source_path_len: usize,
        destination_path: *const u8,
        destination_path_len: usize,
    ) -> c_int
    where
        F: FnOnce(&Path, &Path, &mut MoveControl) -> io::Result<T>,
    {
        let state = unsafe { &mut *context.cast::<MoveCallbackState<F, T>>() };
        let mut move_control = MoveControl::default();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let source = unsafe { copied_path(source_path, source_path_len) }?;
            let destination = unsafe { copied_path(destination_path, destination_path_len) }?;
            let body = state
                .body
                .take()
                .ok_or_else(|| io::Error::other("coordinated move accessor ran more than once"))?;
            body(&source, &destination, &mut move_control)
        }));
        match outcome {
            Ok(Ok(value)) => {
                state.result = Some(Ok(value));
                if move_control.moved { 0 } else { 1 }
            }
            Ok(Err(error)) => {
                state.result = Some(Err(error));
                if move_control.moved { 2 } else { 1 }
            }
            Err(_) => {
                state.result = Some(Err(io::Error::other(
                    "panic inside macOS coordinated move accessor",
                )));
                if move_control.moved { 2 } else { 1 }
            }
        }
    }

    unsafe fn copied_path(pointer: *const u8, length: usize) -> io::Result<PathBuf> {
        if pointer.is_null() || length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Foundation returned an empty adjusted filesystem path",
            ));
        }
        let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
        Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
    }

    fn finish_callback<T>(
        native_status: i32,
        result: Option<io::Result<T>>,
        native_error: &NativeError,
    ) -> io::Result<T> {
        const ACCESSOR_ERROR: i32 = 2;
        match (native_status, result) {
            (0, Some(Ok(value))) => Ok(value),
            (_, Some(Err(error))) if native_error.kind == ACCESSOR_ERROR => Err(error),
            (_, Some(Err(error))) if native_status == 0 => Err(error),
            (_, Some(Err(error))) => {
                combine_operation_and_verification(Err(error), Err(native_io_error(native_error)))
            }
            _ => Err(native_io_error(native_error)),
        }
    }

    fn native_intent(intent: AccessIntent) -> i32 {
        match intent {
            AccessIntent::Read => 0,
            AccessIntent::Write => 1,
            AccessIntent::Delete => 2,
            AccessIntent::Move => 3,
            AccessIntent::Replace => 4,
        }
    }

    fn zeroed_native_error() -> NativeError {
        unsafe { std::mem::zeroed() }
    }

    fn zeroed_native_ubiquity_status() -> NativeUbiquityStatus {
        unsafe { std::mem::zeroed() }
    }

    fn native_io_error(error: &NativeError) -> io::Error {
        let domain = native_string(&error.domain);
        let message = native_string(&error.message);
        let io_kind = native_io_error_kind(error.kind, &domain, error.code);
        io::Error::new(
            io_kind,
            MacFileCoordinationError {
                native_kind: error.kind,
                domain,
                code: error.code,
                message,
            },
        )
    }

    pub(super) fn native_io_error_kind(native_kind: i32, domain: &str, code: i64) -> io::ErrorKind {
        const INVALID_INPUT_ERROR: i32 = 4;
        // Preserve real POSIX failures even when path preparation produced
        // them. In particular, malloc(3) failure must remain OutOfMemory,
        // rather than being flattened into InvalidInput.
        if domain == "NSPOSIXErrorDomain" {
            return i32::try_from(code)
                .map(|code| io::Error::from_raw_os_error(code).kind())
                .unwrap_or(io::ErrorKind::Other);
        }
        if native_kind == INVALID_INPUT_ERROR {
            return io::ErrorKind::InvalidInput;
        }
        if domain == "NSCocoaErrorDomain" {
            return match code {
                257 | 513 => io::ErrorKind::PermissionDenied,
                260 => io::ErrorKind::NotFound,
                516 => io::ErrorKind::AlreadyExists,
                3072 => io::ErrorKind::Interrupted,
                _ => io::ErrorKind::Other,
            };
        }
        if domain == "NSFileProviderErrorDomain" {
            return match code {
                -1000 => io::ErrorKind::PermissionDenied,
                -1001 => io::ErrorKind::AlreadyExists,
                -1003 => io::ErrorKind::StorageFull,
                -1004 => io::ErrorKind::NotConnected,
                -1005 => io::ErrorKind::NotFound,
                _ => io::ErrorKind::Other,
            };
        }
        io::ErrorKind::Other
    }

    fn native_optional_string(value: &[c_char]) -> Option<String> {
        let value = native_string(value);
        (!value.is_empty()).then_some(value)
    }

    fn native_string(value: &[c_char]) -> String {
        if value.is_empty() || value[0] == 0 {
            return String::new();
        }
        let value = unsafe { CStr::from_ptr(value.as_ptr()) };
        value.to_string_lossy().into_owned()
    }
}

#[cfg(target_os = "macos")]
use macos::MacCoordinator;

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CoordinationCall {
    first_path: PathBuf,
    first_is_directory: bool,
    first_intent: AccessIntent,
    second: Option<(PathBuf, bool, AccessIntent)>,
}

#[cfg(test)]
#[derive(Default, Debug)]
struct FakeState {
    calls: Vec<CoordinationCall>,
    next_adjustment: Option<(PathBuf, Option<PathBuf>)>,
}

#[cfg(test)]
#[derive(Default, Debug)]
struct FakeCoordinator {
    state: std::sync::Mutex<FakeState>,
}

#[cfg(test)]
impl FakeCoordinator {
    fn adjust_next(&self, first: PathBuf, second: Option<PathBuf>) {
        self.state.lock().unwrap().next_adjustment = Some((first, second));
    }

    fn calls(&self) -> Vec<CoordinationCall> {
        self.state.lock().unwrap().calls.clone()
    }

    fn coordinate_one<T>(
        &self,
        path: &Path,
        is_directory: bool,
        intent: AccessIntent,
        body: impl FnOnce(&Path) -> io::Result<T>,
    ) -> io::Result<T> {
        let adjusted = {
            let mut state = self.state.lock().unwrap();
            state.calls.push(CoordinationCall {
                first_path: path.to_path_buf(),
                first_is_directory: is_directory,
                first_intent: intent,
                second: None,
            });
            state
                .next_adjustment
                .take()
                .map_or_else(|| path.to_path_buf(), |value| value.0)
        };
        body(&adjusted)
    }

    #[allow(clippy::too_many_arguments)]
    fn coordinate_two<T>(
        &self,
        first_path: &Path,
        first_is_directory: bool,
        first_intent: AccessIntent,
        second_path: &Path,
        second_is_directory: bool,
        second_intent: AccessIntent,
        body: impl FnOnce(&Path, &Path) -> io::Result<T>,
    ) -> io::Result<T> {
        let (first_adjusted, second_adjusted) = {
            let mut state = self.state.lock().unwrap();
            state.calls.push(CoordinationCall {
                first_path: first_path.to_path_buf(),
                first_is_directory,
                first_intent,
                second: Some((
                    second_path.to_path_buf(),
                    second_is_directory,
                    second_intent,
                )),
            });
            state.next_adjustment.take().map_or_else(
                || (first_path.to_path_buf(), second_path.to_path_buf()),
                |value| {
                    (
                        value.0,
                        value.1.unwrap_or_else(|| second_path.to_path_buf()),
                    )
                },
            )
        };
        body(&first_adjusted, &second_adjusted)
    }

    fn coordinate_move<T>(
        &self,
        source_path: &Path,
        source_is_directory: bool,
        destination_path: &Path,
        destination_is_directory: bool,
        body: impl FnOnce(&Path, &Path, &mut MoveControl) -> io::Result<T>,
    ) -> io::Result<T> {
        let (source_adjusted, destination_adjusted) = {
            let mut state = self.state.lock().unwrap();
            state.calls.push(CoordinationCall {
                first_path: source_path.to_path_buf(),
                first_is_directory: source_is_directory,
                first_intent: AccessIntent::Move,
                second: Some((
                    destination_path.to_path_buf(),
                    destination_is_directory,
                    AccessIntent::Replace,
                )),
            });
            state.next_adjustment.take().map_or_else(
                || (source_path.to_path_buf(), destination_path.to_path_buf()),
                |value| {
                    (
                        value.0,
                        value.1.unwrap_or_else(|| destination_path.to_path_buf()),
                    )
                },
            )
        };
        body(
            &source_adjusted,
            &destination_adjusted,
            &mut MoveControl::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_directory(label: &str) -> PathBuf {
        let sequence = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "zerotrust-drive-storage-{label}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn fake_store(path: &Path) -> (StoreRoot, Arc<FakeCoordinator>) {
        let fake = Arc::new(FakeCoordinator::default());
        let store = StoreRoot::open_with(path, Coordination::Fake(Arc::clone(&fake))).unwrap();
        (store, fake)
    }

    #[test]
    fn relative_store_path_rejects_ambiguous_components() {
        assert!(RelativeStorePath::new(Path::new("objects/item.z2")).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let raw_name = OsString::from_vec(vec![b'r', b'a', b'w', 0xff]);
            assert!(RelativeStorePath::new(Path::new(&raw_name)).is_ok());
        }
        for invalid in ["", ".", "./item", "../item", "objects/../item", "/item"] {
            assert!(
                RelativeStorePath::new(Path::new(invalid)).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn direct_backend_keeps_operations_under_the_pinned_parent() {
        let directory = test_directory("direct");
        std::fs::create_dir(directory.join("objects")).unwrap();
        std::fs::write(directory.join("objects/item.z2"), b"authenticated").unwrap();
        let store = StoreRoot::open_direct(&directory).unwrap();
        let entry = store
            .entry(RelativeStorePath::new(Path::new("objects/item.z2")).unwrap())
            .unwrap();

        let bytes = store
            .coordinate_one(&entry, false, AccessIntent::Read, |parent, name| {
                #[cfg(unix)]
                {
                    let name = CString::new(name.as_bytes())?;
                    let fd = unsafe {
                        libc::openat(
                            parent.as_file().as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    let mut file = unsafe { File::from_raw_fd(fd) };
                    let mut bytes = Vec::new();
                    std::io::Read::read_to_end(&mut file, &mut bytes)?;
                    Ok(bytes)
                }
                #[cfg(not(unix))]
                {
                    let _ = (parent, name);
                    Err(io::Error::new(io::ErrorKind::Unsupported, "Unix only"))
                }
            })
            .unwrap();
        assert_eq!(bytes, b"authenticated");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn fake_backend_records_exact_one_and_two_item_intents() {
        let directory = test_directory("fake-record");
        std::fs::write(directory.join("first"), b"first").unwrap();
        std::fs::write(directory.join("second"), b"second").unwrap();
        let (store, fake) = fake_store(&directory);
        let first = store
            .entry(RelativeStorePath::new(Path::new("first")).unwrap())
            .unwrap();
        let second = store
            .entry(RelativeStorePath::new(Path::new("second")).unwrap())
            .unwrap();

        store
            .coordinate_one(&first, false, AccessIntent::Read, |_, _| Ok(()))
            .unwrap();
        store
            .coordinate_move(&first, false, &second, false, |_, _| Ok(()))
            .unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].first_path, store.presentation_root().join("first"));
        assert_eq!(calls[0].first_intent, AccessIntent::Read);
        assert_eq!(
            calls[1].second,
            Some((
                store.presentation_root().join("second"),
                false,
                AccessIntent::Replace
            ))
        );
        assert_eq!(std::fs::read(directory.join("second")).unwrap(), b"first");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn generic_coordination_rejects_move_without_running_the_body() {
        let directory = test_directory("generic-move");
        std::fs::write(directory.join("source"), b"source").unwrap();
        std::fs::write(directory.join("destination"), b"destination").unwrap();
        let (store, fake) = fake_store(&directory);
        let source = store
            .entry(RelativeStorePath::new(Path::new("source")).unwrap())
            .unwrap();
        let destination = store
            .entry(RelativeStorePath::new(Path::new("destination")).unwrap())
            .unwrap();
        let body_ran = std::cell::Cell::new(false);

        let one_error = store
            .coordinate_one(&source, false, AccessIntent::Move, |_, _| {
                body_ran.set(true);
                Ok(())
            })
            .unwrap_err();
        assert_eq!(one_error.kind(), io::ErrorKind::InvalidInput);
        let two_error = store
            .coordinate_two(
                &source,
                false,
                AccessIntent::Move,
                &destination,
                false,
                AccessIntent::Replace,
                |_, _, _, _| {
                    body_ran.set(true);
                    Ok(())
                },
            )
            .unwrap_err();
        assert_eq!(two_error.kind(), io::ErrorKind::InvalidInput);
        assert!(!body_ran.get());
        assert!(fake.calls().is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn exact_move_reports_post_rename_failure_without_losing_the_move() {
        let directory = test_directory("move-post-failure");
        std::fs::write(directory.join("source"), b"source").unwrap();
        let (store, fake) = fake_store(&directory);
        let source = store
            .entry(RelativeStorePath::new(Path::new("source")).unwrap())
            .unwrap();
        let destination = store
            .entry(RelativeStorePath::new(Path::new("destination")).unwrap())
            .unwrap();

        let error = store
            .coordinate_move(&source, false, &destination, false, |_, _| {
                Err::<(), _>(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "post-rename fsync failed",
                ))
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        assert!(!directory.join("source").exists());
        assert_eq!(
            std::fs::read(directory.join("destination")).unwrap(),
            b"source"
        );
        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].first_intent, AccessIntent::Move);
        assert_eq!(
            calls[0].second.as_ref().map(|value| value.2),
            Some(AccessIntent::Replace)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recursive_store_operation_fails_instead_of_deadlocking() {
        let directory = test_directory("recursive-operation");
        let store = StoreRoot::open_direct(&directory).unwrap();

        let error = store
            .coordinate_root(AccessIntent::Read, |_| {
                store.coordinate_root(AccessIntent::Read, |_| Ok(()))
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(error.to_string().contains("recursive"));

        // The thread marker is scoped to the failed outer accessor and must
        // not poison later independent operations.
        store
            .coordinate_root(AccessIntent::Read, |_| Ok(()))
            .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn adjusted_url_is_rejected_before_the_posix_body_runs() {
        let directory = test_directory("adjusted");
        std::fs::write(directory.join("item"), b"item").unwrap();
        let (store, fake) = fake_store(&directory);
        let entry = store
            .entry(RelativeStorePath::new(Path::new("item")).unwrap())
            .unwrap();
        fake.adjust_next(store.presentation_root().join("moved-item"), None);
        let body_ran = std::cell::Cell::new(false);

        let error = store
            .coordinate_one(&entry, false, AccessIntent::Read, |_, _| {
                body_ran.set(true);
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(!body_ran.get());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn adjusted_second_url_is_rejected_before_the_posix_body_runs() {
        let directory = test_directory("adjusted-second");
        std::fs::write(directory.join("first"), b"first").unwrap();
        std::fs::write(directory.join("second"), b"second").unwrap();
        let (store, fake) = fake_store(&directory);
        let first = store
            .entry(RelativeStorePath::new(Path::new("first")).unwrap())
            .unwrap();
        let second = store
            .entry(RelativeStorePath::new(Path::new("second")).unwrap())
            .unwrap();
        fake.adjust_next(
            store.presentation_root().join("first"),
            Some(store.presentation_root().join("moved-second")),
        );
        let body_ran = std::cell::Cell::new(false);

        let error = store
            .coordinate_two(
                &first,
                false,
                AccessIntent::Read,
                &second,
                false,
                AccessIntent::Write,
                |_, _, _, _| {
                    body_ran.set(true);
                    Ok(())
                },
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(!body_ran.get());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn replaced_parent_directory_is_rejected() {
        let directory = test_directory("parent-replacement");
        std::fs::create_dir(directory.join("objects")).unwrap();
        std::fs::write(directory.join("objects/item"), b"old").unwrap();
        let store = StoreRoot::open_direct(&directory).unwrap();
        let entry = store
            .entry(RelativeStorePath::new(Path::new("objects/item")).unwrap())
            .unwrap();
        std::fs::rename(directory.join("objects"), directory.join("displaced")).unwrap();
        std::fs::create_dir(directory.join("objects")).unwrap();
        std::fs::write(directory.join("objects/item"), b"new").unwrap();

        let error = store
            .coordinate_one(&entry, false, AccessIntent::Read, |_, _| Ok(()))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn post_body_parent_replacement_preserves_operation_and_namespace_errors() {
        let directory = test_directory("post-body-parent-replacement");
        std::fs::create_dir(directory.join("objects")).unwrap();
        std::fs::write(directory.join("objects/item"), b"old").unwrap();
        let store = StoreRoot::open_direct(&directory).unwrap();
        let entry = store
            .entry(RelativeStorePath::new(Path::new("objects/item")).unwrap())
            .unwrap();

        let error = store
            .coordinate_one(&entry, false, AccessIntent::Write, |_, _| {
                std::fs::rename(directory.join("objects"), directory.join("displaced"))?;
                std::fs::create_dir(directory.join("objects"))?;
                Err::<(), _>(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "operation sentinel",
                ))
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        let message = error.to_string();
        assert!(message.contains("operation sentinel"), "{message}");
        assert!(
            message.contains("parent directory changed inode identity"),
            "{message}"
        );
        assert!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<OperationAndVerificationError>())
                .is_some()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_parent_is_never_opened_as_a_directory_capability() {
        use std::os::unix::fs::symlink;

        let directory = test_directory("symlink-parent");
        std::fs::create_dir(directory.join("real-objects")).unwrap();
        symlink("real-objects", directory.join("objects")).unwrap();
        let store = StoreRoot::open_direct(&directory).unwrap();
        let error = store
            .entry(RelativeStorePath::new(Path::new("objects/item")).unwrap())
            .unwrap_err();
        assert!(matches!(
            error.raw_os_error(),
            Some(libc::ELOOP | libc::ENOTDIR)
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn direct_backend_round_trips_non_utf8_entry_names() {
        use std::os::unix::ffi::OsStringExt;

        let directory = test_directory("non-utf8-direct");
        let name = OsString::from_vec(vec![b'r', b'a', b'w', 0xff]);
        std::fs::write(directory.join(&name), b"raw-name").unwrap();
        let store = StoreRoot::open_direct(&directory).unwrap();
        let entry = store
            .entry(RelativeStorePath::new(Path::new(&name)).unwrap())
            .unwrap();
        let bytes = store
            .coordinate_one(&entry, false, AccessIntent::Read, |parent, name| {
                let name = CString::new(name.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        parent.as_file().as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut file = unsafe { File::from_raw_fd(fd) };
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(&mut file, &mut bytes)?;
                Ok(bytes)
            })
            .unwrap();
        assert_eq!(bytes, b"raw-name");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_cloud_errors_keep_machine_readable_io_kinds() {
        assert_eq!(
            macos::native_io_error_kind(4, "NSPOSIXErrorDomain", libc::ENOMEM.into()),
            io::ErrorKind::OutOfMemory
        );
        assert_eq!(
            macos::native_io_error_kind(1, "NSFileProviderErrorDomain", -1003),
            io::ErrorKind::StorageFull
        );
        assert_eq!(
            macos::native_io_error_kind(1, "NSFileProviderErrorDomain", -1004),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            macos::native_io_error_kind(1, "NSFileProviderErrorDomain", -1005),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            macos::native_io_error_kind(1, "NSCocoaErrorDomain", 3072),
            io::ErrorKind::Interrupted
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_native_shim_coordinates_local_exact_paths() {
        let directory = test_directory("macos-shim");
        std::fs::write(directory.join("first"), b"first").unwrap();
        std::fs::write(directory.join("second"), b"second").unwrap();
        std::fs::write(directory.join("delete-me"), b"delete").unwrap();
        std::fs::write(directory.join("replace-me"), b"old").unwrap();
        std::fs::write(directory.join("move-source"), b"move").unwrap();
        std::fs::write(directory.join("move-destination"), b"old destination").unwrap();
        std::fs::write(directory.join("move-error-source"), b"move then error").unwrap();
        std::fs::write(directory.join("move-panic-source"), b"move then panic").unwrap();
        std::fs::write(directory.join("unicode-文件"), b"unicode").unwrap();
        let store = StoreRoot::open_macos(&directory).unwrap();
        let first = store
            .entry(RelativeStorePath::new(Path::new("first")).unwrap())
            .unwrap();
        let second = store
            .entry(RelativeStorePath::new(Path::new("second")).unwrap())
            .unwrap();

        store
            .coordinate_root(AccessIntent::Read, |root| {
                assert!(root.metadata()?.is_dir());
                Ok(())
            })
            .unwrap();

        store
            .coordinate_one(&first, false, AccessIntent::Read, |_, _| Ok(()))
            .unwrap();
        store
            .coordinate_two(
                &first,
                false,
                AccessIntent::Read,
                &second,
                false,
                AccessIntent::Write,
                |_, _, _, _| Ok(()),
            )
            .unwrap();
        let two_read_error = store
            .coordinate_two(
                &first,
                false,
                AccessIntent::Read,
                &second,
                false,
                AccessIntent::Read,
                |_, _, _, _| Ok(()),
            )
            .unwrap_err();
        assert_eq!(two_read_error.kind(), io::ErrorKind::Unsupported);
        store
            .coordinate_two(
                &first,
                false,
                AccessIntent::Write,
                &second,
                false,
                AccessIntent::Read,
                |_, _, _, _| Ok(()),
            )
            .unwrap();
        store
            .coordinate_two(
                &first,
                false,
                AccessIntent::Write,
                &second,
                false,
                AccessIntent::Write,
                |_, _, _, _| Ok(()),
            )
            .unwrap();
        let accessor_error = store
            .coordinate_one(&first, false, AccessIntent::Read, |_, _| {
                Err::<(), _>(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "accessor sentinel",
                ))
            })
            .unwrap_err();
        assert_eq!(accessor_error.kind(), io::ErrorKind::WouldBlock);
        assert!(accessor_error.to_string().contains("accessor sentinel"));
        let panic_error = store
            .coordinate_one(
                &first,
                false,
                AccessIntent::Read,
                |_, _| -> io::Result<()> { panic!("caught accessor panic") },
            )
            .unwrap_err();
        assert!(
            panic_error
                .to_string()
                .contains("panic inside macOS coordinated accessor")
        );

        let unicode = store
            .entry(RelativeStorePath::new(Path::new("unicode-文件")).unwrap())
            .unwrap();
        store
            .coordinate_one(&unicode, false, AccessIntent::Read, |_, _| Ok(()))
            .unwrap();

        let delete = store
            .entry(RelativeStorePath::new(Path::new("delete-me")).unwrap())
            .unwrap();
        store
            .coordinate_one(&delete, false, AccessIntent::Delete, |parent, name| {
                let name = CString::new(name.as_bytes())?;
                if unsafe { libc::unlinkat(parent.as_file().as_raw_fd(), name.as_ptr(), 0) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            })
            .unwrap();
        assert!(!directory.join("delete-me").exists());

        let replace = store
            .entry(RelativeStorePath::new(Path::new("replace-me")).unwrap())
            .unwrap();
        store
            .coordinate_one(&replace, false, AccessIntent::Replace, |parent, name| {
                let name = CString::new(name.as_bytes())?;
                if unsafe { libc::unlinkat(parent.as_file().as_raw_fd(), name.as_ptr(), 0) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                let fd = unsafe {
                    libc::openat(
                        parent.as_file().as_raw_fd(),
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
                    return Err(io::Error::last_os_error());
                }
                let mut file = unsafe { File::from_raw_fd(fd) };
                std::io::Write::write_all(&mut file, b"new")?;
                Ok(())
            })
            .unwrap();
        assert_eq!(std::fs::read(directory.join("replace-me")).unwrap(), b"new");

        let move_source = store
            .entry(RelativeStorePath::new(Path::new("move-source")).unwrap())
            .unwrap();
        let move_destination = store
            .entry(RelativeStorePath::new(Path::new("move-destination")).unwrap())
            .unwrap();
        store
            .coordinate_move(&move_source, false, &move_destination, false, |_, _| Ok(()))
            .unwrap();
        assert!(!directory.join("move-source").exists());
        assert_eq!(
            std::fs::read(directory.join("move-destination")).unwrap(),
            b"move"
        );

        let move_error_source = store
            .entry(RelativeStorePath::new(Path::new("move-error-source")).unwrap())
            .unwrap();
        let move_error_destination = store
            .entry(RelativeStorePath::new(Path::new("move-error-destination")).unwrap())
            .unwrap();
        let move_error = store
            .coordinate_move(
                &move_error_source,
                false,
                &move_error_destination,
                false,
                |_, _| {
                    Err::<(), _>(io::Error::new(
                        io::ErrorKind::StorageFull,
                        "post-move durability sentinel",
                    ))
                },
            )
            .unwrap_err();
        assert_eq!(move_error.kind(), io::ErrorKind::StorageFull);
        assert!(!directory.join("move-error-source").exists());
        assert_eq!(
            std::fs::read(directory.join("move-error-destination")).unwrap(),
            b"move then error"
        );
        let move_panic_source = store
            .entry(RelativeStorePath::new(Path::new("move-panic-source")).unwrap())
            .unwrap();
        let move_panic_destination = store
            .entry(RelativeStorePath::new(Path::new("move-panic-destination")).unwrap())
            .unwrap();
        let move_panic_error = store
            .coordinate_move(
                &move_panic_source,
                false,
                &move_panic_destination,
                false,
                |_, _| -> io::Result<()> { panic!("post-move panic") },
            )
            .unwrap_err();
        assert!(
            move_panic_error
                .to_string()
                .contains("panic inside macOS coordinated move accessor")
        );
        assert!(!directory.join("move-panic-source").exists());
        assert_eq!(
            std::fs::read(directory.join("move-panic-destination")).unwrap(),
            b"move then panic"
        );
        let status = store.query_entry_ubiquity(&first, false).unwrap();
        assert!(!status.is_ubiquitous);
        assert_eq!(status.download_status, DownloadStatus::NotApplicable);
        assert_eq!(status.has_unresolved_conflicts, None);
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// Query-only, point-in-time materialization audit for a disposable or
    /// explicitly selected iCloud directory. Passing this test does not prove
    /// Finder's persistent "Keep Downloaded" flag is set; Foundation exposes
    /// current ubiquity state, not that Finder policy bit.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires ZDRIVE_RUN_ICLOUD_TESTS=1 and an explicit real iCloud test root"]
    fn real_icloud_tree_is_currently_materialized_without_conflicts() {
        assert_eq!(
            std::env::var("ZDRIVE_RUN_ICLOUD_TESTS").as_deref(),
            Ok("1"),
            "set ZDRIVE_RUN_ICLOUD_TESTS=1 for the explicit real-iCloud audit"
        );
        let configured = PathBuf::from(
            std::env::var_os("ZDRIVE_ICLOUD_TEST_ROOT")
                .expect("set ZDRIVE_ICLOUD_TEST_ROOT to the exact audit directory"),
        );
        assert!(
            configured.is_absolute(),
            "iCloud test root must be absolute"
        );
        let canonical = std::fs::canonicalize(&configured).expect("canonicalize iCloud test root");
        assert_eq!(
            configured, canonical,
            "iCloud test root must already be canonical and must not be a symlink"
        );
        let root_metadata = std::fs::symlink_metadata(&canonical).unwrap();
        assert!(root_metadata.is_dir());
        assert!(!root_metadata.file_type().is_symlink());

        let store = StoreRoot::open_macos(&canonical).unwrap();
        assert_current_ubiquity(&canonical, store.query_root_ubiquity().unwrap());

        const MAX_ENTRIES: usize = 250_000;
        const MAX_DEPTH: usize = 128;
        let mut stack = vec![(canonical.clone(), 0usize)];
        let mut visited = 0usize;
        while let Some((directory, depth)) = stack.pop() {
            assert!(
                depth <= MAX_DEPTH,
                "iCloud traversal exceeded {MAX_DEPTH} levels"
            );
            let children = std::fs::read_dir(&directory)
                .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()));
            for child in children {
                visited = visited.checked_add(1).expect("iCloud entry count overflow");
                assert!(
                    visited <= MAX_ENTRIES,
                    "iCloud traversal exceeded {MAX_ENTRIES} entries"
                );
                let child = child
                    .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
                    .path();
                let metadata = std::fs::symlink_metadata(&child).unwrap_or_else(|error| {
                    panic!("inspect exact iCloud item {}: {error}", child.display())
                });
                assert!(
                    !metadata.file_type().is_symlink(),
                    "refuse symlink in iCloud audit: {}",
                    child.display()
                );
                let is_directory = metadata.is_dir();
                assert!(
                    is_directory || metadata.is_file(),
                    "refuse special iCloud item: {}",
                    child.display()
                );
                let relative = child.strip_prefix(&canonical).unwrap();
                let entry = store
                    .entry(RelativeStorePath::new(relative).unwrap())
                    .unwrap();
                assert_current_ubiquity(
                    &child,
                    store.query_entry_ubiquity(&entry, is_directory).unwrap(),
                );
                if is_directory {
                    stack.push((child, depth + 1));
                }
            }
        }
        eprintln!(
            "verified current materialization for {visited} exact descendants; this does not prove Finder Keep Downloaded persistence"
        );
    }

    #[cfg(target_os = "macos")]
    fn assert_current_ubiquity(path: &Path, status: UbiquityStatus) {
        assert!(
            status.is_ubiquitous,
            "{} is not reported as ubiquitous",
            path.display()
        );
        assert_eq!(
            status.download_status,
            DownloadStatus::Current,
            "{} is not currently materialized: {status:?}",
            path.display()
        );
        assert!(
            status.download_error.is_none(),
            "{} has a download error: {status:?}",
            path.display()
        );
        assert!(
            status.upload_error.is_none(),
            "{} has an upload error: {status:?}",
            path.display()
        );
        assert_eq!(
            status.has_unresolved_conflicts,
            Some(false),
            "{} has unresolved or unknown conflict evidence: {status:?}",
            path.display()
        );
    }
}
