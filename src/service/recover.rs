// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Stale-mount recovery before an instance mounts: a zerotrust-drive FUSE
//! mount whose server died (a crash, SIGKILL, an out-of-memory kill) stays
//! in the mount table and fails every access with ENOTCONN (Linux) or ENXIO
//! or EIO (macFUSE). Mounting over it fails, so the service unmounts it
//! first. A mount that still answers belongs to a running instance and is
//! left alone.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{Platform, Runner, display_command, failure, os_args, run_checked};

/// The `fsname` the drive mounts with; the mount table's source field.
pub(crate) const FS_NAME: &str = "zerotrust-drive";
/// A stat of a mount whose server hangs blocks; give up after this long.
const STAT_TIMEOUT: Duration = Duration::from_secs(10);

/// One mount table entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MountEntry {
    pub(crate) mount_point: PathBuf,
    pub(crate) fstype: String,
    pub(crate) source: String,
}

/// The outcome of a `stat` of the mount directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reach {
    Ok,
    Errno(i32),
    TimedOut,
}

/// What occupies the mount directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MountCheck {
    /// Nothing is mounted there.
    Free,
    /// A zerotrust-drive mount that answers: an instance is running.
    Live,
    /// A zerotrust-drive mount that does not answer within the timeout.
    Unresponsive,
    /// A zerotrust-drive mount whose server is gone.
    Stale,
    /// Another file system is mounted there.
    Foreign { fstype: String, source: String },
}

/// Decodes the octal escapes (`\040` for a space) of mountinfo fields.
fn unescape_mountinfo(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let octal = bytes.get(index + 1..index + 4).filter(|digits| {
            bytes[index] == b'\\' && digits.iter().all(|digit| (b'0'..=b'7').contains(digit))
        });
        match octal {
            Some(digits) => {
                let value = digits
                    .iter()
                    .fold(0u32, |value, digit| value * 8 + u32::from(digit - b'0'));
                decoded.push(u8::try_from(value).unwrap_or(b'?'));
                index += 4;
            }
            None => {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// Parses `/proc/self/mountinfo`: the mount point is the fifth field, and
/// file system type and source follow the ` - ` separator.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            let mount_point = left.split(' ').nth(4)?;
            let mut right = right.split(' ');
            let fstype = right.next()?;
            let source = right.next()?;
            Some(MountEntry {
                mount_point: PathBuf::from(unescape_mountinfo(mount_point)),
                fstype: unescape_mountinfo(fstype),
                source: unescape_mountinfo(source),
            })
        })
        .collect()
}

/// The entry that is visible at `mount_point`: the last one mounted there.
pub(crate) fn find_entry<'a>(
    entries: &'a [MountEntry],
    mount_point: &Path,
) -> Option<&'a MountEntry> {
    entries
        .iter()
        .rev()
        .find(|entry| entry.mount_point == mount_point)
}

/// FSKit replaces the `fsname` with a per-volume `macfuse://<UUID>` source, so
/// on macOS any FSKit macFUSE volume at the drive's own mount directory counts
/// as the drive's.
pub(crate) const FSKIT_SOURCE_PREFIX: &str = "macfuse://";

fn is_ours(entry: &MountEntry, platform: Platform) -> bool {
    match platform {
        Platform::Linux => entry.source == FS_NAME && entry.fstype.starts_with("fuse"),
        Platform::MacOs => {
            (entry.source == FS_NAME
                && (entry.fstype.starts_with("macfuse") || entry.fstype.starts_with("osxfuse")))
                || (entry.source.starts_with(FSKIT_SOURCE_PREFIX)
                    && entry.fstype.starts_with("macfuse"))
        }
    }
}

fn is_dead(errno: i32, platform: Platform) -> bool {
    match platform {
        Platform::Linux => errno == libc::ENOTCONN,
        Platform::MacOs => [libc::ENXIO, libc::EIO, libc::ENOTCONN].contains(&errno),
    }
}

pub(crate) fn classify(entry: Option<&MountEntry>, reach: Reach, platform: Platform) -> MountCheck {
    match (entry, reach) {
        (Some(entry), _) if !is_ours(entry, platform) => MountCheck::Foreign {
            fstype: entry.fstype.clone(),
            source: entry.source.clone(),
        },
        (_, Reach::Errno(errno)) if is_dead(errno, platform) => MountCheck::Stale,
        (_, Reach::TimedOut) => MountCheck::Unresponsive,
        (Some(_), _) => MountCheck::Live,
        (None, _) => MountCheck::Free,
    }
}

/// The path the mount table shows for `mount_dir`: its canonical parent
/// joined with its name. Canonicalizing the directory itself would stat the
/// possibly dead mount. `None` when the parent does not exist.
pub(crate) fn mount_key(mount_dir: &Path) -> Result<Option<PathBuf>, String> {
    let (Some(parent), Some(name)) = (mount_dir.parent(), mount_dir.file_name()) else {
        return Err(format!(
            "mount directory {} has no parent",
            mount_dir.display()
        ));
    };
    match std::fs::canonicalize(parent) {
        Ok(parent) => Ok(Some(parent.join(name))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot resolve {}: {error}", parent.display())),
    }
}

fn unmount(dir: &Path, platform: Platform, runner: &dyn Runner) -> Result<String, String> {
    let ran = |program: &str, args: &[std::ffi::OsString]| {
        format!("ran {}", display_command(program, args))
    };
    match platform {
        Platform::Linux => {
            let args = os_args(["-uz".as_ref(), dir.as_os_str()]);
            for program in ["fusermount3", "fusermount"] {
                match runner.run(program, &args, None) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!(
                            "cannot run {}: {error}",
                            display_command(program, &args)
                        ));
                    }
                    Ok(output) if output.success() => return Ok(ran(program, &args)),
                    Ok(output) => return Err(failure(program, &args, &output)),
                }
            }
            Err("neither fusermount3 nor fusermount is installed; install fuse3".to_string())
        }
        Platform::MacOs => {
            let args = os_args(["-f".as_ref(), dir.as_os_str()]);
            run_checked(runner, "/sbin/umount", &args, None)?;
            Ok(ran("/sbin/umount", &args))
        }
    }
}

/// The mount table probe [`recover_with`] uses: the entry at a mount point
/// and the outcome of a `stat` of it.
pub(crate) type Probe<'a> = dyn FnMut(&Path) -> Result<(Option<MountEntry>, Reach), String> + 'a;

/// Unmounts a dead zerotrust-drive mount at `mount_dir` and refuses a live
/// or foreign one. Returns the lines to log.
pub(crate) fn recover_with(
    mount_dir: &Path,
    platform: Platform,
    runner: &dyn Runner,
    probe: &mut Probe<'_>,
) -> Result<Vec<String>, String> {
    let Some(key) = mount_key(mount_dir)? else {
        return Ok(Vec::new());
    };
    let mut check = |key: &Path| -> Result<MountCheck, String> {
        let (entry, reach) = probe(key)?;
        Ok(classify(entry.as_ref(), reach, platform))
    };
    let shown = key.display();
    match check(&key)? {
        MountCheck::Free => Ok(Vec::new()),
        MountCheck::Live => Err(format!(
            "{shown} is mounted by a zerotrust-drive that is already running; stop it first"
        )),
        MountCheck::Unresponsive => Err(format!(
            "{shown} is a zerotrust-drive mount that does not answer within {} s; stop the zerotrust-drive serving it, or {}",
            STAT_TIMEOUT.as_secs(),
            match platform {
                Platform::Linux => {
                    format!(
                        "unmount it with `fusermount3 -uz {}`",
                        super::shell_path(&key)
                    )
                }
                // `umount -f` blocks on an FSKit volume whose server was
                // killed until macFUSE 5.5.0; ending the volume's module
                // process releases it.
                Platform::MacOs => format!(
                    "unmount it with `umount -f {}`; if that hangs too, the volume uses FSKit with macFUSE older than 5.5.0: end its process (`pgrep -lf {}`) or log out, then update macFUSE",
                    super::shell_path(&key),
                    crate::fskit::MODULE_ID
                ),
            }
        )),
        MountCheck::Foreign { fstype, source } => Err(format!(
            "{shown} already has a {fstype} file system from {source} mounted; unmount it or choose another mount directory"
        )),
        MountCheck::Stale => {
            let mut lines = vec![format!(
                "{shown} is a dead zerotrust-drive mount from an earlier run; unmounting it"
            )];
            lines.push(unmount(&key, platform, runner)?);
            match check(&key)? {
                MountCheck::Free => {
                    lines.push(format!("{shown} is free again"));
                    Ok(lines)
                }
                other => Err(format!(
                    "{shown} is still occupied after the unmount ({other:?})"
                )),
            }
        }
    }
}

/// [`recover_with`] against this host's mount table.
pub(crate) fn recover(
    mount_dir: &Path,
    platform: Platform,
    runner: &dyn Runner,
) -> Result<Vec<String>, String> {
    recover_with(mount_dir, platform, runner, &mut |key| {
        let entries = mount_table()?;
        let entry = find_entry(&entries, key).cloned();
        Ok((entry, stat_with_timeout(key, STAT_TIMEOUT)))
    })
}

/// Stats `path` on a helper thread, so a hung FUSE server cannot block the
/// start forever.
fn stat_with_timeout(path: &Path, timeout: Duration) -> Reach {
    let stat = |path: &Path| match std::fs::metadata(path) {
        Ok(_) => Reach::Ok,
        Err(error) => Reach::Errno(error.raw_os_error().unwrap_or(0)),
    };
    let (sender, receiver) = std::sync::mpsc::channel();
    let owned = path.to_path_buf();
    let spawned = std::thread::Builder::new()
        .name("zdrive-mount-probe".to_string())
        .spawn(move || {
            let _ = sender.send(stat(&owned));
        });
    match spawned {
        Ok(_) => receiver.recv_timeout(timeout).unwrap_or(Reach::TimedOut),
        Err(_) => stat(path),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn mount_table() -> Result<Vec<MountEntry>, String> {
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|text| parse_mountinfo(&text))
        .map_err(|error| format!("cannot read /proc/self/mountinfo: {error}"))
}

#[cfg(target_os = "macos")]
pub(crate) fn mount_table() -> Result<Vec<MountEntry>, String> {
    use std::os::unix::ffi::OsStrExt;
    let text = |field: &[libc::c_char]| -> Vec<u8> {
        field
            .iter()
            .take_while(|&&character| character != 0)
            .map(|&character| character as u8)
            .collect()
    };
    // MNT_NOWAIT returns the cached table without asking each file system,
    // which a dead or hung FUSE server could not answer.
    // SAFETY: a null buffer only asks for the number of mounts.
    let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    let count = usize::try_from(count)
        .map_err(|_| format!("getfsstat: {}", std::io::Error::last_os_error()))?;
    // Room for mounts that appear between the two calls.
    let capacity = count + 16;
    // SAFETY: statfs is plain old data for which all-zero bytes are valid.
    let mut buffer: Vec<libc::statfs> = (0..capacity)
        .map(|_| unsafe { std::mem::zeroed() })
        .collect();
    let size = libc::c_int::try_from(capacity * std::mem::size_of::<libc::statfs>())
        .map_err(|_| "too many mounts for getfsstat".to_string())?;
    // SAFETY: buffer holds `size` bytes of statfs records.
    let filled = unsafe { libc::getfsstat(buffer.as_mut_ptr(), size, libc::MNT_NOWAIT) };
    let filled = usize::try_from(filled)
        .map_err(|_| format!("getfsstat: {}", std::io::Error::last_os_error()))?;
    buffer.truncate(filled);
    Ok(buffer
        .iter()
        .map(|fs| MountEntry {
            mount_point: PathBuf::from(std::ffi::OsStr::from_bytes(&text(&fs.f_mntonname))),
            fstype: String::from_utf8_lossy(&text(&fs.f_fstypename)).into_owned(),
            source: String::from_utf8_lossy(&text(&fs.f_mntfromname)).into_owned(),
        })
        .collect())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn mount_table() -> Result<Vec<MountEntry>, String> {
    Err("stale-mount recovery is supported only on macOS and Linux".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;
    use crate::service::testing::{FakeRunner, exit, ok};
    use std::cell::RefCell;

    const MOUNTINFO: &str = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 22 0:35 / /home/alex/my\\040drive rw,nosuid,nodev,relatime shared:20 - fuse zerotrust-drive rw,user_id=1000,group_id=1000
41 22 0:36 / /media/usb rw,relatime shared:21 - fuseblk /dev/sdb1 rw
42 22 0:37 / /mnt/sub rw shared:22 master:3 - fuse.sshfs alex@host:/ rw
43 22 0:38 / /media/usb rw,relatime shared:23 - fuse.zerotrust-drive zerotrust-drive rw
garbage line without separator
";

    fn entry(mount_point: &str, fstype: &str, source: &str) -> MountEntry {
        MountEntry {
            mount_point: PathBuf::from(mount_point),
            fstype: fstype.to_string(),
            source: source.to_string(),
        }
    }

    #[test]
    fn service_mountinfo_parses_fields_and_escapes() {
        let entries = parse_mountinfo(MOUNTINFO);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0], entry("/", "ext4", "/dev/sda1"));
        assert_eq!(
            entries[1],
            entry("/home/alex/my drive", "fuse", "zerotrust-drive")
        );
        assert_eq!(entries[3], entry("/mnt/sub", "fuse.sshfs", "alex@host:/"));
        assert_eq!(
            find_entry(&entries, Path::new("/media/usb")),
            Some(&entry(
                "/media/usb",
                "fuse.zerotrust-drive",
                "zerotrust-drive"
            )),
            "the last mount over a path is the visible one"
        );
        assert_eq!(find_entry(&entries, Path::new("/home/alex")), None);
        assert_eq!(unescape_mountinfo("a\\011b\\134c\\9"), "a\tb\\c\\9");
    }

    #[test]
    fn service_mount_classification_matrix() {
        let entries = parse_mountinfo(MOUNTINFO);
        let ours = find_entry(&entries, Path::new("/home/alex/my drive"));
        let linux = Platform::Linux;
        assert_eq!(
            classify(ours, Reach::Errno(libc::ENOTCONN), linux),
            MountCheck::Stale
        );
        assert_eq!(classify(ours, Reach::Ok, linux), MountCheck::Live);
        assert_eq!(
            classify(ours, Reach::Errno(libc::EACCES), linux),
            MountCheck::Live
        );
        assert_eq!(
            classify(ours, Reach::TimedOut, linux),
            MountCheck::Unresponsive
        );
        assert_eq!(classify(None, Reach::Ok, linux), MountCheck::Free);
        assert_eq!(
            classify(None, Reach::Errno(libc::ENOENT), linux),
            MountCheck::Free
        );
        assert_eq!(
            classify(None, Reach::Errno(libc::ENOTCONN), linux),
            MountCheck::Stale
        );
        assert_eq!(
            classify(
                find_entry(&entries, Path::new("/mnt/sub")),
                Reach::Errno(libc::ENOTCONN),
                linux
            ),
            MountCheck::Foreign {
                fstype: "fuse.sshfs".to_string(),
                source: "alex@host:/".to_string()
            }
        );

        let mac = Platform::MacOs;
        let macfuse = entry("/Users/alex/Drive", "macfuse", "zerotrust-drive");
        for errno in [libc::ENXIO, libc::EIO, libc::ENOTCONN] {
            assert_eq!(
                classify(Some(&macfuse), Reach::Errno(errno), mac),
                MountCheck::Stale
            );
        }
        assert_eq!(classify(Some(&macfuse), Reach::Ok, mac), MountCheck::Live);
        let osxfuse = entry("/Users/alex/Drive", "osxfuse", "zerotrust-drive");
        assert_eq!(classify(Some(&osxfuse), Reach::Ok, mac), MountCheck::Live);
        let fskit = entry(
            "/Users/alex/Drive",
            "macfuse",
            "macfuse://8DB7589E-2E50-4257-ACC7-E2542742DA6B",
        );
        assert_eq!(classify(Some(&fskit), Reach::Ok, mac), MountCheck::Live);
        assert_eq!(
            classify(Some(&fskit), Reach::Errno(libc::ENXIO), mac),
            MountCheck::Stale
        );
        assert_eq!(
            classify(Some(&fskit), Reach::TimedOut, mac),
            MountCheck::Unresponsive
        );
        assert!(matches!(
            classify(Some(&fskit), Reach::Ok, linux),
            MountCheck::Foreign { .. }
        ));
        let other_macfuse = entry("/Users/alex/Drive", "macfuse", "sshfs@host");
        assert!(matches!(
            classify(Some(&other_macfuse), Reach::Ok, mac),
            MountCheck::Foreign { .. }
        ));
        assert!(matches!(
            classify(Some(&macfuse), Reach::Ok, linux),
            MountCheck::Foreign { .. }
        ));
        let apfs = entry("/Users/alex/Drive", "apfs", "/dev/disk3s5");
        assert!(matches!(
            classify(Some(&apfs), Reach::Ok, mac),
            MountCheck::Foreign { .. }
        ));
    }

    type Answers = RefCell<std::collections::VecDeque<(Option<MountEntry>, Reach)>>;

    /// Probe answers, consumed in order.
    fn scripted(answers: Vec<(Option<MountEntry>, Reach)>) -> Answers {
        RefCell::new(answers.into())
    }

    #[test]
    fn service_recovery_unmounts_a_stale_linux_mount() {
        let dir = TestDir::new("service-recover-linux");
        let mount = dir.path().join("mount");
        let key = std::fs::canonicalize(dir.path()).unwrap().join("mount");
        let ours = entry(&key.display().to_string(), "fuse", FS_NAME);
        let answers = scripted(vec![
            (Some(ours), Reach::Errno(libc::ENOTCONN)),
            (None, Reach::Errno(libc::ENOENT)),
        ]);
        let probed = RefCell::new(Vec::new());
        let runner = FakeRunner::new(|argv, _| {
            if argv.starts_with("fusermount3 ") {
                Err(std::io::Error::from(std::io::ErrorKind::NotFound))
            } else {
                ok("")
            }
        });
        let lines = recover_with(&mount, Platform::Linux, &runner, &mut |path| {
            probed.borrow_mut().push(path.to_path_buf());
            Ok(answers.borrow_mut().pop_front().unwrap())
        })
        .unwrap();
        assert_eq!(
            runner.argv(),
            [
                format!("fusermount3 -uz {}", key.display()),
                format!("fusermount -uz {}", key.display()),
            ]
        );
        assert_eq!(*probed.borrow(), [key.clone(), key.clone()]);
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[0].contains("dead zerotrust-drive mount"));
        assert!(lines[1].starts_with("ran fusermount -uz "));
    }

    #[test]
    fn service_recovery_unmounts_a_stale_macos_mount() {
        let dir = TestDir::new("service-recover-macos");
        let mount = dir.path().join("mount");
        let key = std::fs::canonicalize(dir.path()).unwrap().join("mount");
        let ours = entry(&key.display().to_string(), "macfuse", FS_NAME);
        let answers = scripted(vec![
            (Some(ours), Reach::Errno(libc::ENXIO)),
            (None, Reach::Ok),
        ]);
        let runner = FakeRunner::succeeding();
        recover_with(&mount, Platform::MacOs, &runner, &mut |_| {
            Ok(answers.borrow_mut().pop_front().unwrap())
        })
        .unwrap();
        assert_eq!(
            runner.argv(),
            [format!("/sbin/umount -f {}", key.display())]
        );
    }

    #[test]
    fn service_recovery_refuses_live_unresponsive_foreign_and_stuck_mounts() {
        let dir = TestDir::new("service-recover-refuse");
        let mount = dir.path().join("mount");
        let key = std::fs::canonicalize(dir.path()).unwrap().join("mount");
        let ours = entry(&key.display().to_string(), "fuse", FS_NAME);
        let run = |answers: Vec<(Option<MountEntry>, Reach)>, runner: &FakeRunner| {
            let answers = scripted(answers);
            recover_with(&mount, Platform::Linux, runner, &mut |_| {
                Ok(answers.borrow_mut().pop_front().unwrap())
            })
        };
        let runner = FakeRunner::succeeding();
        assert_eq!(run(vec![(None, Reach::Ok)], &runner), Ok(Vec::new()));
        let live = run(vec![(Some(ours.clone()), Reach::Ok)], &runner).unwrap_err();
        assert!(live.contains("already running"), "{live}");
        let hung = run(vec![(Some(ours.clone()), Reach::TimedOut)], &runner).unwrap_err();
        assert!(hung.contains("fusermount3 -uz"), "{hung}");
        let mac_ours = entry(&key.display().to_string(), "macfuse", FS_NAME);
        let answers = scripted(vec![(Some(mac_ours), Reach::TimedOut)]);
        let mac_hung = recover_with(&mount, Platform::MacOs, &runner, &mut |_| {
            Ok(answers.borrow_mut().pop_front().unwrap())
        })
        .unwrap_err();
        assert!(mac_hung.contains("umount -f"), "{mac_hung}");
        assert!(
            mac_hung.contains("pgrep -lf io.macfuse.app.fsmodule.macfuse"),
            "{mac_hung}"
        );
        let foreign = entry(&key.display().to_string(), "fuse.sshfs", "alex@host:/");
        let error = run(vec![(Some(foreign), Reach::Ok)], &runner).unwrap_err();
        assert!(
            error.contains("fuse.sshfs file system from alex@host:/"),
            "{error}"
        );
        assert!(runner.argv().is_empty(), "nothing was unmounted");

        let stuck = run(
            vec![
                (Some(ours.clone()), Reach::Errno(libc::ENOTCONN)),
                (Some(ours.clone()), Reach::Errno(libc::ENOTCONN)),
            ],
            &runner,
        )
        .unwrap_err();
        assert!(stuck.contains("still occupied"), "{stuck}");

        let failing = FakeRunner::new(|_, _| exit(1, "", "fusermount3: entry not found"));
        let error = run(vec![(Some(ours), Reach::Errno(libc::ENOTCONN))], &failing).unwrap_err();
        assert!(error.contains("entry not found"), "{error}");

        let orphan = dir.path().join("absent-parent").join("mount");
        assert_eq!(
            recover_with(&orphan, Platform::Linux, &runner, &mut |_| unreachable!()),
            Ok(Vec::new())
        );
    }

    #[test]
    fn service_recovery_reads_the_host_mount_table() {
        let entries = mount_table().unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| entry.mount_point == Path::new("/")),
            "{entries:?}"
        );
        let dir = TestDir::new("service-recover-host");
        assert_eq!(stat_with_timeout(dir.path(), STAT_TIMEOUT), Reach::Ok);
        assert_eq!(
            stat_with_timeout(&dir.path().join("absent"), STAT_TIMEOUT),
            Reach::Errno(libc::ENOENT)
        );
        let platform = Platform::current().unwrap();
        assert_eq!(
            recover(
                &dir.path().join("mount"),
                platform,
                &FakeRunner::succeeding()
            ),
            Ok(Vec::new())
        );
    }
}
