// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Passphrase custody for unattended starts: a private passphrase file, or a
//! systemd-creds credential that the systemd user manager decrypts into the
//! service's `$CREDENTIALS_DIRECTORY`. The passphrase reaches `systemd-creds`
//! only on standard input.

use std::path::{Path, PathBuf};

use super::definition::{
    Custody, Definition, Instance, credential_path, ensure_services_dir, managed_passphrase_path,
};
use super::{Host, Platform, Runner, os_args, remove_if_present, run_checked, shell_path};
use crate::remote::config::Paths;
use crate::remote::write_private_file;

/// The credential name the unit's `LoadCredentialEncrypted=` loads, and the
/// file name below `$CREDENTIALS_DIRECTORY`.
pub(crate) const CREDENTIAL_NAME: &str = "zdrive-passphrase";
const PROBE_CREDENTIAL_NAME: &str = "zdrive-probe";
const SYSTEMD_CREDS: &str = "systemd-creds";
use crate::prompt::MAX_PASSPHRASE_FILE;

/// What [`judge_secret_file`] needs to know about a file.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SecretFileFacts {
    pub(crate) symlink: bool,
    pub(crate) regular: bool,
    pub(crate) uid: u32,
    pub(crate) mode: u32,
}

impl SecretFileFacts {
    fn of(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            symlink: metadata.file_type().is_symlink(),
            regular: metadata.file_type().is_file(),
            uid: metadata.uid(),
            mode: metadata.mode(),
        }
    }
}

/// Refuses a passphrase file that is not a regular file owned by `uid`
/// without any group or other permission bits, naming the exact fix.
pub(crate) fn judge_secret_file(
    path: &Path,
    facts: SecretFileFacts,
    uid: u32,
    user: &str,
) -> Result<(), String> {
    let quoted = shell_path(path);
    if facts.symlink {
        return Err(format!(
            "passphrase file {} is a symbolic link; name the file itself: {}",
            path.display(),
            std::fs::canonicalize(path)
                .map(|target| target.display().to_string())
                .unwrap_or_else(|_| "its target".to_string())
        ));
    }
    if !facts.regular {
        return Err(format!(
            "passphrase file {} is not a regular file",
            path.display()
        ));
    }
    let mut problems = Vec::new();
    let mut fixes = Vec::new();
    if facts.uid != uid {
        problems.push(format!("is owned by uid {}, not by {user}", facts.uid));
        fixes.push(format!("sudo chown {} {quoted}", super::shell_word(user)));
    }
    if facts.mode & 0o077 != 0 {
        problems.push(format!(
            "is accessible to other users (mode {:04o})",
            facts.mode & 0o7777
        ));
        fixes.push(format!("chmod 600 {quoted}"));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "passphrase file {} {}; run: {}",
            path.display(),
            problems.join(" and "),
            fixes.join("; ")
        ))
    }
}

/// Requires `path` to be a regular file owned by the current user that no
/// group or other user can access.
pub(crate) fn check_private_secret_file(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            format!("passphrase file {} does not exist", path.display())
        } else {
            format!("cannot inspect passphrase file {}: {error}", path.display())
        }
    })?;
    let uid = super::current_uid();
    judge_secret_file(
        path,
        SecretFileFacts::of(&metadata),
        uid,
        &super::user_name(uid),
    )
}

/// Reads a passphrase file after [`check_private_secret_file`]: at most 4 KiB
/// of UTF-8 without one trailing line break, never empty. The opened file is
/// judged again, so a swap after the first check is caught.
pub(crate) fn read_passphrase_file(path: &Path) -> Result<String, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    check_private_secret_file(path)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("cannot open passphrase file {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect passphrase file {}: {error}", path.display()))?;
    let uid = super::current_uid();
    judge_secret_file(
        path,
        SecretFileFacts::of(&metadata),
        uid,
        &super::user_name(uid),
    )?;
    let mut bytes = Vec::new();
    file.take(MAX_PASSPHRASE_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read passphrase file {}: {error}", path.display()))?;
    crate::prompt::secret_from_bytes(bytes, path)
        .map_err(|error| format!("passphrase file {error}"))
}

/// Whether `systemd-creds --user` (systemd 256 or newer) can encrypt and
/// decrypt here. Probed with a random value, because the version alone does
/// not tell whether the user scope works on this host.
// For `zdrive doctor`; `service install` probes with the error detail.
#[allow(dead_code)]
pub(crate) fn systemd_creds_user_supported(runner: &dyn Runner) -> bool {
    probe_systemd_creds(runner, &probe_dir()).is_ok()
}

/// Where the probe credential lives briefly: the private runtime directory
/// when there is one.
pub(crate) fn probe_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(std::env::temp_dir)
}

/// Round trip of a random value through `systemd-creds --user encrypt` and
/// `decrypt` via a credential file in `dir`, which is removed afterwards.
pub(crate) fn probe_systemd_creds(runner: &dyn Runner, dir: &Path) -> Result<(), String> {
    let mut random = [0u8; 20];
    getrandom::fill(&mut random)
        .map_err(|error| format!("cannot generate a probe value: {error}"))?;
    let value = crate::remote::hex(&random[..16]);
    let file = dir.join(format!(
        "zerotrust-drive-creds-probe-{}-{}.cred",
        std::process::id(),
        crate::remote::hex(&random[16..])
    ));
    let name = format!("--name={PROBE_CREDENTIAL_NAME}");
    let result = (|| {
        run_checked(
            runner,
            SYSTEMD_CREDS,
            &os_args([
                "--user".as_ref(),
                "encrypt".as_ref(),
                name.as_ref(),
                "-".as_ref(),
                file.as_os_str(),
            ]),
            Some(value.as_bytes()),
        )?;
        let output = run_checked(
            runner,
            SYSTEMD_CREDS,
            &os_args([
                "--user".as_ref(),
                "decrypt".as_ref(),
                name.as_ref(),
                file.as_os_str(),
                "-".as_ref(),
            ]),
            None,
        )?;
        let decrypted = output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout);
        if decrypted == value.as_bytes() {
            Ok(())
        } else {
            Err("systemd-creds --user decrypted a different value".to_string())
        }
    })();
    let _ = std::fs::remove_file(&file);
    result
}

/// Encrypts `passphrase` into `path` with `systemd-creds --user`, through a
/// temp file renamed into place so a failure keeps the previous credential.
fn encrypt_credential(runner: &dyn Runner, passphrase: &str, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} has no file name", path.display()))?;
    let temp = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    remove_if_present(&temp)?;
    let name = format!("--name={CREDENTIAL_NAME}");
    let result = (|| {
        run_checked(
            runner,
            SYSTEMD_CREDS,
            &os_args([
                "--user".as_ref(),
                "encrypt".as_ref(),
                name.as_ref(),
                "-".as_ref(),
                temp.as_os_str(),
            ]),
            Some(passphrase.as_bytes()),
        )?;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("chmod 600 {}: {error}", temp.display()))?;
        std::fs::rename(&temp, path).map_err(|error| {
            format!("cannot move the credential to {}: {error}", path.display())
        })?;
        std::fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| format!("cannot sync {}: {error}", parent.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Stores the passphrase of an encrypted instance in the custody its
/// definition names: the zdrive-managed passphrase file, or a systemd-creds
/// credential. A user-supplied passphrase file is never written. The other
/// managed custody is removed, so no stale plaintext copy stays behind.
pub(crate) fn store_passphrase(
    paths: &Paths,
    def: &Definition,
    passphrase: &str,
    runner: &dyn Runner,
) -> Result<Vec<String>, String> {
    let Instance::Encrypted { custody, .. } = &def.instance else {
        return Err(format!(
            "service {}: a plain instance has no passphrase",
            def.name
        ));
    };
    if passphrase.is_empty() {
        return Err(format!(
            "service {}: refusing to store an empty passphrase",
            def.name
        ));
    }
    let managed = managed_passphrase_path(paths, &def.name);
    let credential = credential_path(paths, &def.name);
    ensure_services_dir(paths)?;
    let mut lines = Vec::new();
    match custody {
        Custody::File(path) if *path == managed => {
            write_private_file(path, passphrase.as_bytes()).map_err(|error| error.to_string())?;
            lines.push(format!(
                "stored the passphrase in {} (0600)",
                path.display()
            ));
            if remove_if_present(&credential)? {
                lines.push(format!(
                    "deleted the old credential {}",
                    credential.display()
                ));
            }
        }
        Custody::File(path) => {
            return Err(format!(
                "service {}: {} is your own passphrase file; zdrive does not write it",
                def.name,
                path.display()
            ));
        }
        Custody::SystemdCreds => {
            encrypt_credential(runner, passphrase, &credential)?;
            lines.push(format!(
                "encrypted the passphrase with systemd-creds into {}",
                credential.display()
            ));
            if remove_if_present(&managed)? {
                lines.push(format!(
                    "deleted the plaintext passphrase file {}",
                    managed.display()
                ));
            }
        }
    }
    Ok(lines)
}

/// Whether the custody artifact `store_passphrase` would write is missing.
pub(crate) fn needs_passphrase(paths: &Paths, def: &Definition) -> bool {
    match &def.instance {
        Instance::Encrypted {
            custody: Custody::File(path),
            ..
        } => *path == managed_passphrase_path(paths, &def.name) && !path.exists(),
        Instance::Encrypted {
            custody: Custody::SystemdCreds,
            ..
        } => !credential_path(paths, &def.name).exists(),
        Instance::Plain { .. } => false,
    }
}

/// Checks that an unattended start of `def` will find its passphrase.
pub(crate) fn ensure_ready(host: &Host, def: &Definition) -> Result<(), String> {
    let name = &def.name;
    match &def.instance {
        Instance::Plain { .. } => Ok(()),
        Instance::Encrypted {
            custody: Custody::File(path),
            ..
        } => read_passphrase_file(path)
            .map(drop)
            .map_err(|error| format!("service {name}: {error}")),
        Instance::Encrypted {
            custody: Custody::SystemdCreds,
            ..
        } => {
            if host.platform != Platform::Linux {
                return Err(format!(
                    "service {name}: systemd-creds custody needs Linux; reinstall with --custody file"
                ));
            }
            let credential = credential_path(&host.paths, name);
            match std::fs::symlink_metadata(&credential) {
                Ok(metadata) if metadata.file_type().is_file() => Ok(()),
                _ => Err(format!(
                    "service {name}: credential {} is missing; run: zdrive service install --name {name} --custody systemd-creds",
                    credential.display()
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;
    use crate::service::testing::{FakeRunner, absolute, exit, host, ok};
    use std::os::unix::fs::PermissionsExt;

    fn facts(uid: u32, mode: u32) -> SecretFileFacts {
        SecretFileFacts {
            symlink: false,
            regular: true,
            uid,
            mode: 0o100000 | mode,
        }
    }

    fn encrypted(name: &str, custody: Custody) -> Definition {
        Definition {
            name: name.to_string(),
            instance: Instance::Encrypted {
                remote: None,
                encrypted_dir: PathBuf::from("/abs/store"),
                mount_dir: PathBuf::from("/abs/mount"),
                custody,
                fuse_backend: crate::fskit::BackendArg::Auto,
            },
            final_push_wait_secs: 60,
        }
    }

    #[test]
    fn service_secret_file_judgement_names_the_exact_fix() {
        let path = Path::new("/home/alex/pass phrase");
        assert!(judge_secret_file(path, facts(501, 0o600), 501, "alex").is_ok());
        assert!(judge_secret_file(path, facts(501, 0o400), 501, "alex").is_ok());
        assert_eq!(
            judge_secret_file(path, facts(501, 0o640), 501, "alex").unwrap_err(),
            "passphrase file /home/alex/pass phrase is accessible to other users (mode 0640); run: chmod 600 '/home/alex/pass phrase'"
        );
        assert_eq!(
            judge_secret_file(path, facts(0, 0o600), 501, "alex").unwrap_err(),
            "passphrase file /home/alex/pass phrase is owned by uid 0, not by alex; run: sudo chown alex '/home/alex/pass phrase'"
        );
        assert_eq!(
            judge_secret_file(path, facts(0, 0o604), 501, "alex").unwrap_err(),
            "passphrase file /home/alex/pass phrase is owned by uid 0, not by alex and is accessible to other users (mode 0604); run: sudo chown alex '/home/alex/pass phrase'; chmod 600 '/home/alex/pass phrase'"
        );
        let directory = SecretFileFacts {
            regular: false,
            ..facts(501, 0o700)
        };
        assert!(
            judge_secret_file(path, directory, 501, "alex")
                .unwrap_err()
                .contains("not a regular file")
        );
        let link = SecretFileFacts {
            symlink: true,
            ..facts(501, 0o777)
        };
        assert!(
            judge_secret_file(path, link, 501, "alex")
                .unwrap_err()
                .contains("symbolic link")
        );
    }

    #[test]
    fn service_private_secret_files_are_checked_on_disk() {
        let dir = TestDir::new("service-secret-file");
        let file = absolute(&dir, "secret");
        assert!(
            check_private_secret_file(&file)
                .unwrap_err()
                .contains("does not exist")
        );
        std::fs::write(&file, "correct horse\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = check_private_secret_file(&file).unwrap_err();
        assert!(error.contains("mode 0644"), "{error}");
        assert!(error.ends_with(&format!("run: chmod 600 {}", shell_path(&file))));
        assert!(read_passphrase_file(&file).is_err());

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_passphrase_file(&file).unwrap(), "correct horse");
        std::fs::write(&file, "windows\r\n").unwrap();
        assert_eq!(read_passphrase_file(&file).unwrap(), "windows");
        // One rule for every passphrase file: a second line is a mistake,
        // not part of the secret.
        std::fs::write(&file, "two\n\n").unwrap();
        assert!(
            read_passphrase_file(&file)
                .unwrap_err()
                .contains("more than one line")
        );
        std::fs::write(&file, "\n").unwrap();
        assert!(read_passphrase_file(&file).unwrap_err().contains("empty"));
        std::fs::write(&file, vec![b'x'; 4097]).unwrap();
        assert!(read_passphrase_file(&file).unwrap_err().contains("larger"));
        std::fs::write(&file, [0xff, 0xfe]).unwrap();
        assert!(read_passphrase_file(&file).unwrap_err().contains("UTF-8"));

        let link = absolute(&dir, "link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(
            check_private_secret_file(&link)
                .unwrap_err()
                .contains("symbolic link")
        );
        assert!(
            check_private_secret_file(dir.path())
                .unwrap_err()
                .contains("not a regular file")
        );
    }

    #[test]
    fn service_systemd_creds_probe_round_trips_through_stdin_and_stdout() {
        use std::sync::{Arc, Mutex};
        let dir = TestDir::new("service-creds-probe");
        let stored: Arc<Mutex<Vec<u8>>> = Arc::default();
        let store = stored.clone();
        let runner = FakeRunner::new(move |argv, stdin| {
            let file = argv
                .split(' ')
                .nth(if argv.contains(" encrypt ") { 5 } else { 4 });
            if argv.contains(" encrypt ") {
                std::fs::write(file.unwrap(), b"sealed").unwrap();
                *store.lock().unwrap() = stdin.unwrap().to_vec();
                ok("")
            } else {
                ok(&format!(
                    "{}\n",
                    String::from_utf8(store.lock().unwrap().clone()).unwrap()
                ))
            }
        });
        assert_eq!(probe_systemd_creds(&runner, dir.path()), Ok(()));
        let argv = runner.argv();
        assert_eq!(argv.len(), 2);
        let file = argv[0].rsplit(' ').next().unwrap().to_string();
        assert!(
            file.starts_with(
                &dir.path()
                    .join("zerotrust-drive-creds-probe-")
                    .display()
                    .to_string()
            )
        );
        assert!(file.ends_with(".cred"));
        assert_eq!(
            argv[0],
            format!("systemd-creds --user encrypt --name=zdrive-probe - {file}")
        );
        assert_eq!(
            argv[1],
            format!("systemd-creds --user decrypt --name=zdrive-probe {file} -")
        );
        let value = runner.stdin_of(0).unwrap();
        assert_eq!(value.len(), 32, "a random 128-bit hex probe value");
        assert!(runner.stdin_of(1).is_none());
        assert!(!Path::new(&file).exists(), "the probe file is removed");
    }

    #[test]
    fn service_systemd_creds_probe_fails_on_old_systemd_and_mismatches() {
        let dir = TestDir::new("service-creds-probe-fail");
        let old =
            FakeRunner::new(|_, _| exit(1, "", "systemd-creds: unrecognized option '--user'"));
        let error = probe_systemd_creds(&old, dir.path()).unwrap_err();
        assert!(error.contains("unrecognized option"), "{error}");
        assert_eq!(old.argv().len(), 1);

        let missing =
            FakeRunner::new(|_, _| Err(std::io::Error::from(std::io::ErrorKind::NotFound)));
        assert!(probe_systemd_creds(&missing, dir.path()).is_err());

        let wrong = FakeRunner::new(|argv, _| {
            if argv.contains(" decrypt ") {
                ok("something else")
            } else {
                ok("")
            }
        });
        assert!(
            probe_systemd_creds(&wrong, dir.path())
                .unwrap_err()
                .contains("different value")
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn service_store_passphrase_writes_managed_file_or_credential() {
        let dir = TestDir::new("service-store-passphrase");
        let host = host(&dir, Platform::Linux);
        let managed = managed_passphrase_path(&host.paths, "enc");
        let credential = credential_path(&host.paths, "enc");
        let file_def = encrypted("enc", Custody::File(managed.clone()));
        assert!(needs_passphrase(&host.paths, &file_def));
        let runner = FakeRunner::succeeding();
        let lines = store_passphrase(&host.paths, &file_def, "s3cret", &runner).unwrap();
        assert_eq!(std::fs::read(&managed).unwrap(), b"s3cret");
        let mode = std::fs::metadata(&managed).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(lines.len(), 1);
        assert!(runner.argv().is_empty());
        assert!(!needs_passphrase(&host.paths, &file_def));
        assert!(ensure_ready(&host, &file_def).is_ok());

        let creds_def = encrypted("enc", Custody::SystemdCreds);
        assert!(needs_passphrase(&host.paths, &creds_def));
        let runner = FakeRunner::new(|argv, _| {
            std::fs::write(argv.rsplit(' ').next().unwrap(), b"sealed").unwrap();
            ok("")
        });
        let lines = store_passphrase(&host.paths, &creds_def, "s3cret", &runner).unwrap();
        let temp = credential
            .parent()
            .unwrap()
            .join(format!(".enc.cred.{}.tmp", std::process::id()));
        assert_eq!(
            runner.argv(),
            [format!(
                "systemd-creds --user encrypt --name=zdrive-passphrase - {}",
                temp.display()
            )]
        );
        assert_eq!(runner.stdin_of(0).unwrap(), b"s3cret");
        assert_eq!(std::fs::read(&credential).unwrap(), b"sealed");
        assert!(!temp.exists());
        assert!(!managed.exists(), "the plaintext copy is removed");
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(ensure_ready(&host, &creds_def).is_ok());

        let failing = FakeRunner::new(|_, _| exit(1, "", "TPM2 not available"));
        let error = store_passphrase(&host.paths, &creds_def, "new", &failing).unwrap_err();
        assert!(error.contains("TPM2 not available"), "{error}");
        assert_eq!(
            std::fs::read(&credential).unwrap(),
            b"sealed",
            "a failed encryption keeps the previous credential"
        );
    }

    #[test]
    fn service_store_passphrase_refuses_foreign_files_plain_and_empty() {
        let dir = TestDir::new("service-store-refusals");
        let host = host(&dir, Platform::Linux);
        let runner = FakeRunner::succeeding();
        let own = encrypted("enc", Custody::File(absolute(&dir, "mine")));
        assert!(
            store_passphrase(&host.paths, &own, "x", &runner)
                .unwrap_err()
                .contains("your own passphrase file")
        );
        assert!(!needs_passphrase(&host.paths, &own));
        let managed = encrypted(
            "enc",
            Custody::File(managed_passphrase_path(&host.paths, "enc")),
        );
        assert!(
            store_passphrase(&host.paths, &managed, "", &runner)
                .unwrap_err()
                .contains("empty")
        );
        let plain = Definition {
            name: "p".to_string(),
            instance: Instance::Plain {
                remote: "home".to_string(),
                local_dir: PathBuf::from("/abs/p"),
            },
            final_push_wait_secs: 60,
        };
        assert!(store_passphrase(&host.paths, &plain, "x", &runner).is_err());
        assert!(ensure_ready(&host, &plain).is_ok());
    }

    #[test]
    fn service_custody_readiness_refusals() {
        let dir = TestDir::new("service-custody-ready");
        let linux = host(&dir, Platform::Linux);
        let creds = encrypted("enc", Custody::SystemdCreds);
        assert_eq!(
            ensure_ready(&linux, &creds).unwrap_err(),
            format!(
                "service enc: credential {} is missing; run: zdrive service install --name enc --custody systemd-creds",
                credential_path(&linux.paths, "enc").display()
            )
        );
        let mac = host(&dir, Platform::MacOs);
        assert!(
            ensure_ready(&mac, &creds)
                .unwrap_err()
                .contains("needs Linux")
        );
        let missing = encrypted("enc", Custody::File(absolute(&dir, "absent")));
        assert!(
            ensure_ready(&mac, &missing)
                .unwrap_err()
                .starts_with("service enc: passphrase file ")
        );
    }
}
