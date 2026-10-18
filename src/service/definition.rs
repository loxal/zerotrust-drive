// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Instance definitions in `$XDG_CONFIG_HOME/zerotrust-drive/services/`
//! (`<name>.json`, 0600 in a 0700 directory). launchd and systemd know only
//! the instance name; everything else is read from here at every start.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::remote::config::{Paths, RemoteName};
use crate::remote::{ensure_private_dir, read_private_file, write_private_file};

pub(crate) const FORMAT: &str = "zerotrust-drive-service";
pub(crate) const VERSION: u32 = 1;
pub(crate) const DEFAULT_FINAL_PUSH_WAIT_SECS: u64 = 60;
/// launchd's ExitTimeOut and systemd's TimeoutStopSec.
pub(crate) const STOP_TIMEOUT_SECS: u64 = 90;
/// Leaves the unmount and the final local flush time within the stop
/// timeout, after which the service manager kills the process.
pub(crate) const MAX_FINAL_PUSH_WAIT_SECS: u64 = 75;
const MAX_DEFINITION_FILE: u64 = 64 << 10;

const MODE_ENCRYPTED: &str = "encrypted";
const MODE_PLAIN: &str = "plain";
const CUSTODY_SYSTEMD_CREDS: &str = "systemd-creds";
const CUSTODY_FILE: &str = "file";
const CUSTODY_NONE: &str = "none";

/// One auto-started instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Definition {
    pub(crate) name: String,
    pub(crate) instance: Instance,
    /// Seconds a stopping instance waits for its final upload.
    pub(crate) final_push_wait_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Instance {
    /// Mount the encrypted store at `mount_dir`, kept in sync with `remote`
    /// when one is given.
    Encrypted {
        remote: Option<String>,
        encrypted_dir: PathBuf,
        mount_dir: PathBuf,
        custody: Custody,
    },
    /// Keep the plain folder `local_dir` in sync with `remote`.
    Plain { remote: String, local_dir: PathBuf },
}

/// Where an unattended encrypted instance finds its passphrase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Custody {
    /// The systemd-creds credential `services/<name>.cred`, which the user
    /// manager decrypts into `$CREDENTIALS_DIRECTORY/zdrive-passphrase`.
    SystemdCreds,
    /// A passphrase file that only the current user can read.
    File(PathBuf),
}

/// The on-disk shape. Every field is checked by [`Definition::from_file`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefinitionFile {
    format: String,
    version: u32,
    name: String,
    mode: String,
    remote: Option<String>,
    encrypted_dir: Option<PathBuf>,
    mount_dir: Option<PathBuf>,
    local_dir: Option<PathBuf>,
    custody: String,
    passphrase_file: Option<PathBuf>,
    final_push_wait_secs: u64,
}

pub(crate) fn services_dir(paths: &Paths) -> PathBuf {
    paths.config.join("services")
}

pub(crate) fn definition_path(paths: &Paths, name: &str) -> PathBuf {
    services_dir(paths).join(format!("{name}.json"))
}

/// The passphrase file `zdrive service install --custody file` writes when
/// no `--passphrase-file` is given.
pub(crate) fn managed_passphrase_path(paths: &Paths, name: &str) -> PathBuf {
    services_dir(paths).join(format!("{name}.passphrase"))
}

/// The systemd-creds credential of an instance.
pub(crate) fn credential_path(paths: &Paths, name: &str) -> PathBuf {
    services_dir(paths).join(format!("{name}.cred"))
}

/// Creates the configuration and services directories as 0700.
pub(crate) fn ensure_services_dir(paths: &Paths) -> Result<PathBuf, String> {
    ensure_private_dir(&paths.config).map_err(|error| error.to_string())?;
    let dir = services_dir(paths);
    ensure_private_dir(&dir).map_err(|error| error.to_string())?;
    Ok(dir)
}

/// Names of every stored definition, sorted. Files that cannot name an
/// instance are skipped.
pub(crate) fn names(paths: &Paths) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(services_dir(paths)) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let file_name = entry.file_name();
            let name = file_name.to_str()?.strip_suffix(".json")?;
            validate_name(name).ok()?;
            Some(name.to_string())
        })
        .collect();
    names.sort();
    names
}

/// `[a-z0-9][a-z0-9_-]{0,62}`: the name becomes part of file names, a
/// launchd label and a systemd instance, so nothing that could traverse or
/// need escaping is accepted.
pub(crate) fn validate_name(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|&byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        });
    if valid {
        Ok(())
    } else {
        Err(format!(
            "invalid service name {name:?}: use 1-63 lowercase letters, digits, '-' or '_', starting with a letter or digit"
        ))
    }
}

fn validate_remote(remote: &str) -> Result<(), String> {
    RemoteName::parse(remote)
        .map(drop)
        .map_err(|error| error.to_string())
}

fn validate_path(label: &str, path: &Path) -> Result<(), String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("{label} {} is not valid UTF-8", path.display()))?;
    if text.chars().any(char::is_control) {
        return Err(format!(
            "{label} {text:?} must not contain control characters"
        ));
    }
    if !path.is_absolute() {
        return Err(format!("{label} {text} must be an absolute path"));
    }
    if path.parent().is_none() {
        return Err(format!("{label} must not be the root directory"));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(format!("{label} {text} must not contain '.' or '..'"));
    }
    Ok(())
}

impl Definition {
    pub(crate) fn validate(&self) -> Result<(), String> {
        validate_name(&self.name)?;
        if self.final_push_wait_secs > MAX_FINAL_PUSH_WAIT_SECS {
            return Err(format!(
                "final_push_wait_secs {} exceeds {MAX_FINAL_PUSH_WAIT_SECS}: the final upload must finish within the {STOP_TIMEOUT_SECS} s service stop timeout",
                self.final_push_wait_secs
            ));
        }
        match &self.instance {
            Instance::Encrypted {
                remote,
                encrypted_dir,
                mount_dir,
                custody,
            } => {
                if let Some(remote) = remote {
                    validate_remote(remote)?;
                }
                validate_path("encrypted_dir", encrypted_dir)?;
                validate_path("mount_dir", mount_dir)?;
                crate::ensure_disjoint_paths(encrypted_dir, mount_dir)?;
                if let Custody::File(file) = custody {
                    validate_path("passphrase_file", file)?;
                    if file.starts_with(encrypted_dir) || file.starts_with(mount_dir) {
                        return Err(format!(
                            "passphrase_file {} must live outside the encrypted store and the mount",
                            file.display()
                        ));
                    }
                }
            }
            Instance::Plain { remote, local_dir } => {
                validate_remote(remote)?;
                validate_path("local_dir", local_dir)?;
            }
        }
        Ok(())
    }

    fn from_file(file: DefinitionFile) -> Result<Self, String> {
        if file.format != FORMAT {
            return Err(format!("format is {:?}, expected {FORMAT:?}", file.format));
        }
        if file.version != VERSION {
            return Err(if file.version > VERSION {
                format!(
                    "version {} was written by a newer zerotrust-drive; upgrade zdrive",
                    file.version
                )
            } else {
                format!("unsupported version {}", file.version)
            });
        }
        let instance = match file.mode.as_str() {
            MODE_ENCRYPTED => {
                if file.local_dir.is_some() {
                    return Err("local_dir is valid only in plain mode".to_string());
                }
                let encrypted_dir = file
                    .encrypted_dir
                    .ok_or("encrypted mode needs encrypted_dir")?;
                let mount_dir = file.mount_dir.ok_or("encrypted mode needs mount_dir")?;
                let custody = match (file.custody.as_str(), file.passphrase_file) {
                    (CUSTODY_SYSTEMD_CREDS, None) => Custody::SystemdCreds,
                    (CUSTODY_SYSTEMD_CREDS, Some(_)) => {
                        return Err(
                            "passphrase_file must be null with systemd-creds custody".to_string()
                        );
                    }
                    (CUSTODY_FILE, Some(path)) => Custody::File(path),
                    (CUSTODY_FILE, None) => {
                        return Err("file custody needs passphrase_file".to_string());
                    }
                    (other, _) => {
                        return Err(format!(
                            "custody {other:?} is not valid in encrypted mode; use \"systemd-creds\" or \"file\""
                        ));
                    }
                };
                Instance::Encrypted {
                    remote: file.remote,
                    encrypted_dir,
                    mount_dir,
                    custody,
                }
            }
            MODE_PLAIN => {
                if file.encrypted_dir.is_some() || file.mount_dir.is_some() {
                    return Err(
                        "encrypted_dir and mount_dir are valid only in encrypted mode".to_string(),
                    );
                }
                if file.passphrase_file.is_some() {
                    return Err("passphrase_file is valid only in encrypted mode".to_string());
                }
                if file.custody != CUSTODY_NONE {
                    return Err(format!(
                        "custody must be \"none\" in plain mode, not {:?}",
                        file.custody
                    ));
                }
                Instance::Plain {
                    remote: file.remote.ok_or("plain mode needs remote")?,
                    local_dir: file.local_dir.ok_or("plain mode needs local_dir")?,
                }
            }
            other => {
                return Err(format!(
                    "mode {other:?} is neither \"encrypted\" nor \"plain\""
                ));
            }
        };
        let definition = Self {
            name: file.name,
            instance,
            final_push_wait_secs: file.final_push_wait_secs,
        };
        definition.validate()?;
        Ok(definition)
    }

    fn to_file(&self) -> DefinitionFile {
        let mut file = DefinitionFile {
            format: FORMAT.to_string(),
            version: VERSION,
            name: self.name.clone(),
            mode: String::new(),
            remote: None,
            encrypted_dir: None,
            mount_dir: None,
            local_dir: None,
            custody: CUSTODY_NONE.to_string(),
            passphrase_file: None,
            final_push_wait_secs: self.final_push_wait_secs,
        };
        match &self.instance {
            Instance::Encrypted {
                remote,
                encrypted_dir,
                mount_dir,
                custody,
            } => {
                file.mode = MODE_ENCRYPTED.to_string();
                file.remote = remote.clone();
                file.encrypted_dir = Some(encrypted_dir.clone());
                file.mount_dir = Some(mount_dir.clone());
                match custody {
                    Custody::SystemdCreds => file.custody = CUSTODY_SYSTEMD_CREDS.to_string(),
                    Custody::File(path) => {
                        file.custody = CUSTODY_FILE.to_string();
                        file.passphrase_file = Some(path.clone());
                    }
                }
            }
            Instance::Plain { remote, local_dir } => {
                file.mode = MODE_PLAIN.to_string();
                file.remote = Some(remote.clone());
                file.local_dir = Some(local_dir.clone());
            }
        }
        file
    }

    /// Parses and validates the JSON form.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        let file: DefinitionFile =
            serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        Self::from_file(file)
    }

    pub(crate) fn to_json(&self) -> Result<String, String> {
        self.validate()?;
        let mut text = serde_json::to_string_pretty(&self.to_file())
            .map_err(|error| format!("cannot serialize the service definition: {error}"))?;
        text.push('\n');
        Ok(text)
    }

    pub(crate) fn load(paths: &Paths, name: &str) -> Result<Self, String> {
        validate_name(name)?;
        let path = definition_path(paths, name);
        let bytes = read_private_file(&path, MAX_DEFINITION_FILE)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| {
                format!(
                    "no service instance named {name}: {} does not exist; create it with `zdrive service install --name {name} --mode ...`",
                    path.display()
                )
            })?;
        let definition = Self::parse(&bytes)
            .map_err(|error| format!("invalid service definition {}: {error}", path.display()))?;
        if definition.name != name {
            return Err(format!(
                "invalid service definition {}: it names instance {:?}, not {name:?}",
                path.display(),
                definition.name
            ));
        }
        Ok(definition)
    }

    /// Validates and atomically writes the definition; returns its path.
    pub(crate) fn save(&self, paths: &Paths) -> Result<PathBuf, String> {
        let json = self.to_json()?;
        ensure_services_dir(paths)?;
        let path = definition_path(paths, &self.name);
        write_private_file(&path, json.as_bytes()).map_err(|error| error.to_string())?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;
    use crate::service::Platform;
    use crate::service::testing::host;
    use std::os::unix::fs::PermissionsExt;

    fn encrypted(custody: Custody) -> Definition {
        Definition {
            name: "encrypted".to_string(),
            instance: Instance::Encrypted {
                remote: Some("home".to_string()),
                encrypted_dir: PathBuf::from("/abs/store"),
                mount_dir: PathBuf::from("/abs/mount"),
                custody,
            },
            final_push_wait_secs: 60,
        }
    }

    fn json(overrides: &[(&str, serde_json::Value)]) -> Vec<u8> {
        let mut value = serde_json::json!({
            "format": "zerotrust-drive-service", "version": 1, "name": "encrypted",
            "mode": "encrypted", "remote": "home", "encrypted_dir": "/abs/store",
            "mount_dir": "/abs/mount", "local_dir": null, "custody": "systemd-creds",
            "passphrase_file": null, "final_push_wait_secs": 60
        });
        for (key, replacement) in overrides {
            value[*key] = replacement.clone();
        }
        serde_json::to_vec(&value).unwrap()
    }

    fn refusal(overrides: &[(&str, serde_json::Value)]) -> String {
        Definition::parse(&json(overrides)).unwrap_err()
    }

    #[test]
    fn service_definition_parses_the_documented_example() {
        assert_eq!(
            Definition::parse(&json(&[])).unwrap(),
            encrypted(Custody::SystemdCreds)
        );
    }

    #[test]
    fn service_definition_round_trips_every_shape() {
        let dir = TestDir::new("service-definition");
        let host = host(&dir, Platform::Linux);
        let shapes = [
            encrypted(Custody::SystemdCreds),
            encrypted(Custody::File(PathBuf::from("/abs/secret"))),
            Definition {
                name: "local-only".to_string(),
                instance: Instance::Encrypted {
                    remote: None,
                    encrypted_dir: PathBuf::from("/abs/store"),
                    mount_dir: PathBuf::from("/abs/mount"),
                    custody: Custody::File(PathBuf::from("/abs/secret")),
                },
                final_push_wait_secs: 0,
            },
            Definition {
                name: "photos_2".to_string(),
                instance: Instance::Plain {
                    remote: "home".to_string(),
                    local_dir: PathBuf::from("/abs/photos"),
                },
                final_push_wait_secs: MAX_FINAL_PUSH_WAIT_SECS,
            },
        ];
        for shape in shapes {
            let path = shape.save(&host.paths).unwrap();
            assert_eq!(path, definition_path(&host.paths, &shape.name));
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let services = std::fs::metadata(services_dir(&host.paths)).unwrap();
            assert_eq!(services.permissions().mode() & 0o777, 0o700);
            assert_eq!(Definition::load(&host.paths, &shape.name).unwrap(), shape);
        }
        assert_eq!(
            names(&host.paths),
            ["encrypted", "local-only", "photos_2"].map(str::to_string)
        );
    }

    #[test]
    fn service_definition_json_has_the_documented_fields() {
        let text = encrypted(Custody::SystemdCreds).to_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            value,
            serde_json::from_slice::<serde_json::Value>(&json(&[])).unwrap()
        );
        assert!(text.ends_with("}\n"));
    }

    #[test]
    fn service_definition_refuses_wrong_format_version_and_unknown_fields() {
        use serde_json::json as j;
        assert!(refusal(&[("format", j!("other"))]).contains("expected"));
        assert!(refusal(&[("version", j!(2))]).contains("newer zerotrust-drive"));
        assert!(refusal(&[("version", j!(0))]).contains("unsupported version"));
        assert!(refusal(&[("extra", j!(true))]).contains("unknown field"));
        assert!(refusal(&[("mode", j!("mirror"))]).contains("neither"));
        let mut missing: serde_json::Value = serde_json::from_slice(&json(&[])).unwrap();
        missing
            .as_object_mut()
            .unwrap()
            .remove("final_push_wait_secs");
        let error = Definition::parse(&serde_json::to_vec(&missing).unwrap()).unwrap_err();
        assert!(error.contains("final_push_wait_secs"), "{error}");
    }

    #[test]
    fn service_definition_refuses_inconsistent_encrypted_shapes() {
        use serde_json::json as j;
        let null = serde_json::Value::Null;
        assert!(refusal(&[("encrypted_dir", null.clone())]).contains("needs encrypted_dir"));
        assert!(refusal(&[("mount_dir", null.clone())]).contains("needs mount_dir"));
        assert!(refusal(&[("local_dir", j!("/abs/l"))]).contains("only in plain mode"));
        assert!(refusal(&[("custody", j!("none"))]).contains("not valid in encrypted mode"));
        assert!(refusal(&[("custody", j!("file"))]).contains("needs passphrase_file"));
        assert!(refusal(&[("passphrase_file", j!("/abs/p"))]).contains("must be null"));
        assert!(refusal(&[("remote", j!("Bad Name"))]).contains("invalid remote name"));
        assert!(refusal(&[("encrypted_dir", j!("rel/store"))]).contains("absolute"));
        assert!(refusal(&[("mount_dir", j!("/abs/../mount"))]).contains("'..'"));
        assert!(refusal(&[("mount_dir", j!("/"))]).contains("root directory"));
        assert!(refusal(&[("mount_dir", j!("/abs/mo\nunt"))]).contains("control"));
        assert!(refusal(&[("mount_dir", j!("/abs/store/inner"))]).contains("non-nested"));
        assert!(
            refusal(&[
                ("custody", j!("file")),
                ("passphrase_file", j!("/abs/mount/p"))
            ])
            .contains("outside the encrypted store")
        );
        assert!(
            refusal(&[("custody", j!("file")), ("passphrase_file", j!("p"))]).contains("absolute")
        );
        assert!(refusal(&[("final_push_wait_secs", j!(76))]).contains("stop timeout"));
        assert!(refusal(&[("name", j!("Upper"))]).contains("invalid service name"));
    }

    #[test]
    fn service_definition_refuses_inconsistent_plain_shapes() {
        use serde_json::json as j;
        let null = serde_json::Value::Null;
        let plain = |extra: &[(&str, serde_json::Value)]| {
            let mut overrides = vec![
                ("mode", j!("plain")),
                ("encrypted_dir", null.clone()),
                ("mount_dir", null.clone()),
                ("local_dir", j!("/abs/folder")),
                ("custody", j!("none")),
            ];
            overrides.extend(extra.iter().cloned());
            Definition::parse(&json(&overrides))
        };
        assert!(plain(&[]).is_ok());
        let error = |extra: &[(&str, serde_json::Value)]| plain(extra).unwrap_err();
        assert!(error(&[("remote", null.clone())]).contains("needs remote"));
        assert!(error(&[("local_dir", null.clone())]).contains("needs local_dir"));
        assert!(error(&[("custody", j!("file"))]).contains("must be \"none\""));
        assert!(error(&[("passphrase_file", j!("/abs/p"))]).contains("only in encrypted"));
        assert!(error(&[("mount_dir", j!("/abs/m"))]).contains("only in encrypted"));
        assert!(error(&[("local_dir", j!("folder"))]).contains("absolute"));
    }

    #[test]
    fn service_names_are_validated() {
        for valid in ["a", "0", "home", "my-drive_2", &"a".repeat(63)] {
            assert!(validate_name(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "-a",
            "_a",
            "A",
            "a.b",
            "a/b",
            "..",
            "a b",
            &"a".repeat(64),
        ] {
            assert!(validate_name(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn service_definition_load_refuses_missing_mismatched_and_public_files() {
        let dir = TestDir::new("service-definition-load");
        let host = host(&dir, Platform::MacOs);
        let error = Definition::load(&host.paths, "absent").unwrap_err();
        assert!(
            error.contains("zdrive service install --name absent"),
            "{error}"
        );
        assert!(Definition::load(&host.paths, "../x").is_err());

        ensure_services_dir(&host.paths).unwrap();
        let path = definition_path(&host.paths, "other");
        write_private_file(&path, &json(&[])).unwrap();
        let error = Definition::load(&host.paths, "other").unwrap_err();
        assert!(error.contains("names instance"), "{error}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = Definition::load(&host.paths, "other").unwrap_err();
        assert!(error.contains("chmod 600"), "{error}");
    }
}
