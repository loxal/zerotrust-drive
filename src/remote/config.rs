// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Per-remote configuration and the sealed provider credential.
//!
//! Configuration lives outside every store and every synced folder:
//! `$XDG_CONFIG_HOME/zerotrust-drive/remotes/<name>.json` (0600, in a 0700
//! directory). The refresh token inside it is sealed with XChaCha20-Poly1305
//! under an Argon2id key derived from the store passphrase, so neither the
//! file nor a backup of it grants Drive access on its own.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::format::valid_file_id;
use super::{
    RemoteError, ensure_private_dir, hex, read_private_file, unhex_vec, write_private_file,
};
use crate::crypto::{KdfParams, decrypt_bytes_owned, encrypt_bytes, try_derive_key};

const APP_DIR: &str = "zerotrust-drive";
pub(crate) const CLIENT_FILE_NAME: &str = "google-oauth-client.json";
pub(crate) const CONFIG_FORMAT: &str = "zerotrust-drive-remote-config";
pub(crate) const CONFIG_VERSION: u32 = 1;
pub(crate) const PROVIDER_GOOGLE_DRIVE: &str = "google-drive";
const MAX_CONFIG_FILE: u64 = 64 << 10;
const TOKEN_AAD_DOMAIN: &[u8] = b"zerotrust-drive token vault v1\0";
const MAX_REFRESH_TOKEN: usize = 4096;

/// Where configuration and per-remote sync state live.
#[derive(Clone, Debug)]
pub(crate) struct Paths {
    pub(crate) config: PathBuf,
    pub(crate) state: PathBuf,
}

impl Paths {
    pub(crate) fn from_env() -> Result<Self, RemoteError> {
        Self::resolve(|name| std::env::var_os(name))
    }

    /// XDG base directories; relative values are invalid by the
    /// specification and ignored.
    fn resolve(var: impl Fn(&str) -> Option<OsString>) -> Result<Self, RemoteError> {
        let absolute = |name: &str| {
            var(name)
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        };
        let home = || {
            absolute("HOME").ok_or_else(|| {
                RemoteError::Local("HOME is not set to an absolute path".to_string())
            })
        };
        let config = match absolute("XDG_CONFIG_HOME") {
            Some(path) => path,
            None => home()?.join(".config"),
        };
        let state = match absolute("XDG_STATE_HOME") {
            Some(path) => path,
            None => home()?.join(".local").join("state"),
        };
        Ok(Self {
            config: config.join(APP_DIR),
            state: state.join(APP_DIR),
        })
    }

    pub(crate) fn default_client_file(&self) -> PathBuf {
        self.config.join(CLIENT_FILE_NAME)
    }

    pub(crate) fn remote_config(&self, name: &RemoteName) -> PathBuf {
        self.config
            .join("remotes")
            .join(format!("{}.json", name.as_str()))
    }

    pub(crate) fn remote_state(&self, name: &RemoteName) -> PathBuf {
        self.state.join("remotes").join(name.as_str())
    }

    /// Sync state of one local replica of `name`. The canonical store
    /// directory is part of the key, so two local replicas of one remote
    /// never share checkpoints or a synced head.
    pub(crate) fn replica_state(&self, name: &RemoteName, encrypted_dir: &Path) -> PathBuf {
        use sha2::{Digest, Sha256};
        use std::os::unix::ffi::OsStrExt;
        let digest = Sha256::digest(encrypted_dir.as_os_str().as_bytes());
        self.remote_state(name).join(hex(&digest[..8]))
    }
}

/// A validated remote name: `[a-z0-9][a-z0-9_-]{0,62}`. It names files, so
/// nothing that could traverse or collide is accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RemoteName(String);

impl RemoteName {
    pub(crate) fn parse(text: &str) -> Result<Self, RemoteError> {
        let bytes = text.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= 63
            && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
            && bytes.iter().all(|&byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            });
        if valid {
            Ok(Self(text.to_string()))
        } else {
            Err(RemoteError::Local(format!(
                "invalid remote name {text:?}: use 1-63 lowercase letters, digits, '-' or '_', starting with a letter or digit"
            )))
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RemoteName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A refresh token encrypted under a passphrase-derived key. The remote
/// name is authenticated as associated data, so a sealed token cannot be
/// moved to another remote's configuration.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SealedToken {
    pub(crate) kdf: KdfParams,
    ciphertext: String,
}

impl std::fmt::Debug for SealedToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SealedToken { <sealed> }")
    }
}

fn token_aad(name: &RemoteName) -> Vec<u8> {
    let mut aad = TOKEN_AAD_DOMAIN.to_vec();
    aad.extend_from_slice(name.as_str().as_bytes());
    aad
}

impl SealedToken {
    /// Seals under fresh `kdf` parameters; production passes
    /// `KdfParams::new_random()`.
    pub(crate) fn seal(
        name: &RemoteName,
        passphrase: &str,
        refresh_token: &str,
        kdf: KdfParams,
    ) -> Result<Self, RemoteError> {
        let key = try_derive_key(passphrase, &kdf).map_err(RemoteError::Local)?;
        let ciphertext = encrypt_bytes(&key, refresh_token.as_bytes(), &token_aad(name))
            .map_err(RemoteError::Local)?;
        Ok(Self {
            kdf,
            ciphertext: hex(&ciphertext),
        })
    }

    pub(crate) fn unseal(
        &self,
        name: &RemoteName,
        passphrase: &str,
    ) -> Result<String, RemoteError> {
        let key = try_derive_key(passphrase, &self.kdf).map_err(|error| {
            RemoteError::Local(format!("remote {name} credential parameters: {error}"))
        })?;
        let ciphertext = unhex_vec(&self.ciphertext).ok_or_else(|| {
            RemoteError::Local(format!("remote {name} has a malformed sealed credential"))
        })?;
        let plaintext = decrypt_bytes_owned(&key, ciphertext, &token_aad(name)).map_err(|_| {
            RemoteError::Auth(format!(
                "cannot open the Google credential of remote {name} with this passphrase (it was sealed under the passphrase used at authorization, which may since have been rotated); run `zdrive remote auth --remote {name}` again"
            ))
        })?;
        let token = String::from_utf8(plaintext)
            .map_err(|_| RemoteError::Local(format!("remote {name} credential is not text")))?;
        if token.is_empty() || token.len() > MAX_REFRESH_TOKEN {
            return Err(RemoteError::Local(format!(
                "remote {name} credential has an implausible length"
            )));
        }
        Ok(token)
    }
}

/// One configured remote.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteConfig {
    pub(crate) format: String,
    pub(crate) version: u32,
    pub(crate) name: String,
    pub(crate) provider: String,
    /// The authorized account, used as the login hint when re-authorizing.
    pub(crate) account: String,
    /// The provider folder that holds this remote's layout.
    pub(crate) folder_id: String,
    /// Human-readable location of `folder_id`, for status output only.
    pub(crate) folder_hint: String,
    /// Absolute path of the OAuth client file used for this remote.
    pub(crate) client_file: PathBuf,
    pub(crate) token: SealedToken,
}

impl RemoteConfig {
    pub(crate) fn new(
        name: &RemoteName,
        account: &str,
        folder_id: &str,
        folder_hint: &str,
        client_file: &Path,
        token: SealedToken,
    ) -> Self {
        Self {
            format: CONFIG_FORMAT.to_string(),
            version: CONFIG_VERSION,
            name: name.as_str().to_string(),
            provider: PROVIDER_GOOGLE_DRIVE.to_string(),
            account: account.to_string(),
            folder_id: folder_id.to_string(),
            folder_hint: folder_hint.to_string(),
            client_file: client_file.to_path_buf(),
            token,
        }
    }

    fn validate(&self, expected: &RemoteName) -> Result<(), String> {
        if self.format != CONFIG_FORMAT {
            return Err("is not a zerotrust-drive remote configuration".to_string());
        }
        if self.version != CONFIG_VERSION {
            return Err(format!(
                "has configuration version {} (expected {CONFIG_VERSION}); upgrade zdrive",
                self.version
            ));
        }
        if self.name != expected.as_str() {
            return Err(format!("names remote {:?}, not {expected}", self.name));
        }
        if self.provider != PROVIDER_GOOGLE_DRIVE {
            return Err(format!("uses unsupported provider {:?}", self.provider));
        }
        if !valid_file_id(&self.folder_id) {
            return Err("names an invalid folder id".to_string());
        }
        if !self.client_file.is_absolute() {
            return Err("names a relative OAuth client file".to_string());
        }
        Ok(())
    }

    /// Loads and validates `<config>/remotes/<name>.json`.
    pub(crate) fn load(paths: &Paths, name: &RemoteName) -> Result<Self, RemoteError> {
        let path = paths.remote_config(name);
        let bytes = read_private_file(&path, MAX_CONFIG_FILE)?.ok_or_else(|| {
            RemoteError::NotFound(format!(
                "remote {name} is not configured; run `zdrive remote auth --remote {name}` first"
            ))
        })?;
        let config: Self = serde_json::from_slice(&bytes).map_err(|error| {
            RemoteError::Local(format!(
                "{}: invalid remote configuration at line {} column {}",
                path.display(),
                error.line(),
                error.column()
            ))
        })?;
        config
            .validate(name)
            .map_err(|detail| RemoteError::Local(format!("{} {detail}", path.display())))?;
        Ok(config)
    }

    /// Atomically writes the configuration with mode 0600.
    pub(crate) fn save(&self, paths: &Paths) -> Result<(), RemoteError> {
        let name = RemoteName::parse(&self.name)?;
        self.validate(&name).map_err(RemoteError::Local)?;
        ensure_private_dir(&paths.config)?;
        let directory = paths.config.join("remotes");
        ensure_private_dir(&directory)?;
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|error| {
            RemoteError::Local(format!("serialize remote configuration: {error}"))
        })?;
        bytes.push(b'\n');
        write_private_file(&paths.remote_config(&name), &bytes)
    }
}

#[cfg(test)]
pub(crate) fn test_kdf() -> KdfParams {
    KdfParams {
        format_version: crate::crypto::FORMAT_VERSION,
        algorithm: "argon2id".to_string(),
        salt: vec![9; crate::crypto::SALT_LEN],
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;
    use std::os::unix::fs::PermissionsExt;

    fn paths(root: &Path) -> Paths {
        Paths {
            config: root.join("config"),
            state: root.join("state"),
        }
    }

    fn sample(name: &RemoteName) -> RemoteConfig {
        let token =
            SealedToken::seal(name, "vault passphrase", "1//refresh-token", test_kdf()).unwrap();
        RemoteConfig::new(
            name,
            "tester@example.com",
            "0AbCdEfGhIjKlMnOp",
            "My Drive/zerotrust-drive",
            Path::new("/home/tester/.config/zerotrust-drive/google-oauth-client.json"),
            token,
        )
    }

    #[test]
    fn xdg_directories_take_precedence_and_relative_values_are_ignored() {
        let lookup = |entries: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                entries
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| OsString::from(value))
            }
        };
        let paths = Paths::resolve(lookup(&[
            ("HOME", "/home/tester"),
            ("XDG_CONFIG_HOME", "/xdg/config"),
            ("XDG_STATE_HOME", "relative/state"),
        ]))
        .unwrap();
        assert_eq!(paths.config, Path::new("/xdg/config/zerotrust-drive"));
        assert_eq!(
            paths.state,
            Path::new("/home/tester/.local/state/zerotrust-drive")
        );
        assert!(Paths::resolve(lookup(&[("HOME", "relative")])).is_err());
        let name = RemoteName::parse("gdrive").unwrap();
        assert_eq!(
            paths.remote_config(&name),
            Path::new("/xdg/config/zerotrust-drive/remotes/gdrive.json")
        );
        assert_eq!(
            paths.remote_state(&name),
            Path::new("/home/tester/.local/state/zerotrust-drive/remotes/gdrive")
        );
        let first = paths.replica_state(&name, Path::new("/stores/one"));
        assert_eq!(first.parent(), Some(paths.remote_state(&name).as_path()));
        assert_eq!(first.file_name().map(|name| name.len()), Some(16));
        assert_eq!(first, paths.replica_state(&name, Path::new("/stores/one")));
        assert_ne!(first, paths.replica_state(&name, Path::new("/stores/two")));
    }

    #[test]
    fn remote_names_cannot_traverse_or_collide() {
        for valid in ["gdrive", "0", "a-b_c", &"x".repeat(63)] {
            assert!(RemoteName::parse(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "-gdrive",
            "_x",
            "GDrive",
            "a/b",
            "..",
            ".hidden",
            "a b",
            "é",
            &"x".repeat(64),
        ] {
            assert!(RemoteName::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn sealed_token_round_trips_only_with_its_passphrase_and_name() {
        let name = RemoteName::parse("gdrive").unwrap();
        let sealed = SealedToken::seal(&name, "correct", "1//refresh", test_kdf()).unwrap();
        assert!(!sealed.ciphertext.contains("refresh"));
        assert!(!format!("{sealed:?}").contains(&sealed.ciphertext));
        assert_eq!(sealed.unseal(&name, "correct").unwrap(), "1//refresh");
        assert!(matches!(
            sealed.unseal(&name, "wrong"),
            Err(RemoteError::Auth(message)) if message.contains("remote auth --remote gdrive")
        ));
        let other = RemoteName::parse("other").unwrap();
        assert!(matches!(
            sealed.unseal(&other, "correct"),
            Err(RemoteError::Auth(_))
        ));
        let mut tampered = sealed.clone();
        let last = tampered.ciphertext.pop().unwrap();
        tampered
            .ciphertext
            .push(if last == '0' { '1' } else { '0' });
        assert!(matches!(
            tampered.unseal(&name, "correct"),
            Err(RemoteError::Auth(_))
        ));
        let mut malformed = sealed;
        malformed.ciphertext.push('z');
        assert!(matches!(
            malformed.unseal(&name, "correct"),
            Err(RemoteError::Local(_))
        ));
    }

    #[test]
    fn configuration_round_trips_privately() {
        let root = TestDir::new("config-round-trip");
        let paths = paths(root.path());
        let name = RemoteName::parse("gdrive").unwrap();
        let missing = RemoteConfig::load(&paths, &name).unwrap_err();
        assert!(
            matches!(missing, RemoteError::NotFound(ref message) if message.contains("remote auth"))
        );
        sample(&name).save(&paths).unwrap();
        for (path, mode) in [
            (paths.config.clone(), 0o700),
            (paths.config.join("remotes"), 0o700),
            (paths.remote_config(&name), 0o600),
        ] {
            let actual = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(actual, mode, "{}", path.display());
        }
        let loaded = RemoteConfig::load(&paths, &name).unwrap();
        assert_eq!(loaded.account, "tester@example.com");
        assert_eq!(loaded.folder_id, "0AbCdEfGhIjKlMnOp");
        assert_eq!(
            loaded.token.unseal(&name, "vault passphrase").unwrap(),
            "1//refresh-token"
        );
        // Replacing keeps one file and no temporaries.
        sample(&name).save(&paths).unwrap();
        let entries: Vec<_> = std::fs::read_dir(paths.config.join("remotes"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![OsString::from("gdrive.json")]);
    }

    #[test]
    fn configuration_accessible_to_others_or_mismatched_is_refused() {
        let root = TestDir::new("config-refusals");
        let paths = paths(root.path());
        let name = RemoteName::parse("gdrive").unwrap();
        sample(&name).save(&paths).unwrap();
        let path = paths.remote_config(&name);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let refused = RemoteConfig::load(&paths, &name).unwrap_err().to_string();
        assert!(refused.contains("chmod 600"), "{refused}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // A configuration copied to another name does not load under it.
        let other = RemoteName::parse("other").unwrap();
        std::fs::copy(&path, paths.remote_config(&other)).unwrap();
        std::fs::set_permissions(
            paths.remote_config(&other),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let refused = RemoteConfig::load(&paths, &other).unwrap_err().to_string();
        assert!(refused.contains("names remote"), "{refused}");

        // Unknown fields and other versions fail closed.
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(RemoteConfig::load(&paths, &name).is_err());
        value.as_object_mut().unwrap().remove("unexpected");
        value["version"] = serde_json::json!(2);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let refused = RemoteConfig::load(&paths, &name).unwrap_err().to_string();
        assert!(refused.contains("upgrade zdrive"), "{refused}");

        // A group-accessible configuration directory is refused on save.
        std::fs::set_permissions(&paths.config, std::fs::Permissions::from_mode(0o755)).unwrap();
        let refused = sample(&name).save(&paths).unwrap_err().to_string();
        assert!(refused.contains("chmod 700"), "{refused}");
    }
}
