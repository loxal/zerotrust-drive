// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Per-remote configuration and the sealed provider credential.
//!
//! Configuration lives outside every store and every synced folder:
//! `$XDG_CONFIG_HOME/zerotrust-drive/remotes/<name>.json` (0600, in a 0700
//! directory). The refresh token of an encrypted remote is sealed with
//! XChaCha20-Poly1305 under an Argon2id key derived from the store
//! passphrase, so neither the file nor a backup of it grants Drive access on
//! its own. A plain remote has no passphrase; its token sits unsealed in a
//! private `remotes/<name>.token` file, as rclone keeps its own.

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
/// Version 2 adds the client kind, scope and mode. Version 1 files (0.17)
/// still load: they are bring-your-own, full-scope, encrypted remotes.
pub(crate) const CONFIG_VERSION: u32 = 2;
const CONFIG_VERSION_V1: u32 = 1;
pub(crate) const PROVIDER_GOOGLE_DRIVE: &str = "google-drive";
/// Full Drive access, for bring-your-own clients.
pub(crate) const SCOPE_DRIVE: &str = "https://www.googleapis.com/auth/drive";
/// Only files this app created: the scope of the bundled clients.
pub(crate) const SCOPE_DRIVE_FILE: &str = "https://www.googleapis.com/auth/drive.file";
const MAX_CONFIG_FILE: u64 = 64 << 10;
const TOKEN_AAD_DOMAIN: &[u8] = b"zerotrust-drive token vault v1\0";
const MAX_REFRESH_TOKEN: usize = 4096;

/// Which OAuth client issued a remote's refresh token. A refresh must use
/// the same client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ClientKind {
    /// A Desktop client JSON the user created (`client_file`).
    #[default]
    Byo,
    /// The zdrive Desktop client compiled into release builds.
    BundledDesktop,
    /// The zdrive "TVs and Limited Input devices" client, for the device flow.
    BundledDevice,
}

impl ClientKind {
    pub(crate) fn bundled(self) -> bool {
        self != ClientKind::Byo
    }
}

/// What the remote folder holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RemoteMode {
    /// The encrypted store replica: Google only receives ciphertext.
    #[default]
    Encrypted,
    /// Unencrypted files, mirrored by `zdrive sync`. Google can read them.
    Plain,
}

impl RemoteMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RemoteMode::Encrypted => "encrypted",
            RemoteMode::Plain => "plain",
        }
    }
}

fn default_scope() -> String {
    SCOPE_DRIVE.to_string()
}

/// Where configuration, per-remote sync state and local data live.
#[derive(Clone, Debug)]
pub(crate) struct Paths {
    pub(crate) config: PathBuf,
    pub(crate) state: PathBuf,
    /// `$XDG_DATA_HOME/zerotrust-drive`: default stores and local trash.
    pub(crate) data: PathBuf,
}

impl Paths {
    pub(crate) fn from_env() -> Result<Self, RemoteError> {
        Self::resolve(|name| std::env::var_os(name))
    }

    /// XDG base directories; relative values are invalid by the
    /// specification and ignored.
    pub(crate) fn resolve(var: impl Fn(&str) -> Option<OsString>) -> Result<Self, RemoteError> {
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
        let data = match absolute("XDG_DATA_HOME") {
            Some(path) => path,
            None => home()?.join(".local").join("share"),
        };
        Ok(Self {
            config: config.join(APP_DIR),
            state: state.join(APP_DIR),
            data: data.join(APP_DIR),
        })
    }

    /// The store a bare `zdrive` mounts without `--encrypted-dir`.
    pub(crate) fn default_store(&self) -> PathBuf {
        self.data.join("store")
    }

    pub(crate) fn default_client_file(&self) -> PathBuf {
        self.config.join(CLIENT_FILE_NAME)
    }

    pub(crate) fn remote_config(&self, name: &RemoteName) -> PathBuf {
        self.config
            .join("remotes")
            .join(format!("{}.json", name.as_str()))
    }

    /// The unsealed refresh token of a plain-mode remote (0600). Plain
    /// mode has no passphrase to seal it with, like rclone's default.
    pub(crate) fn remote_token(&self, name: &RemoteName) -> PathBuf {
        self.config
            .join("remotes")
            .join(format!("{}.token", name.as_str()))
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

/// The OAuth client and scope that issued a remote's refresh token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Issuer {
    pub(crate) client: ClientKind,
    /// Absolute path of a bring-your-own client JSON; `None` when bundled.
    pub(crate) client_file: Option<PathBuf>,
    pub(crate) scope: String,
}

impl Issuer {
    pub(crate) fn byo(client_file: &Path) -> Self {
        Self {
            client: ClientKind::Byo,
            client_file: Some(client_file.to_path_buf()),
            scope: SCOPE_DRIVE.to_string(),
        }
    }

    pub(crate) fn bundled(client: ClientKind) -> Self {
        Self {
            client,
            client_file: None,
            scope: SCOPE_DRIVE_FILE.to_string(),
        }
    }
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

fn is_full_scope(scope: &str) -> bool {
    scope == SCOPE_DRIVE
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
    #[serde(default, skip_serializing_if = "is_default")]
    pub(crate) client: ClientKind,
    /// Absolute path of the bring-your-own OAuth client file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) client_file: Option<PathBuf>,
    #[serde(default = "default_scope", skip_serializing_if = "is_full_scope")]
    pub(crate) scope: String,
    #[serde(default, skip_serializing_if = "is_default")]
    pub(crate) mode: RemoteMode,
    /// The refresh token sealed under the store passphrase (encrypted mode).
    /// Plain remotes keep theirs in [`Paths::remote_token`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) token: Option<SealedToken>,
}

impl RemoteConfig {
    /// An encrypted remote whose credential is sealed under the store
    /// passphrase.
    pub(crate) fn encrypted(
        name: &RemoteName,
        account: &str,
        folder_id: &str,
        folder_hint: &str,
        issuer: &Issuer,
        token: SealedToken,
    ) -> Self {
        Self::build(
            name,
            account,
            folder_id,
            folder_hint,
            issuer,
            RemoteMode::Encrypted,
            Some(token),
        )
    }

    /// A plain remote; its credential lives in the token file.
    pub(crate) fn plain(
        name: &RemoteName,
        account: &str,
        folder_id: &str,
        folder_hint: &str,
        issuer: &Issuer,
    ) -> Self {
        Self::build(
            name,
            account,
            folder_id,
            folder_hint,
            issuer,
            RemoteMode::Plain,
            None,
        )
    }

    fn build(
        name: &RemoteName,
        account: &str,
        folder_id: &str,
        folder_hint: &str,
        issuer: &Issuer,
        mode: RemoteMode,
        token: Option<SealedToken>,
    ) -> Self {
        let mut config = Self {
            format: CONFIG_FORMAT.to_string(),
            version: CONFIG_VERSION,
            name: name.as_str().to_string(),
            provider: PROVIDER_GOOGLE_DRIVE.to_string(),
            account: account.to_string(),
            folder_id: folder_id.to_string(),
            folder_hint: folder_hint.to_string(),
            client: issuer.client,
            client_file: issuer.client_file.clone(),
            scope: issuer.scope.clone(),
            mode,
            token,
        };
        config.version = config.required_version();
        config
    }

    pub(crate) fn issuer(&self) -> Issuer {
        Issuer {
            client: self.client,
            client_file: self.client_file.clone(),
            scope: self.scope.clone(),
        }
    }

    /// Version 1 when 0.17 can read it (bring-your-own, full scope,
    /// encrypted), so a rollback keeps working; version 2 otherwise.
    fn required_version(&self) -> u32 {
        if self.client == ClientKind::Byo
            && self.scope == SCOPE_DRIVE
            && self.mode == RemoteMode::Encrypted
        {
            CONFIG_VERSION_V1
        } else {
            CONFIG_VERSION
        }
    }

    fn validate(&self, expected: &RemoteName) -> Result<(), String> {
        if self.format != CONFIG_FORMAT {
            return Err("is not a zerotrust-drive remote configuration".to_string());
        }
        if self.version != CONFIG_VERSION_V1 && self.version != CONFIG_VERSION {
            return Err(format!(
                "has configuration version {} (expected {CONFIG_VERSION_V1} or {CONFIG_VERSION}); upgrade zdrive",
                self.version
            ));
        }
        if self.version == CONFIG_VERSION_V1 && self.required_version() != CONFIG_VERSION_V1 {
            return Err("is version 1 but uses version 2 settings".to_string());
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
        match (self.client, &self.client_file) {
            (ClientKind::Byo, None) => {
                return Err("names no OAuth client file".to_string());
            }
            (ClientKind::Byo, Some(file)) if !file.is_absolute() => {
                return Err("names a relative OAuth client file".to_string());
            }
            (ClientKind::Byo, Some(_)) => {}
            (_, Some(_)) => {
                return Err("names both a bundled client and a client file".to_string());
            }
            (_, None) => {}
        }
        match self.scope.as_str() {
            SCOPE_DRIVE if self.client.bundled() => {
                return Err("asks for full Drive access with a bundled client".to_string());
            }
            SCOPE_DRIVE | SCOPE_DRIVE_FILE => {}
            other => return Err(format!("uses unsupported scope {other:?}")),
        }
        match (self.mode, &self.token) {
            (RemoteMode::Encrypted, None) => {
                return Err("holds no sealed credential".to_string());
            }
            (RemoteMode::Plain, Some(_)) => {
                return Err("is plain but holds a sealed credential".to_string());
            }
            _ => {}
        }
        Ok(())
    }

    /// The refresh token: unsealed with the store passphrase for an
    /// encrypted remote, read from the private token file for a plain one.
    pub(crate) fn refresh_token(
        &self,
        paths: &Paths,
        name: &RemoteName,
        passphrase: Option<&str>,
    ) -> Result<String, RemoteError> {
        match (&self.token, self.mode) {
            (Some(token), RemoteMode::Encrypted) => {
                let passphrase = passphrase.ok_or_else(|| {
                    RemoteError::Local(format!(
                        "remote {name} is encrypted: its credential needs the store passphrase"
                    ))
                })?;
                token.unseal(name, passphrase)
            }
            _ => load_plain_token(paths, name),
        }
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

    /// Atomically writes the configuration with mode 0600, as version 1
    /// whenever 0.17 can read it.
    pub(crate) fn save(&self, paths: &Paths) -> Result<(), RemoteError> {
        let name = RemoteName::parse(&self.name)?;
        let mut config = self.clone();
        config.version = config.required_version();
        config.validate(&name).map_err(RemoteError::Local)?;
        ensure_private_dir(&paths.config)?;
        let directory = paths.config.join("remotes");
        ensure_private_dir(&directory)?;
        let mut bytes = serde_json::to_vec_pretty(&config).map_err(|error| {
            RemoteError::Local(format!("serialize remote configuration: {error}"))
        })?;
        bytes.push(b'\n');
        write_private_file(&paths.remote_config(&name), &bytes)
    }
}

/// Stores a plain remote's refresh token in its private token file.
pub(crate) fn save_plain_token(
    paths: &Paths,
    name: &RemoteName,
    refresh_token: &str,
) -> Result<(), RemoteError> {
    if refresh_token.is_empty()
        || refresh_token.len() > MAX_REFRESH_TOKEN
        || refresh_token.contains(['\n', '\r'])
    {
        return Err(RemoteError::Local(
            "refusing an implausible refresh token".to_string(),
        ));
    }
    ensure_private_dir(&paths.config)?;
    ensure_private_dir(&paths.config.join("remotes"))?;
    let mut bytes = refresh_token.as_bytes().to_vec();
    bytes.push(b'\n');
    write_private_file(&paths.remote_token(name), &bytes)
}

/// Reads a plain remote's refresh token; the file must be private.
pub(crate) fn load_plain_token(paths: &Paths, name: &RemoteName) -> Result<String, RemoteError> {
    let path = paths.remote_token(name);
    let bytes = read_private_file(&path, MAX_REFRESH_TOKEN as u64 + 2)?.ok_or_else(|| {
        RemoteError::NotFound(format!(
            "remote {name} has no credential at {}; run `zdrive remote auth --remote {name} --plain` again",
            path.display()
        ))
    })?;
    let text = String::from_utf8(bytes)
        .map_err(|_| RemoteError::Local(format!("{} is not text", path.display())))?;
    let token = text.trim_end_matches(['\n', '\r']);
    if token.is_empty() || token.len() > MAX_REFRESH_TOKEN || token.contains(['\n', '\r']) {
        return Err(RemoteError::Local(format!(
            "{} holds an implausible credential",
            path.display()
        )));
    }
    Ok(token.to_string())
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
            data: root.join("data"),
        }
    }

    const CLIENT_FILE: &str = "/home/tester/.config/zerotrust-drive/google-oauth-client.json";

    fn sample(name: &RemoteName) -> RemoteConfig {
        let token =
            SealedToken::seal(name, "vault passphrase", "1//refresh-token", test_kdf()).unwrap();
        RemoteConfig::encrypted(
            name,
            "tester@example.com",
            "0AbCdEfGhIjKlMnOp",
            "My Drive/zerotrust-drive",
            &Issuer::byo(Path::new(CLIENT_FILE)),
            token,
        )
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn json_of(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
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
        assert_eq!(
            paths.default_store(),
            Path::new("/home/tester/.local/share/zerotrust-drive/store")
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
            loaded
                .refresh_token(&paths, &name, Some("vault passphrase"))
                .unwrap(),
            "1//refresh-token"
        );
        // A bring-your-own encrypted remote stays readable by 0.17.
        let written = json_of(&paths.remote_config(&name));
        assert_eq!(written["version"], 1);
        for absent in ["client", "scope", "mode"] {
            assert!(written.get(absent).is_none(), "{absent}");
        }
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
        value["version"] = serde_json::json!(3);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let refused = RemoteConfig::load(&paths, &name).unwrap_err().to_string();
        assert!(refused.contains("upgrade zdrive"), "{refused}");
        // Version 1 cannot carry version 2 settings.
        value["version"] = serde_json::json!(1);
        value["mode"] = serde_json::json!("plain");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let refused = RemoteConfig::load(&paths, &name).unwrap_err().to_string();
        assert!(refused.contains("version 2 settings"), "{refused}");

        // A group-accessible configuration directory is refused on save.
        std::fs::set_permissions(&paths.config, std::fs::Permissions::from_mode(0o755)).unwrap();
        let refused = sample(&name).save(&paths).unwrap_err().to_string();
        assert!(refused.contains("chmod 700"), "{refused}");
    }

    #[test]
    fn a_configuration_written_by_0_17_loads_as_byo_full_scope_encrypted() {
        let root = TestDir::new("config-0-17");
        let paths = paths(root.path());
        let name = RemoteName::parse("gdrive-test").unwrap();
        let token = SealedToken::seal(&name, "vault passphrase", "1//legacy", test_kdf()).unwrap();
        // Exactly the key set 0.17.0 writes.
        let legacy = serde_json::json!({
            "format": CONFIG_FORMAT,
            "version": 1,
            "name": "gdrive-test",
            "provider": "google-drive",
            "account": "tester@example.com",
            "folder_id": "1x04nI2XZuRe1Y_wgIpMBi6mBRe1QOFvm",
            "folder_hint": "My Drive/zerotrust-drive-test",
            "client_file": CLIENT_FILE,
            "token": serde_json::to_value(&token).unwrap(),
        });
        ensure_private_dir(&paths.config.join("remotes")).unwrap();
        std::fs::set_permissions(&paths.config, std::fs::Permissions::from_mode(0o700)).unwrap();
        write_private(
            &paths.remote_config(&name),
            &serde_json::to_vec_pretty(&legacy).unwrap(),
        );
        let loaded = RemoteConfig::load(&paths, &name).unwrap();
        assert_eq!(loaded.issuer(), Issuer::byo(Path::new(CLIENT_FILE)));
        assert_eq!(loaded.mode, RemoteMode::Encrypted);
        assert_eq!(
            loaded
                .refresh_token(&paths, &name, Some("vault passphrase"))
                .unwrap(),
            "1//legacy"
        );
        assert!(loaded.refresh_token(&paths, &name, None).is_err());
        // Saving it again changes nothing 0.17 depends on.
        loaded.save(&paths).unwrap();
        assert_eq!(json_of(&paths.remote_config(&name)), legacy);
    }

    #[test]
    fn bundled_and_plain_remotes_are_version_2_and_validated() {
        let root = TestDir::new("config-v2");
        let paths = paths(root.path());
        let name = RemoteName::parse("zdrive").unwrap();
        let token = SealedToken::seal(&name, "vault passphrase", "1//bundled", test_kdf()).unwrap();
        let bundled = RemoteConfig::encrypted(
            &name,
            "tester@example.com",
            "0AbCdEfGhIjKlMnOp",
            "My Drive/ZeroTrust Drive",
            &Issuer::bundled(ClientKind::BundledDevice),
            token,
        );
        bundled.save(&paths).unwrap();
        let written = json_of(&paths.remote_config(&name));
        assert_eq!(written["version"], 2);
        assert_eq!(written["client"], "bundled-device");
        assert_eq!(written["scope"], SCOPE_DRIVE_FILE);
        assert!(written.get("client_file").is_none());
        let loaded = RemoteConfig::load(&paths, &name).unwrap();
        assert_eq!(loaded.issuer(), Issuer::bundled(ClientKind::BundledDevice));

        let plain = RemoteConfig::plain(
            &name,
            "tester@example.com",
            "0AbCdEfGhIjKlMnOp",
            "My Drive/ZeroTrust Drive (plain)",
            &Issuer::bundled(ClientKind::BundledDesktop),
        );
        plain.save(&paths).unwrap();
        let written = json_of(&paths.remote_config(&name));
        assert_eq!(written["mode"], "plain");
        assert!(written.get("token").is_none());
        let loaded = RemoteConfig::load(&paths, &name).unwrap();
        assert_eq!(loaded.mode, RemoteMode::Plain);
        assert!(matches!(
            loaded.refresh_token(&paths, &name, None),
            Err(RemoteError::NotFound(message)) if message.contains("--plain")
        ));

        // Each inconsistent combination is refused before it is written.
        let mut cases: Vec<(RemoteConfig, &str)> = Vec::new();
        let mut full_bundled = plain.clone();
        full_bundled.scope = SCOPE_DRIVE.to_string();
        cases.push((full_bundled, "full Drive access"));
        let mut both = plain.clone();
        both.client_file = Some(PathBuf::from(CLIENT_FILE));
        cases.push((both, "both a bundled client"));
        let mut byo_without = plain.clone();
        byo_without.client = ClientKind::Byo;
        cases.push((byo_without, "no OAuth client file"));
        let mut odd_scope = plain.clone();
        odd_scope.scope = "https://www.googleapis.com/auth/drive.readonly".to_string();
        cases.push((odd_scope, "unsupported scope"));
        let mut sealed_plain = plain.clone();
        sealed_plain.token = bundled.token.clone();
        cases.push((sealed_plain, "plain but holds"));
        let mut unsealed = bundled.clone();
        unsealed.token = None;
        cases.push((unsealed, "no sealed credential"));
        for (config, expected) in cases {
            let refused = config.save(&paths).unwrap_err().to_string();
            assert!(refused.contains(expected), "{expected}: {refused}");
        }
    }

    #[test]
    fn plain_tokens_live_in_a_private_single_line_file() {
        let root = TestDir::new("config-plain-token");
        let paths = paths(root.path());
        let name = RemoteName::parse("plain").unwrap();
        for invalid in ["", "two\nlines", &"x".repeat(MAX_REFRESH_TOKEN + 1)] {
            assert!(save_plain_token(&paths, &name, invalid).is_err());
        }
        save_plain_token(&paths, &name, "1//plain").unwrap();
        let path = paths.remote_token(&name);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(load_plain_token(&paths, &name).unwrap(), "1//plain");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let refused = load_plain_token(&paths, &name).unwrap_err().to_string();
        assert!(refused.contains("chmod 600"), "{refused}");
        write_private(&path, b"one\ntwo\n");
        assert!(load_plain_token(&paths, &name).is_err());
    }
}
