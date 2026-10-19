// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Passphrase resolution and no-echo prompting on the controlling terminal.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// Reads one secret line after showing a prompt.
pub(crate) trait SecretReader {
    fn read_secret(&mut self, prompt: &str) -> io::Result<String>;
}

/// Prompts on `/dev/tty`, so redirected standard streams do not matter.
pub(crate) struct TerminalReader {
    tty: File,
}

impl TerminalReader {
    /// `None` when the process has no controlling terminal.
    pub(crate) fn open() -> Option<Self> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()
            .map(|tty| TerminalReader { tty })
    }
}

impl SecretReader for TerminalReader {
    fn read_secret(&mut self, prompt: &str) -> io::Result<String> {
        let echo_off = EchoOff::enable(self.tty.as_raw_fd())?;
        self.tty.write_all(prompt.as_bytes())?;
        self.tty.flush()?;
        let line = read_line(&mut self.tty);
        drop(echo_off);
        let line = line?;
        String::from_utf8(line)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "passphrase is not UTF-8"))
    }
}

/// A terminal that also asks for ordinary, echoed answers.
pub(crate) trait Prompter: SecretReader {
    fn read_visible(&mut self, prompt: &str) -> io::Result<String>;
}

impl Prompter for TerminalReader {
    fn read_visible(&mut self, prompt: &str) -> io::Result<String> {
        self.tty.write_all(prompt.as_bytes())?;
        self.tty.flush()?;
        String::from_utf8(read_line(&mut self.tty)?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the answer is not UTF-8"))
    }
}

/// A yes/no question whose default is no; `unchanged` says what an
/// unreadable or unexpected answer leaves as it was.
pub(crate) fn ask_yes_no(
    prompter: &mut dyn Prompter,
    question: &str,
    unchanged: &str,
) -> Result<bool, String> {
    let answer = prompter
        .read_visible(&format!("zerotrust-drive: {question} [y/N] "))
        .map_err(|error| format!("cannot read the answer: {error}; {unchanged}"))?;
    match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(true),
        "" | "n" | "no" => Ok(false),
        other => Err(format!("unexpected answer {other:?}; {unchanged}")),
    }
}

/// The terminal settings to restore if a signal arrives mid-prompt.
static SAVED_TERMINAL: Mutex<Option<(RawFd, libc::termios)>> = Mutex::new(None);

/// Turns echo off for its lifetime. ECHONL keeps the newline visible and
/// ICANON stays on, so the line discipline still handles erase and kill.
struct EchoOff {
    fd: RawFd,
    original: libc::termios,
}

impl EchoOff {
    fn enable(fd: RawFd) -> io::Result<Self> {
        // SAFETY: termios is plain old data; tcgetattr fully initialises it.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: fd is an open descriptor and original is a live termios.
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut hidden = original;
        hidden.c_lflag &= !libc::ECHO;
        hidden.c_lflag |= libc::ECHONL;
        *SAVED_TERMINAL
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some((fd, original));
        // SAFETY: fd is an open descriptor and hidden is a valid termios.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &hidden) } != 0 {
            let error = io::Error::last_os_error();
            SAVED_TERMINAL
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            return Err(error);
        }
        Ok(EchoOff { fd, original })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        let mut saved = SAVED_TERMINAL
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // SAFETY: fd is still open (the reader outlives this guard) and
        // original came from tcgetattr.
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
        saved.take();
    }
}

/// Called by the signal thread before terminating, so an interrupted prompt
/// never leaves the terminal without echo.
pub(crate) fn restore_terminal_after_signal() {
    let saved = SAVED_TERMINAL
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some((fd, original)) = saved {
        // SAFETY: the descriptor stays open while a prompt is active,
        // original came from tcgetattr, and the buffer is a static byte.
        unsafe {
            libc::tcsetattr(fd, libc::TCSAFLUSH, &original);
            libc::write(fd, b"\n".as_ptr().cast(), 1);
        }
    }
}

fn read_line(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(line)
}

/// Where a resolved passphrase came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassphraseSource {
    Environment,
    /// `$CREDENTIALS_DIRECTORY/zdrive-passphrase`, provided by systemd.
    Credential,
    /// `--passphrase-file`.
    File,
    Argument,
    Prompt,
    /// The built-in demo passphrase: no source and no terminal, or an
    /// explicit `--allow-default-passphrase`.
    Default,
}

use crate::service::custody::CREDENTIAL_NAME;
/// The largest passphrase file or credential zdrive reads.
pub(crate) const MAX_PASSPHRASE_FILE: u64 = 4096;

/// The passphrase from a source that needs no terminal, in precedence order:
/// `ZEROTRUST_PASSPHRASE`, the systemd credential, then `--passphrase-file`.
pub(crate) fn stored_passphrase(
    passphrase_file: Option<&Path>,
) -> Result<Option<(String, PassphraseSource)>, String> {
    let credentials = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
    let from_env = std::env::var("ZEROTRUST_PASSPHRASE").ok();
    if let Some(notice) = overridden_file_notice(from_env.is_some(), passphrase_file) {
        eprintln!("{notice}");
    }
    resolve_stored(from_env, credentials.as_deref(), passphrase_file)
}

/// An explicit `--passphrase-file` that the environment overrides would
/// otherwise be ignored silently, and a different secret only shows up later
/// as an authentication failure.
fn overridden_file_notice(env_set: bool, passphrase_file: Option<&Path>) -> Option<String> {
    let path = passphrase_file.filter(|_| env_set)?;
    Some(format!(
        "zerotrust-drive: note: ZEROTRUST_PASSPHRASE is set and takes precedence; --passphrase-file {} is not read",
        path.display()
    ))
}

fn resolve_stored(
    from_env: Option<String>,
    credentials_dir: Option<&Path>,
    passphrase_file: Option<&Path>,
) -> Result<Option<(String, PassphraseSource)>, String> {
    if let Some(passphrase) = from_env {
        return Ok(Some((passphrase, PassphraseSource::Environment)));
    }
    // systemd owns the credentials directory (private, read-only, per
    // service), so only absence is tolerated: a unit may load other
    // credentials without this one.
    if let Some(directory) = credentials_dir.filter(|directory| directory.is_absolute()) {
        let path = directory.join(CREDENTIAL_NAME);
        match std::fs::File::open(&path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(MAX_PASSPHRASE_FILE + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
                let passphrase = secret_from_bytes(bytes, &path)?;
                return Ok(Some((passphrase, PassphraseSource::Credential)));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot open {}: {error}", path.display())),
        }
    }
    let Some(path) = passphrase_file else {
        return Ok(None);
    };
    let passphrase = crate::service::custody::read_passphrase_file(path)?;
    Ok(Some((passphrase, PassphraseSource::File)))
}

/// One line of UTF-8; a single trailing newline is not part of the secret.
pub(crate) fn secret_from_bytes(mut bytes: Vec<u8>, path: &Path) -> Result<String, String> {
    if bytes.len() as u64 > MAX_PASSPHRASE_FILE {
        return Err(format!(
            "{} is larger than {MAX_PASSPHRASE_FILE} bytes",
            path.display()
        ));
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.contains(&b'\n') {
        return Err(format!(
            "{} holds more than one line; it must contain only the passphrase",
            path.display()
        ));
    }
    if bytes.is_empty() {
        return Err(format!("{} holds an empty passphrase", path.display()));
    }
    String::from_utf8(bytes).map_err(|_| format!("{} is not UTF-8", path.display()))
}

/// Resolve the current passphrase. Precedence: a stored source (see
/// [`stored_passphrase`]), argument, then a terminal prompt, unless
/// `allow_default` asks for the demo passphrase. A brand-new store asks
/// twice so a typo cannot lock the data away.
pub(crate) fn resolve_current(
    stored: Option<(String, PassphraseSource)>,
    from_argument: Option<String>,
    reader: Option<&mut dyn SecretReader>,
    allow_default: bool,
    creating_store: bool,
    default: &str,
) -> Result<(String, PassphraseSource), String> {
    if let Some(stored) = stored {
        return Ok(stored);
    }
    if let Some(passphrase) = from_argument {
        return Ok((passphrase, PassphraseSource::Argument));
    }
    match reader {
        Some(reader) if !allow_default => {
            let passphrase = if creating_store {
                prompt_confirmed(
                    reader,
                    "zerotrust-drive: new drive - choose a passphrase: ",
                    "zerotrust-drive: repeat the passphrase: ",
                )?
            } else {
                prompt_once(reader, "zerotrust-drive: passphrase: ")?
            };
            Ok((passphrase, PassphraseSource::Prompt))
        }
        _ => Ok((default.to_string(), PassphraseSource::Default)),
    }
}

/// Resolve the passphrase a rekey rotates to. It is always confirmed when
/// prompted, and there is no fallback: rotation needs an explicit secret.
pub(crate) fn resolve_new(
    from_env: Option<String>,
    from_argument: Option<String>,
    reader: Option<&mut dyn SecretReader>,
) -> Result<String, String> {
    if let Some(passphrase) = from_env.or(from_argument) {
        return Ok(passphrase);
    }
    match reader {
        Some(reader) => prompt_confirmed(
            reader,
            "zerotrust-drive: new passphrase: ",
            "zerotrust-drive: repeat the new passphrase: ",
        ),
        None => Err(
            "passphrase rotation needs a new passphrase: set ZEROTRUST_NEW_PASSPHRASE or run from a terminal to be prompted"
                .to_string(),
        ),
    }
}

fn prompt_once(reader: &mut dyn SecretReader, prompt: &str) -> Result<String, String> {
    reader
        .read_secret(prompt)
        .map_err(|error| format!("cannot read the passphrase from the terminal: {error}"))
}

fn prompt_confirmed(
    reader: &mut dyn SecretReader,
    prompt: &str,
    confirmation: &str,
) -> Result<String, String> {
    let first = prompt_once(reader, prompt)?;
    let second = prompt_once(reader, confirmation)?;
    if first != second {
        return Err("the passphrases do not match; nothing was changed".to_string());
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Scripted {
        answers: VecDeque<String>,
        prompts: Vec<String>,
    }

    impl Scripted {
        fn new(answers: &[&str]) -> Self {
            Scripted {
                answers: answers.iter().map(|answer| answer.to_string()).collect(),
                prompts: Vec::new(),
            }
        }
    }

    impl SecretReader for Scripted {
        fn read_secret(&mut self, prompt: &str) -> io::Result<String> {
            self.prompts.push(prompt.to_string());
            self.answers
                .pop_front()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
    }

    fn current(
        env: Option<&str>,
        argument: Option<&str>,
        reader: Option<&mut Scripted>,
        allow_default: bool,
        creating: bool,
    ) -> Result<(String, PassphraseSource), String> {
        resolve_current(
            env.map(|env| (env.to_string(), PassphraseSource::Environment)),
            argument.map(str::to_string),
            reader.map(|reader| reader as &mut dyn SecretReader),
            allow_default,
            creating,
            "demo",
        )
    }

    #[test]
    fn environment_wins_over_argument_and_never_prompts() {
        let mut reader = Scripted::new(&[]);
        let resolved = current(Some("env"), Some("arg"), Some(&mut reader), false, true);
        assert_eq!(
            resolved,
            Ok(("env".to_string(), PassphraseSource::Environment))
        );
        assert!(reader.prompts.is_empty());
    }

    #[test]
    fn argument_is_used_without_prompting() {
        let mut reader = Scripted::new(&[]);
        let resolved = current(None, Some("arg"), Some(&mut reader), false, false);
        assert_eq!(
            resolved,
            Ok(("arg".to_string(), PassphraseSource::Argument))
        );
        assert!(reader.prompts.is_empty());
    }

    #[test]
    fn existing_store_prompts_once() {
        let mut reader = Scripted::new(&["typed"]);
        let resolved = current(None, None, Some(&mut reader), false, false);
        assert_eq!(
            resolved,
            Ok(("typed".to_string(), PassphraseSource::Prompt))
        );
        assert_eq!(reader.prompts.len(), 1);
    }

    #[test]
    fn new_store_requires_a_matching_confirmation() {
        let mut reader = Scripted::new(&["first", "first"]);
        let resolved = current(None, None, Some(&mut reader), false, true);
        assert_eq!(
            resolved,
            Ok(("first".to_string(), PassphraseSource::Prompt))
        );
        assert_eq!(reader.prompts.len(), 2);

        let mut reader = Scripted::new(&["first", "typo"]);
        let error = current(None, None, Some(&mut reader), false, true).unwrap_err();
        assert!(error.contains("do not match"), "{error}");
    }

    #[test]
    fn no_terminal_or_explicit_opt_in_falls_back_to_the_default() {
        assert_eq!(
            current(None, None, None, false, true),
            Ok(("demo".to_string(), PassphraseSource::Default))
        );
        let mut reader = Scripted::new(&[]);
        assert_eq!(
            current(None, None, Some(&mut reader), true, true),
            Ok(("demo".to_string(), PassphraseSource::Default))
        );
        assert!(reader.prompts.is_empty());
    }

    #[test]
    fn prompt_failure_is_reported_instead_of_falling_back() {
        let mut reader = Scripted::new(&[]);
        let error = current(None, None, Some(&mut reader), false, false).unwrap_err();
        assert!(error.contains("cannot read the passphrase"), "{error}");
    }

    #[test]
    fn new_passphrase_prefers_environment_then_argument_then_prompt() {
        let mut reader = Scripted::new(&[]);
        assert_eq!(
            resolve_new(
                Some("env".to_string()),
                Some("arg".to_string()),
                Some(&mut reader)
            ),
            Ok("env".to_string())
        );
        assert_eq!(
            resolve_new(None, Some("arg".to_string()), Some(&mut reader)),
            Ok("arg".to_string())
        );
        assert!(reader.prompts.is_empty());

        let mut reader = Scripted::new(&["next", "next"]);
        assert_eq!(
            resolve_new(None, None, Some(&mut reader)),
            Ok("next".to_string())
        );
        assert_eq!(reader.prompts.len(), 2);

        let mut reader = Scripted::new(&["next", "nxet"]);
        assert!(resolve_new(None, None, Some(&mut reader)).is_err());
    }

    #[test]
    fn new_passphrase_without_any_source_is_refused() {
        let error = resolve_new(None, None, None).unwrap_err();
        assert!(error.contains("ZEROTRUST_NEW_PASSPHRASE"), "{error}");
    }

    #[test]
    fn read_line_strips_line_endings_and_stops_at_newline() {
        let mut input: &[u8] = b"secret value\r\nnext line\n";
        assert_eq!(read_line(&mut input).unwrap(), b"secret value");
        assert_eq!(read_line(&mut input).unwrap(), b"next line");
        assert_eq!(read_line(&mut input).unwrap(), b"");
    }

    fn private_file(dir: &Path, name: &str, contents: &[u8], mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn stored_sources_follow_environment_credential_file_precedence() {
        let root = crate::remote::TestDir::new("stored-passphrase");
        let credentials = root.path().join("credentials");
        std::fs::create_dir(&credentials).unwrap();
        let file = private_file(root.path(), "pass", b"from file\n", 0o600);

        assert_eq!(resolve_stored(None, None, None), Ok(None));
        assert_eq!(
            resolve_stored(None, Some(&credentials), Some(&file)),
            Ok(Some(("from file".to_string(), PassphraseSource::File)))
        );
        private_file(&credentials, CREDENTIAL_NAME, b"from systemd", 0o400);
        assert_eq!(
            resolve_stored(None, Some(&credentials), Some(&file)),
            Ok(Some((
                "from systemd".to_string(),
                PassphraseSource::Credential
            )))
        );
        assert_eq!(
            resolve_stored(Some("env".to_string()), Some(&credentials), Some(&file)),
            Ok(Some(("env".to_string(), PassphraseSource::Environment)))
        );
        assert!(
            overridden_file_notice(true, Some(&file))
                .is_some_and(|notice| notice.contains("takes precedence")
                    && notice.contains(&file.display().to_string()))
        );
        assert_eq!(overridden_file_notice(true, None), None);
        assert_eq!(overridden_file_notice(false, Some(&file)), None);
        // A relative credentials directory is not one systemd provides.
        assert_eq!(
            resolve_stored(None, Some(Path::new("credentials")), None),
            Ok(None)
        );
        // A stored source never prompts.
        let mut reader = Scripted::new(&[]);
        let stored = resolve_stored(None, None, Some(&file)).unwrap();
        assert_eq!(
            resolve_current(
                stored,
                Some("arg".to_string()),
                Some(&mut reader),
                false,
                true,
                "demo"
            ),
            Ok(("from file".to_string(), PassphraseSource::File))
        );
        assert!(reader.prompts.is_empty());
    }

    #[test]
    fn passphrase_files_must_be_private_single_line_and_non_empty() {
        let root = crate::remote::TestDir::new("passphrase-file-refusals");
        let missing = root.path().join("missing");
        let error = resolve_stored(None, None, Some(&missing)).unwrap_err();
        assert!(error.contains("does not exist"), "{error}");

        let shared = private_file(root.path(), "shared", b"secret\n", 0o640);
        let error = resolve_stored(None, None, Some(&shared)).unwrap_err();
        assert!(error.contains("chmod 600"), "{error}");

        let link = root.path().join("link");
        std::os::unix::fs::symlink(&shared, &link).unwrap();
        assert!(resolve_stored(None, None, Some(&link)).is_err());

        for (name, contents, expected) in [
            ("empty", &b"\n"[..], "empty passphrase"),
            ("two-lines", &b"one\ntwo\n"[..], "more than one line"),
            ("binary", &b"\xff\xfe"[..], "not UTF-8"),
        ] {
            let path = private_file(root.path(), name, contents, 0o600);
            let error = resolve_stored(None, None, Some(&path)).unwrap_err();
            assert!(error.contains(expected), "{name}: {error}");
        }
        let large = private_file(root.path(), "large", &[b'x'; 5000], 0o600);
        assert!(resolve_stored(None, None, Some(&large)).is_err());

        let crlf = private_file(root.path(), "crlf", b"windows line\r\n", 0o600);
        assert_eq!(
            resolve_stored(None, None, Some(&crlf)),
            Ok(Some(("windows line".to_string(), PassphraseSource::File)))
        );
        // Interior spaces are part of the secret.
        let spaced = private_file(root.path(), "spaced", b" a b ", 0o600);
        assert_eq!(
            resolve_stored(None, None, Some(&spaced))
                .unwrap()
                .unwrap()
                .0,
            " a b "
        );
    }
}
