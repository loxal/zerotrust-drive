// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! The sd_notify protocol: one datagram per state change to the socket in
//! `$NOTIFY_SOCKET`, which systemd sets for `Type=notify` services. Outside
//! systemd the variable is unset and every call is a no-op.

use std::ffi::OsStr;
use std::os::unix::net::UnixDatagram;

/// Sends `state` (for example `READY=1`) to `$NOTIFY_SOCKET`. `Ok(false)`
/// when the variable is unset or empty.
pub(crate) fn notify(state: &str) -> std::io::Result<bool> {
    notify_with(std::env::var_os("NOTIFY_SOCKET").as_deref(), state)
}

pub(crate) fn notify_with(socket: Option<&OsStr>, state: &str) -> std::io::Result<bool> {
    let Some(socket) = socket.filter(|socket| !socket.is_empty()) else {
        return Ok(false);
    };
    let sender = UnixDatagram::unbound()?;
    let bytes = socket.as_encoded_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        send_abstract(&sender, name, state)?;
    } else if bytes.starts_with(b"/") {
        sender.send_to(state.as_bytes(), socket)?;
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "NOTIFY_SOCKET {} is neither an absolute path nor an abstract socket",
                socket.to_string_lossy()
            ),
        ));
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn send_abstract(sender: &UnixDatagram, name: &[u8], state: &str) -> std::io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    let address = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
    sender.send_to_addr(state.as_bytes(), &address).map(drop)
}

#[cfg(not(target_os = "linux"))]
fn send_abstract(_sender: &UnixDatagram, _name: &[u8], _state: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "abstract NOTIFY_SOCKET addresses exist only on Linux",
    ))
}

/// `READY=1`: the mount or the sync is up.
// The mount and sync paths that the integration wires call this.
#[allow(dead_code)]
pub(crate) fn ready() -> std::io::Result<bool> {
    notify("READY=1")
}

/// `STATUS=...`: a one-line state for `systemctl status`.
pub(crate) fn status(text: &str) -> std::io::Result<bool> {
    notify(&format!("STATUS={}", text.replace(['\n', '\r'], " ")))
}

/// `STOPPING=1`: the shutdown, including the final upload, has begun.
// The mount and sync paths that the integration wires call this.
#[allow(dead_code)]
pub(crate) fn stopping() -> std::io::Result<bool> {
    notify("STOPPING=1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;

    #[test]
    fn service_notify_is_a_no_op_without_a_socket() {
        assert!(!notify_with(None, "READY=1").unwrap());
        assert!(!notify_with(Some(OsStr::new("")), "READY=1").unwrap());
        assert_eq!(
            notify_with(Some(OsStr::new("relative.sock")), "READY=1")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn service_notify_sends_datagrams_to_a_path_socket() {
        let dir = TestDir::new("service-notify");
        let path = dir.path().join("n.sock");
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        for state in ["READY=1", "STATUS=starting home", "STOPPING=1"] {
            assert!(notify_with(Some(path.as_os_str()), state).unwrap());
            let mut buffer = [0u8; 256];
            let length = receiver.recv(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], state.as_bytes());
        }
        let missing = dir.path().join("absent.sock");
        assert!(notify_with(Some(missing.as_os_str()), "READY=1").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn service_notify_sends_datagrams_to_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("zerotrust-drive-notify-test-{}", std::process::id());
        let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let receiver = UnixDatagram::bind_addr(&address).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let socket = std::ffi::OsString::from(format!("@{name}"));
        assert!(notify_with(Some(&socket), "READY=1").unwrap());
        let mut buffer = [0u8; 64];
        let length = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..length], b"READY=1");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn service_notify_refuses_abstract_sockets_off_linux() {
        assert_eq!(
            notify_with(Some(OsStr::new("@zdrive")), "READY=1")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Unsupported
        );
    }
}
