// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Relays FUSE messages between a kernel channel that has no file descriptor
//! and a datagram socket that fuser serves as if it were `/dev/macfuse`.
//!
//! macFUSE's FSKit backend delivers requests through libfuse's channel API
//! (`fuse_chan_recv` and `fuse_chan_send`) instead of a device descriptor.
//! The reader thread forwards each request as one datagram; the writer thread
//! returns each reply as the two parts libfuse sends itself (out header, then
//! body), because FSKit fails a mount when a reply arrives in one part.
//!
//! Every forwarded request is tracked until its reply passes back, so none
//! is left unanswered: once fuser has stopped, outstanding and new requests
//! get EIO, and the bridge unmounts the volume unless the kernel side ended it
//! already. When the kernel channel ends first, a synthetic DESTROY makes
//! fuser flush and return exactly as after a real unmount.

use std::collections::HashSet;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const IN_HEADER: usize = 40;
const OUT_HEADER: usize = 16;
const OPCODE_FORGET: u32 = 2;
const OPCODE_READ: u32 = 15;
const OPCODE_READDIR: u32 = 28;
const OPCODE_DESTROY: u32 = 38;
const OPCODE_NOTIFY_REPLY: u32 = 41;
const OPCODE_BATCH_FORGET: u32 = 42;
const OPCODE_READDIRPLUS: u32 = 44;
/// `fuse_read_in.size` follows the header, `fh` and `offset`.
const READ_SIZE_OFFSET: usize = IN_HEADER + 16;
/// The unique of the DESTROY the bridge synthesizes. The kernel never
/// reaches it: its uniques count up from 1.
const SYNTHETIC_UNIQUE: u64 = u64::MAX;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How long [`Bridge::finish`] waits for the kernel channel to close.
const READER_GRACE: Duration = Duration::from_secs(10);
/// Socket buffer sizes to try, largest first: macOS refuses a size above
/// its `kern.ipc.maxsockbuf` bound instead of clamping it.
const BUFFER_SIZES: [usize; 4] = [8 << 20, 4 << 20, 2 << 20, 1 << 20];
/// Room between the largest payload and the socket buffer for the FUSE
/// headers and the socket's own accounting.
const HEADROOM: usize = 64 << 10;

#[cfg(target_os = "linux")]
const SEND_FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: libc::c_int = 0;

/// One result of [`KernelChannel::receive`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Received {
    /// A request of this many bytes is at the start of the buffer.
    Request(usize),
    /// Interrupted before a request arrived; receive again.
    Retry,
    /// The channel ended, with libfuse's result (0 or a negative errno).
    Ended(i32),
}

/// The kernel side of the bridge: macFUSE's libfuse channel in production, a
/// fake in tests.
pub(crate) trait KernelChannel: Send + Sync + 'static {
    /// The largest request the channel delivers.
    fn buffer_size(&self) -> usize;
    /// Wait for the next request. Only the reader thread calls this.
    fn receive(&self, buffer: &mut [u8]) -> Received;
    /// Send one reply made of `parts`; returns 0 or a negative errno.
    fn send(&self, parts: &[&[u8]]) -> i32;
    /// Unmount the volume the channel serves.
    fn unmount(&self, force: bool) -> io::Result<()>;
}

#[derive(Default)]
struct State {
    /// Uniques forwarded to fuser whose reply has not passed back yet.
    outstanding: HashSet<u64>,
    /// fuser has stopped serving: answer everything here.
    fuser_gone: bool,
}

#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    replies: AtomicU64,
    max_request: AtomicU64,
    max_reply: AtomicU64,
    eio: AtomicU64,
    oversize: AtomicU64,
}

impl Counters {
    fn count(counter: &AtomicU64, max: &AtomicU64, len: usize) {
        counter.fetch_add(1, Ordering::Relaxed);
        max.fetch_max(u64::try_from(len).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    fn load(counter: &AtomicU64) -> crate::telemetry::Field {
        crate::telemetry::Field::U64(counter.load(Ordering::Relaxed))
    }
}

struct Shared {
    channel: Box<dyn KernelChannel>,
    /// The bridge's end of the socket pair; fuser holds the other.
    socket: OwnedFd,
    /// Receive buffer for replies: the socket buffer, so any datagram fits.
    capacity: usize,
    /// Largest READ-family payload fuser may be asked for.
    limit: usize,
    state: Mutex<State>,
    channel_ended: AtomicBool,
    destroy_seen: AtomicBool,
    counters: Counters,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Answer `unique` with `errno` (0 for success) and no body.
    fn answer(&self, unique: u64, errno: i32) {
        let mut header = [0u8; OUT_HEADER];
        header[0..4].copy_from_slice(&(OUT_HEADER as u32).to_ne_bytes());
        header[4..8].copy_from_slice(&(-errno).to_ne_bytes());
        header[8..16].copy_from_slice(&unique.to_ne_bytes());
        if errno != 0 {
            self.counters.eio.fetch_add(1, Ordering::Relaxed);
        }
        let sent = self.channel.send(&[&header]);
        if sent < 0 && sent != -libc::ENOENT {
            eprintln!(
                "zerotrust-drive: FSKit bridge: cannot answer request {unique}: {}",
                io::Error::from_raw_os_error(-sent)
            );
        }
    }

    /// Forward one kernel request to fuser, or answer it here when fuser
    /// cannot.
    fn forward(&self, request: &[u8]) {
        Counters::count(
            &self.counters.requests,
            &self.counters.max_request,
            request.len(),
        );
        if request.len() < OUT_HEADER {
            eprintln!(
                "zerotrust-drive: FSKit bridge: ignored a {}-byte request",
                request.len()
            );
            return;
        }
        let unique = read_u64(request, 8);
        if request.len() < IN_HEADER {
            self.answer(unique, libc::EIO);
            return;
        }
        let opcode = read_u32(request, 4);
        let expects_reply = !matches!(
            opcode,
            OPCODE_FORGET | OPCODE_BATCH_FORGET | OPCODE_NOTIFY_REPLY
        );
        if opcode == OPCODE_DESTROY {
            self.destroy_seen.store(true, Ordering::SeqCst);
        }
        {
            let mut state = self.state();
            if state.fuser_gone {
                drop(state);
                if opcode == OPCODE_DESTROY {
                    self.answer(unique, 0);
                } else if expects_reply {
                    self.answer(unique, libc::EIO);
                }
                return;
            }
            if let Some(size) = requested_reply_size(opcode, request)
                && size > self.limit
            {
                drop(state);
                self.counters.oversize.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "zerotrust-drive: FSKit bridge: refused a {size}-byte read (limit {})",
                    self.limit
                );
                self.answer(unique, libc::EIO);
                return;
            }
            if expects_reply {
                state.outstanding.insert(unique);
            }
        }
        if let Err(error) = send_datagram(self.socket.as_raw_fd(), request, 0) {
            eprintln!(
                "zerotrust-drive: FSKit bridge: cannot forward a {}-byte request: {error}",
                request.len()
            );
            if expects_reply && self.state().outstanding.remove(&unique) {
                self.answer(unique, libc::EIO);
            }
        }
    }

    /// Pass one fuser reply back to the kernel as header and body.
    fn relay(&self, reply: &[u8], truncated: bool) {
        Counters::count(
            &self.counters.replies,
            &self.counters.max_reply,
            reply.len(),
        );
        if reply.len() < OUT_HEADER {
            eprintln!(
                "zerotrust-drive: FSKit bridge: dropped a {}-byte reply",
                reply.len()
            );
            return;
        }
        let unique = read_u64(reply, 8);
        if unique == SYNTHETIC_UNIQUE {
            return;
        }
        // Unique 0 is a notification, which answers no request.
        let tracked = self.state().outstanding.remove(&unique);
        if !tracked && unique != 0 {
            // Already answered with EIO; the kernel no longer waits for it.
            return;
        }
        if truncated {
            self.counters.oversize.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "zerotrust-drive: FSKit bridge: a reply exceeded {} bytes",
                self.capacity
            );
            if tracked {
                self.answer(unique, libc::EIO);
            }
            return;
        }
        let (header, body) = reply.split_at(OUT_HEADER);
        let sent = if body.is_empty() {
            self.channel.send(&[header])
        } else {
            self.channel.send(&[header, body])
        };
        if sent < 0 && sent != -libc::ENOENT {
            eprintln!(
                "zerotrust-drive: FSKit bridge: cannot pass back the reply to request {unique}: {}",
                io::Error::from_raw_os_error(-sent)
            );
        }
    }

    /// Answer every request fuser will no longer reply to.
    fn answer_outstanding(&self) {
        let pending: Vec<u64> = self.state().outstanding.drain().collect();
        for unique in pending {
            self.answer(unique, libc::EIO);
        }
    }

    /// Make fuser end its session as after a real unmount: it replies,
    /// drops the filesystem (which flushes in `destroy`) and returns.
    fn send_synthetic_destroy(&self, flags: libc::c_int) -> io::Result<()> {
        let mut message = [0u8; IN_HEADER];
        message[0..4].copy_from_slice(&(IN_HEADER as u32).to_ne_bytes());
        message[4..8].copy_from_slice(&OPCODE_DESTROY.to_ne_bytes());
        message[8..16].copy_from_slice(&SYNTHETIC_UNIQUE.to_ne_bytes());
        // SAFETY: geteuid and getegid cannot fail.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        message[24..28].copy_from_slice(&uid.to_ne_bytes());
        message[28..32].copy_from_slice(&gid.to_ne_bytes());
        send_datagram(self.socket.as_raw_fd(), &message, flags)
    }
}

/// A running bridge. [`Bridge::finish`] (or dropping it) stops it once fuser
/// has returned.
pub(crate) struct Bridge {
    shared: Arc<Shared>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
    finished: bool,
}

/// Start relaying `channel`. Returns the bridge and the descriptor fuser
/// serves (`fuser::Session::from_fd`).
pub(crate) fn start(channel: impl KernelChannel) -> io::Result<(Bridge, OwnedFd)> {
    let (bridge_end, fuser_end) = datagram_pair()?;
    let buffer = size_buffers(&bridge_end, &fuser_end)?;
    let shared = Arc::new(Shared {
        channel: Box::new(channel),
        socket: bridge_end,
        capacity: buffer,
        limit: payload_limit(buffer),
        state: Mutex::new(State::default()),
        channel_ended: AtomicBool::new(false),
        destroy_seen: AtomicBool::new(false),
        counters: Counters::default(),
    });
    let writer = {
        let shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("zdrive-fskit-out".to_string())
            .spawn(move || write_replies(&shared))?
    };
    let reader = {
        let shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("zdrive-fskit-in".to_string())
            .spawn(move || read_requests(&shared))
    };
    let reader = match reader {
        Ok(reader) => reader,
        Err(error) => {
            shared.state().fuser_gone = true;
            let _ = writer.join();
            return Err(error);
        }
    };
    Ok((
        Bridge {
            shared,
            reader: Some(reader),
            writer: Some(writer),
            finished: false,
        },
        fuser_end,
    ))
}

impl Bridge {
    /// Largest READ or WRITE payload the bridge carries.
    pub(crate) fn limit(&self) -> usize {
        self.shared.limit
    }

    /// A callback that ends fuser's session without the kernel channel, for
    /// a mount that is abandoned before its volume appeared.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn abandoner(&self) -> Box<dyn Fn() + Send> {
        let shared = Arc::downgrade(&self.shared);
        Box::new(move || {
            if let Some(shared) = shared.upgrade()
                && let Err(error) = shared.send_synthetic_destroy(libc::MSG_DONTWAIT)
            {
                eprintln!("zerotrust-drive: FSKit bridge: cannot abandon the mount: {error}");
            }
        })
    }

    /// Stop relaying after fuser's session has returned: answer what fuser
    /// left unanswered, unmount a volume the kernel still holds, and wait
    /// for the channel to close. Idempotent.
    pub(crate) fn finish(&mut self) {
        if std::mem::replace(&mut self.finished, true) {
            return;
        }
        self.shared.state().fuser_gone = true;
        if let Some(writer) = self.writer.take()
            && writer.join().is_err()
        {
            eprintln!("zerotrust-drive: FSKit bridge: the reply thread panicked");
        }
        let kernel_ended = self.shared.channel_ended.load(Ordering::SeqCst)
            || self.shared.destroy_seen.load(Ordering::SeqCst);
        if !kernel_ended {
            // fuser stopped while the volume is attached. Detach it while the
            // reader still answers, so the volume cannot hang; unmount can
            // block, so it runs on its own thread.
            let shared = Arc::clone(&self.shared);
            let spawned = std::thread::Builder::new()
                .name("zdrive-fskit-unmount".to_string())
                .spawn(move || detach_volume(shared.channel.as_ref()));
            if let Err(error) = spawned {
                eprintln!("zerotrust-drive: FSKit bridge: cannot start the unmount: {error}");
            }
        }
        let mut channel_closed = true;
        if let Some(reader) = self.reader.take() {
            let deadline = Instant::now() + READER_GRACE;
            while !reader.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            if reader.is_finished() {
                if reader.join().is_err() {
                    eprintln!("zerotrust-drive: FSKit bridge: the request thread panicked");
                }
            } else {
                channel_closed = false;
                eprintln!(
                    "zerotrust-drive: warning: the FSKit channel did not close within {} s",
                    READER_GRACE.as_secs()
                );
            }
        }
        let counters = &self.shared.counters;
        crate::telemetry::event(
            crate::telemetry::Level::Standard,
            "fskit.bridge",
            &[
                ("requests", Counters::load(&counters.requests)),
                ("replies", Counters::load(&counters.replies)),
                ("max_request", Counters::load(&counters.max_request)),
                ("max_reply", Counters::load(&counters.max_reply)),
                ("eio", Counters::load(&counters.eio)),
                ("oversize", Counters::load(&counters.oversize)),
                (
                    "limit",
                    crate::telemetry::Field::U64(self.shared.limit as u64),
                ),
                ("kernel_ended", crate::telemetry::Field::Bool(kernel_ended)),
                (
                    "channel_closed",
                    crate::telemetry::Field::Bool(channel_closed),
                ),
            ],
        );
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.finish();
    }
}

fn read_requests(shared: &Shared) {
    let mut buffer = vec![0u8; shared.channel.buffer_size()];
    let code = loop {
        match shared.channel.receive(&mut buffer) {
            Received::Request(len) => shared.forward(&buffer[..len.min(buffer.len())]),
            Received::Retry => {}
            Received::Ended(code) => break code,
        }
    };
    shared.channel_ended.store(true, Ordering::SeqCst);
    if code != 0 && code != -libc::ENODEV {
        eprintln!(
            "zerotrust-drive: FSKit bridge: the channel ended: {}",
            io::Error::from_raw_os_error(-code)
        );
    }
    if !shared.state().fuser_gone {
        // Fails harmlessly when fuser has already returned after a real
        // DESTROY and closed its end.
        let _ = shared.send_synthetic_destroy(libc::MSG_DONTWAIT);
    }
}

fn write_replies(shared: &Shared) {
    let socket = shared.socket.as_raw_fd();
    let mut buffer = vec![0u8; shared.capacity];
    loop {
        if wait_readable(socket, POLL_INTERVAL) {
            match receive_datagram(socket, &mut buffer) {
                Ok((len, truncated)) if len > 0 => {
                    shared.relay(&buffer[..len], truncated);
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                // Nothing to read after all, or a condition the closed peer
                // left behind: pause instead of spinning.
                _ => std::thread::sleep(POLL_INTERVAL),
            }
        }
        // Every reply fuser wrote before it stopped has been relayed once
        // the socket stays quiet.
        if shared.state().fuser_gone {
            break;
        }
    }
    shared.answer_outstanding();
}

fn detach_volume(channel: &dyn KernelChannel) {
    match channel.unmount(false) {
        Ok(()) => {}
        Err(error) if [Some(libc::EINVAL), Some(libc::ENOENT)].contains(&error.raw_os_error()) => {}
        Err(error) => {
            eprintln!(
                "zerotrust-drive: FSKit bridge: unmount failed ({error}); forcing it, the encrypted state is already flushed"
            );
            if let Err(error) = channel.unmount(true) {
                eprintln!("zerotrust-drive: FSKit bridge: forced unmount failed: {error}");
            }
        }
    }
}

/// The reply size a READ-family request asks for.
fn requested_reply_size(opcode: u32, request: &[u8]) -> Option<usize> {
    if !matches!(opcode, OPCODE_READ | OPCODE_READDIR | OPCODE_READDIRPLUS)
        || request.len() < READ_SIZE_OFFSET + 4
    {
        return None;
    }
    usize::try_from(read_u32(request, READ_SIZE_OFFSET)).ok()
}

/// The largest power of two that leaves [`HEADROOM`] in a socket buffer.
fn payload_limit(buffer: usize) -> usize {
    let usable = buffer.saturating_sub(HEADROOM);
    if usable == 0 {
        0
    } else {
        1 << (usize::BITS - 1 - usable.leading_zeros())
    }
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_ne_bytes(word)
}

fn read_u64(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_ne_bytes(word)
}

fn datagram_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: fds has room for the two descriptors socketpair writes.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair succeeded, so both descriptors are open and owned
    // by nobody else.
    let pair = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [pair.0.as_raw_fd(), pair.1.as_raw_fd()] {
        // SAFETY: fcntl on an open descriptor.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // macOS has no MSG_NOSIGNAL: a send to a closed peer must not raise
        // SIGPIPE.
        #[cfg(target_os = "macos")]
        set_socket_option(fd, libc::SO_NOSIGPIPE, 1)?;
    }
    Ok(pair)
}

/// Enlarge both ends' buffers as far as the host allows and return the
/// smallest effective size, which bounds every datagram.
fn size_buffers(first: &OwnedFd, second: &OwnedFd) -> io::Result<usize> {
    let mut effective = usize::MAX;
    for fd in [first.as_raw_fd(), second.as_raw_fd()] {
        for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
            // A host below the smallest size keeps its default; the payload
            // limit derived from it is checked by the caller.
            for size in BUFFER_SIZES {
                let size = libc::c_int::try_from(size).unwrap_or(libc::c_int::MAX);
                if set_socket_option(fd, option, size).is_ok() {
                    break;
                }
            }
            let mut value: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: value and len are live out-parameters of matching size.
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    (&mut value as *mut libc::c_int).cast(),
                    &mut len,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            let value = usize::try_from(value).unwrap_or(0);
            // Linux reports twice the size it accounts for payload.
            let value = if cfg!(target_os = "linux") {
                value / 2
            } else {
                value
            };
            effective = effective.min(value);
        }
    }
    Ok(effective)
}

fn set_socket_option(fd: RawFd, option: libc::c_int, value: libc::c_int) -> io::Result<()> {
    // SAFETY: value is a live c_int for the call's duration.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn send_datagram(fd: RawFd, bytes: &[u8], flags: libc::c_int) -> io::Result<()> {
    loop {
        // SAFETY: bytes is valid for its length for the call's duration.
        let sent =
            unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), SEND_FLAGS | flags) };
        if sent >= 0 {
            return if usize::try_from(sent).ok() == Some(bytes.len()) {
                Ok(())
            } else {
                Err(io::Error::other("the socket shortened a datagram"))
            };
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Receive one datagram without blocking; reports whether it was cut short.
fn receive_datagram(fd: RawFd, buffer: &mut [u8]) -> io::Result<(usize, bool)> {
    let mut part = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    // SAFETY: msghdr is plain old data for which all-zero bytes are valid.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut part;
    message.msg_iovlen = 1;
    // SAFETY: message points at one live iovec over buffer.
    let received = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_DONTWAIT) };
    let received = usize::try_from(received).map_err(|_| io::Error::last_os_error())?;
    Ok((received, message.msg_flags & libc::MSG_TRUNC != 0))
}

fn wait_readable(fd: RawFd, timeout: Duration) -> bool {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: poll reads and writes one live pollfd.
    unsafe { libc::poll(&mut poll, 1, millis) > 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Condvar;

    const OPCODE_GETATTR: u32 = 3;
    const OPCODE_WRITE: u32 = 16;
    const OPCODE_INIT: u32 = 26;
    const WAIT: Duration = Duration::from_secs(10);

    #[derive(Default)]
    struct Fake {
        incoming: Mutex<VecDeque<Option<Vec<u8>>>>,
        incoming_ready: Condvar,
        sent: Mutex<Vec<Vec<Vec<u8>>>>,
        sent_changed: Condvar,
        unmounts: Mutex<Vec<bool>>,
        busy: AtomicBool,
    }

    impl Fake {
        /// Deliver a request, an interruption with an empty one, or end the
        /// channel with `None`.
        fn push(&self, message: Option<Vec<u8>>) {
            self.incoming.lock().unwrap().push_back(message);
            self.incoming_ready.notify_all();
        }

        /// Wait until at least `count` replies were sent; return them all.
        fn sent(&self, count: usize) -> Vec<Vec<Vec<u8>>> {
            let sent = self.sent.lock().unwrap();
            let (sent, timeout) = self
                .sent_changed
                .wait_timeout_while(sent, WAIT, |sent| sent.len() < count)
                .unwrap();
            assert!(
                !timeout.timed_out(),
                "only {} replies: {:?}",
                sent.len(),
                *sent
            );
            sent.clone()
        }

        fn wait_for_unmounts(&self, count: usize) -> Vec<bool> {
            let deadline = Instant::now() + WAIT;
            loop {
                let unmounts = self.unmounts.lock().unwrap().clone();
                if unmounts.len() >= count {
                    return unmounts;
                }
                assert!(Instant::now() < deadline, "unmounts: {unmounts:?}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    struct FakeChannel(Arc<Fake>);

    impl KernelChannel for FakeChannel {
        fn buffer_size(&self) -> usize {
            32 << 20
        }

        fn receive(&self, buffer: &mut [u8]) -> Received {
            let incoming = self.0.incoming.lock().unwrap();
            let mut incoming = self
                .0
                .incoming_ready
                .wait_while(incoming, |incoming| incoming.is_empty())
                .unwrap();
            match incoming.pop_front().unwrap() {
                Some(request) if request.is_empty() => Received::Retry,
                Some(request) => {
                    buffer[..request.len()].copy_from_slice(&request);
                    Received::Request(request.len())
                }
                None => {
                    // The channel stays ended.
                    incoming.push_front(None);
                    Received::Ended(-libc::ENODEV)
                }
            }
        }

        fn send(&self, parts: &[&[u8]]) -> i32 {
            self.0
                .sent
                .lock()
                .unwrap()
                .push(parts.iter().map(|part| part.to_vec()).collect());
            self.0.sent_changed.notify_all();
            0
        }

        fn unmount(&self, force: bool) -> io::Result<()> {
            self.0.unmounts.lock().unwrap().push(force);
            if !force && self.0.busy.load(Ordering::SeqCst) {
                return Err(io::Error::from_raw_os_error(libc::EBUSY));
            }
            Ok(())
        }
    }

    fn started() -> (Arc<Fake>, Bridge, OwnedFd) {
        let fake = Arc::new(Fake::default());
        let (bridge, fuser_end) = start(FakeChannel(Arc::clone(&fake))).unwrap();
        (fake, bridge, fuser_end)
    }

    fn request(opcode: u32, unique: u64, body: &[u8]) -> Vec<u8> {
        let mut message = vec![0u8; IN_HEADER];
        let len = u32::try_from(IN_HEADER + body.len()).unwrap();
        message[0..4].copy_from_slice(&len.to_ne_bytes());
        message[4..8].copy_from_slice(&opcode.to_ne_bytes());
        message[8..16].copy_from_slice(&unique.to_ne_bytes());
        message[16..24].copy_from_slice(&1u64.to_ne_bytes());
        // SAFETY: geteuid and getegid cannot fail.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        message[24..28].copy_from_slice(&uid.to_ne_bytes());
        message[28..32].copy_from_slice(&gid.to_ne_bytes());
        message.extend_from_slice(body);
        message
    }

    fn read_request(opcode: u32, unique: u64, size: usize) -> Vec<u8> {
        let mut body = vec![0u8; 40];
        body[16..20].copy_from_slice(&u32::try_from(size).unwrap().to_ne_bytes());
        request(opcode, unique, &body)
    }

    fn reply(unique: u64, errno: i32, body: &[u8]) -> Vec<u8> {
        let mut message = vec![0u8; OUT_HEADER];
        let len = u32::try_from(OUT_HEADER + body.len()).unwrap();
        message[0..4].copy_from_slice(&len.to_ne_bytes());
        message[4..8].copy_from_slice(&(-errno).to_ne_bytes());
        message[8..16].copy_from_slice(&unique.to_ne_bytes());
        message.extend_from_slice(body);
        message
    }

    /// (unique, error) of a reply the bridge sent to the kernel.
    fn answer_of(parts: &[Vec<u8>]) -> (u64, i32) {
        let header = &parts[0];
        assert_eq!(header.len(), OUT_HEADER);
        let error = i32::from_ne_bytes(header[4..8].try_into().unwrap());
        (read_u64(header, 8), error)
    }

    /// What fuser would read next, or None within `timeout`.
    fn fuser_reads(fuser_end: &OwnedFd, timeout: Duration) -> Option<Vec<u8>> {
        if !wait_readable(fuser_end.as_raw_fd(), timeout) {
            return None;
        }
        let mut buffer = vec![0u8; 1 << 20];
        let (len, truncated) = receive_datagram(fuser_end.as_raw_fd(), &mut buffer).unwrap();
        assert!(!truncated);
        buffer.truncate(len);
        Some(buffer)
    }

    fn fuser_replies(fuser_end: &OwnedFd, message: &[u8]) {
        send_datagram(fuser_end.as_raw_fd(), message, 0).unwrap();
    }

    /// fuser receives no further request once the bridge has finished: its
    /// socket stays quiet or shows only that the bridge closed its end.
    fn fuser_gets_nothing(fuser_end: &OwnedFd) {
        if !wait_readable(fuser_end.as_raw_fd(), Duration::from_millis(200)) {
            return;
        }
        let mut buffer = vec![0u8; 1 << 20];
        match receive_datagram(fuser_end.as_raw_fd(), &mut buffer) {
            Ok((0, _)) => {}
            Err(error) if error.raw_os_error() == Some(libc::ECONNRESET) => {}
            other => panic!("fuser received {other:?}"),
        }
    }

    #[test]
    fn payload_limit_is_a_power_of_two_below_the_socket_buffer() {
        assert_eq!(payload_limit(8 << 20), 4 << 20);
        assert_eq!(payload_limit((8 << 20) - 16), 4 << 20);
        assert_eq!(payload_limit((4 << 20) + HEADROOM), 4 << 20);
        assert_eq!(payload_limit(212_992), 128 << 10);
        assert_eq!(payload_limit(1 << 20), 512 << 10);
        assert_eq!(payload_limit(HEADROOM), 0);
        assert_eq!(payload_limit(0), 0);
    }

    #[test]
    fn requests_pass_whole_and_replies_return_as_header_and_body() {
        let (fake, mut bridge, fuser_end) = started();
        assert!(bridge.limit() >= 64 << 10, "limit {}", bridge.limit());

        let getattr = request(OPCODE_GETATTR, 5, &[0u8; 16]);
        fake.push(Some(getattr.clone()));
        assert_eq!(fuser_reads(&fuser_end, WAIT).unwrap(), getattr);
        let body = vec![7u8; 104];
        fuser_replies(&fuser_end, &reply(5, 0, &body));
        let sent = fake.sent(1);
        assert_eq!(sent[0].len(), 2, "header and body travel as two parts");
        assert_eq!(answer_of(&sent[0]), (5, 0));
        assert_eq!(sent[0][1], body);

        // A header-only reply stays one part, and an interrupted receive
        // before it loses nothing.
        fake.push(Some(Vec::new()));
        fake.push(Some(request(OPCODE_GETATTR, 6, &[0u8; 16])));
        assert!(fuser_reads(&fuser_end, WAIT).is_some());
        fuser_replies(&fuser_end, &reply(6, libc::ENOENT, &[]));
        let sent = fake.sent(2);
        assert_eq!(sent[1].len(), 1);
        assert_eq!(answer_of(&sent[1]), (6, -libc::ENOENT));

        // A reply to a request that was never forwarded is not passed on.
        fuser_replies(&fuser_end, &reply(99, 0, &[]));

        // The channel ends: fuser gets a DESTROY of its own to flush on.
        fake.push(None);
        let destroy = fuser_reads(&fuser_end, WAIT).unwrap();
        assert_eq!(destroy.len(), IN_HEADER);
        assert_eq!(read_u32(&destroy, 4), OPCODE_DESTROY);
        assert_eq!(read_u64(&destroy, 8), SYNTHETIC_UNIQUE);
        // SAFETY: geteuid cannot fail.
        assert_eq!(read_u32(&destroy, 24), unsafe { libc::geteuid() });
        fuser_replies(&fuser_end, &reply(SYNTHETIC_UNIQUE, 0, &[]));

        bridge.finish();
        assert_eq!(fake.sent.lock().unwrap().len(), 2, "no reply to 99 or MAX");
        assert!(fake.unmounts.lock().unwrap().is_empty());
        bridge.finish();
    }

    #[test]
    fn requests_the_socket_cannot_carry_fail_with_eio() {
        let (fake, mut bridge, fuser_end) = started();
        let limit = bridge.limit();

        fake.push(Some(read_request(OPCODE_READ, 9, limit + 1)));
        assert_eq!(answer_of(&fake.sent(1)[0]), (9, -libc::EIO));
        assert!(fuser_reads(&fuser_end, Duration::from_millis(200)).is_none());

        let readdirplus = read_request(OPCODE_READDIRPLUS, 10, limit);
        fake.push(Some(readdirplus.clone()));
        assert_eq!(fuser_reads(&fuser_end, WAIT).unwrap(), readdirplus);

        // Larger than any datagram: the forward itself fails.
        let body = vec![1u8; bridge.shared.capacity * 2 + HEADROOM];
        fake.push(Some(request(OPCODE_WRITE, 11, &body)));
        assert_eq!(answer_of(&fake.sent(2)[1]), (11, -libc::EIO));

        fake.push(None);
        bridge.finish();
        // The READDIRPLUS fuser never answered gets EIO when fuser stops.
        assert_eq!(answer_of(&fake.sent(3)[2]), (10, -libc::EIO));
        assert_eq!(bridge.shared.counters.oversize.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_stopped_fuser_leaves_no_request_unanswered_and_the_volume_detached() {
        let (fake, bridge, fuser_end) = started();
        fake.busy.store(true, Ordering::SeqCst);
        fake.push(Some(request(OPCODE_GETATTR, 20, &[0u8; 16])));
        assert!(fuser_reads(&fuser_end, WAIT).is_some());

        // fuser returned (an error, say) while the volume is attached.
        let finisher = std::thread::spawn(move || {
            let mut bridge = bridge;
            bridge.finish();
        });
        assert_eq!(answer_of(&fake.sent(1)[0]), (20, -libc::EIO));
        assert_eq!(fake.wait_for_unmounts(2), vec![false, true]);

        // The kernel still talks until the unmount completes.
        fake.push(Some(request(OPCODE_DESTROY, 21, &[])));
        fake.push(Some(request(OPCODE_FORGET, 22, &[0u8; 8])));
        fake.push(Some(request(OPCODE_GETATTR, 23, &[0u8; 16])));
        let sent = fake.sent(3);
        assert_eq!(answer_of(&sent[1]), (21, 0));
        assert_eq!(answer_of(&sent[2]), (23, -libc::EIO));
        fake.push(None);
        finisher.join().unwrap();
        assert_eq!(fake.sent.lock().unwrap().len(), 3, "FORGET gets no reply");
        fuser_gets_nothing(&fuser_end);
    }

    #[test]
    fn abandoning_ends_fuser_while_the_channel_stays_open() {
        let (fake, mut bridge, fuser_end) = started();
        bridge.abandoner()();
        let destroy = fuser_reads(&fuser_end, WAIT).unwrap();
        assert_eq!(read_u32(&destroy, 4), OPCODE_DESTROY);
        assert_eq!(read_u64(&destroy, 8), SYNTHETIC_UNIQUE);
        fake.push(None);
        bridge.finish();
    }

    #[derive(Clone, Default)]
    struct Probe {
        initialized: Arc<AtomicBool>,
        destroyed: Arc<AtomicBool>,
    }

    impl fuser::Filesystem for Probe {
        fn init(
            &mut self,
            _request: &fuser::Request,
            _config: &mut fuser::KernelConfig,
        ) -> io::Result<()> {
            self.initialized.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn destroy(&mut self) {
            self.destroyed.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_real_fuser_session_flushes_and_returns_when_the_channel_ends() {
        let (fake, mut bridge, fuser_end) = started();
        let probe = Probe::default();

        // FUSE 7.19, as macFUSE sends it: major, minor, max_readahead, flags.
        let mut init = Vec::new();
        for word in [7u32, 19, 1 << 20, 0] {
            init.extend_from_slice(&word.to_ne_bytes());
        }
        fake.push(Some(request(OPCODE_INIT, 1, &init)));
        let mut config = fuser::Config::default();
        config.acl = fuser::SessionACL::RootAndOwner;
        let session = fuser::Session::from_fd(
            probe.clone(),
            fuser_end,
            fuser::SessionACL::RootAndOwner,
            config,
        )
        .unwrap();
        let init_reply = &fake.sent(1)[0];
        assert_eq!(answer_of(init_reply), (1, 0));
        assert!(probe.initialized.load(Ordering::SeqCst));

        let serving = std::thread::spawn(move || session.run());
        fake.push(Some(request(OPCODE_GETATTR, 2, &[0u8; 16])));
        assert_eq!(answer_of(&fake.sent(2)[1]).0, 2);
        assert!(!probe.destroyed.load(Ordering::SeqCst));

        fake.push(None);
        serving.join().unwrap().unwrap();
        assert!(probe.destroyed.load(Ordering::SeqCst));
        bridge.finish();
        assert!(fake.unmounts.lock().unwrap().is_empty());
        assert_eq!(fake.sent.lock().unwrap().len(), 2);
    }
}
