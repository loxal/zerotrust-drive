// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! macFUSE's libfuse channel for the FSKit backend.
//!
//! Only public libfuse 2.9 symbols are used; fuser already links macFUSE's
//! `libfuse.2.dylib`. libfuse's own multithreaded loop calls
//! `fuse_chan_recv` and `fuse_chan_send` from several threads at once, which
//! is how the bridge uses them as well.

use std::ffi::{CString, c_char, c_int, c_void};
use std::io;
use std::path::Path;

use super::bridge::{KernelChannel, Received};

#[repr(C)]
struct FuseArgs {
    argc: c_int,
    argv: *mut *mut c_char,
    allocated: c_int,
}

#[repr(C)]
struct SessionOps {
    process: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize, *mut c_void)>,
    exit: Option<unsafe extern "C" fn(*mut c_void, c_int)>,
    exited: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    destroy: Option<unsafe extern "C" fn(*mut c_void)>,
}

unsafe extern "C" {
    fn fuse_opt_add_arg(args: *mut FuseArgs, arg: *const c_char) -> c_int;
    fn fuse_opt_free_args(args: *mut FuseArgs);
    fn fuse_mount(mountpoint: *const c_char, args: *mut FuseArgs) -> *mut c_void;
    fn fuse_unmount(mountpoint: *const c_char, channel: *mut c_void);
    fn fuse_chan_bufsize(channel: *mut c_void) -> usize;
    fn fuse_chan_recv(channel: *mut *mut c_void, buffer: *mut c_char, size: usize) -> c_int;
    fn fuse_chan_send(channel: *mut c_void, parts: *const libc::iovec, count: usize) -> c_int;
    fn fuse_session_new(ops: *mut SessionOps, data: *mut c_void) -> *mut c_void;
    fn fuse_session_add_chan(session: *mut c_void, channel: *mut c_void);
    fn fuse_session_destroy(session: *mut c_void);
}

/// `fuse_chan_recv` needs the channel attached to a session; the bridge
/// reads requests itself, so the session never processes one.
unsafe extern "C" fn never_process(_: *mut c_void, _: *const c_char, _: usize, _: *mut c_void) {}

/// A volume mounted through the FSKit backend and its request channel.
pub(crate) struct FskitChannel {
    session: *mut c_void,
    channel: *mut c_void,
    buffer_size: usize,
    mountpoint: CString,
}

// SAFETY: libfuse's channel functions are called concurrently by its own
// multithreaded loop; the pointers are only freed in Drop, after every thread
// holding the channel has ended.
unsafe impl Send for FskitChannel {}
// SAFETY: as above.
unsafe impl Sync for FskitChannel {}

impl FskitChannel {
    /// Ask macFUSE to mount `mountpoint` through FSKit. The volume appears
    /// only after fuser has answered FSKit's first requests through the
    /// bridge.
    pub(crate) fn mount(mountpoint: &Path, options: &str) -> io::Result<Self> {
        let path = CString::new(mountpoint.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mount point contains NUL"))?;
        let options = CString::new(options).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "mount option contains NUL")
        })?;
        let mut args = FuseArgs {
            argc: 0,
            argv: std::ptr::null_mut(),
            allocated: 0,
        };
        let mut added = true;
        for arg in [c"zerotrust-drive", c"-o", options.as_c_str()] {
            // SAFETY: args is a valid, initially empty fuse_args; libfuse
            // copies arg.
            added &= unsafe { fuse_opt_add_arg(&mut args, arg.as_ptr()) } == 0;
        }
        let channel = if added {
            // SAFETY: path and args are valid for the call.
            unsafe { fuse_mount(path.as_ptr(), &mut args) }
        } else {
            std::ptr::null_mut()
        };
        // SAFETY: args was built by fuse_opt_add_arg.
        unsafe { fuse_opt_free_args(&mut args) };
        if !added {
            return Err(io::Error::other("cannot build the macFUSE mount options"));
        }
        if channel.is_null() {
            return Err(io::Error::other(format!(
                "macFUSE could not mount {} through FSKit; enable macFUSE under System Settings > General > Login Items & Extensions > File System Extensions",
                mountpoint.display()
            )));
        }
        let mut ops = SessionOps {
            process: Some(never_process),
            exit: None,
            exited: None,
            destroy: None,
        };
        // SAFETY: libfuse copies ops; a null data pointer is allowed.
        let session = unsafe { fuse_session_new(&mut ops, std::ptr::null_mut()) };
        if session.is_null() {
            // SAFETY: channel came from fuse_mount and is released here.
            unsafe { fuse_unmount(path.as_ptr(), channel) };
            return Err(io::Error::other("libfuse could not create a session"));
        }
        // SAFETY: both pointers are live; the session now owns the channel.
        unsafe { fuse_session_add_chan(session, channel) };
        // SAFETY: channel is live.
        let buffer_size = unsafe { fuse_chan_bufsize(channel) };
        Ok(Self {
            session,
            channel,
            buffer_size,
            mountpoint: path,
        })
    }
}

impl KernelChannel for FskitChannel {
    fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    fn receive(&self, buffer: &mut [u8]) -> Received {
        let mut channel = self.channel;
        // SAFETY: channel is live and buffer is writable for its length.
        let received =
            unsafe { fuse_chan_recv(&mut channel, buffer.as_mut_ptr().cast(), buffer.len()) };
        match received {
            n if n > 0 => Received::Request(usize::try_from(n).unwrap_or(0)),
            n if n == -libc::EINTR || n == -libc::EAGAIN || n == -libc::ENOENT => Received::Retry,
            n => Received::Ended(n),
        }
    }

    fn send(&self, parts: &[&[u8]]) -> i32 {
        let parts: Vec<libc::iovec> = parts
            .iter()
            .map(|part| libc::iovec {
                iov_base: part.as_ptr().cast_mut().cast(),
                iov_len: part.len(),
            })
            .collect();
        // SAFETY: channel is live; libfuse only reads the iovecs.
        unsafe { fuse_chan_send(self.channel, parts.as_ptr(), parts.len()) }
    }

    fn unmount(&self, force: bool) -> io::Result<()> {
        let flags = if force { libc::MNT_FORCE } else { 0 };
        // SAFETY: mountpoint is a valid C string.
        if unsafe { libc::unmount(self.mountpoint.as_ptr(), flags) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for FskitChannel {
    fn drop(&mut self) {
        // SAFETY: the session is live and owns the channel, which it
        // destroys with it; no thread uses either any more.
        unsafe { fuse_session_destroy(self.session) };
    }
}
