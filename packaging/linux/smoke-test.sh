#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>
#
# Smoke-test an installed zdrive end to end on Linux:
#
#   packaging/linux/smoke-test.sh [ZDRIVE] [WORKDIR]
#
# Creates a throwaway encrypted drive, writes and reads a file through the
# FUSE mount, unmounts with fusermount3 -u and requires exit status 0, checks
# that the backing directory holds no plaintext, then remounts and reads the
# file back. ZDRIVE defaults to zdrive on PATH and WORKDIR to ./zdrive-smoke,
# which is removed first. Needs /dev/fuse plus CAP_SYS_ADMIN or fusermount3.
# The passphrase is random, reaches zdrive only through ZEROTRUST_PASSPHRASE
# and is never printed.
set -euo pipefail

zdrive=${1:-zdrive}
work=${2:-$PWD/zdrive-smoke}
timeout_seconds=${ZDRIVE_SMOKE_TIMEOUT:-120}

die() {
    printf 'smoke-test: error: %s\n' "$*" >&2
    if [ -f "$work/zdrive.log" ]; then
        sed 's/^/  zdrive: /' "$work/zdrive.log" >&2
    fi
    exit 1
}

command -v "$zdrive" >/dev/null 2>&1 || die "zdrive binary '$zdrive' not found"
command -v fusermount3 >/dev/null 2>&1 || die "fusermount3 not found (install fuse3)"
command -v mountpoint >/dev/null 2>&1 || die "mountpoint not found (install util-linux)"
[ -c /dev/fuse ] || die "/dev/fuse is not available"

rm -rf "$work"
mkdir -p "$work/encrypted" "$work/mnt"
work=$(cd "$work" && pwd)

ZEROTRUST_PASSPHRASE=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
export ZEROTRUST_PASSPHRASE
marker="zerotrust-drive smoke $(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
pid=

mount_drive() {
    "$zdrive" --encrypted-dir "$work/encrypted" --decrypted-dir "$work/mnt" \
        </dev/null >>"$work/zdrive.log" 2>&1 &
    pid=$!
    local half_seconds=0
    until mountpoint -q "$work/mnt"; do
        kill -0 "$pid" 2>/dev/null || die "zdrive exited before the drive was mounted"
        [ "$half_seconds" -lt $((timeout_seconds * 2)) ] ||
            die "drive not mounted after ${timeout_seconds}s"
        sleep 0.5
        half_seconds=$((half_seconds + 1))
    done
}

unmount_drive() {
    fusermount3 -u "$work/mnt" || die "fusermount3 -u $work/mnt failed"
    local status=0
    wait "$pid" || status=$?
    [ "$status" -eq 0 ] || die "zdrive exited with status $status after the unmount"
}

mount_drive
printf '%s\n' "$marker" >"$work/mnt/hello.txt"
[ "$(cat "$work/mnt/hello.txt")" = "$marker" ] || die "read-back through the mount differs"
unmount_drive

[ -z "$(ls -A "$work/mnt")" ] || die "mount point is not empty after the unmount"
if grep -rqF -- "$marker" "$work/encrypted"; then
    die "plaintext found in the encrypted directory"
fi

mount_drive
[ "$(cat "$work/mnt/hello.txt")" = "$marker" ] || die "file did not survive the remount"
unmount_drive

rm -rf "$work"
printf 'smoke-test: ok as uid %s: mount, write, read, fusermount3 -u (exit 0), no plaintext at rest, remount read\n' "$(id -u)"
