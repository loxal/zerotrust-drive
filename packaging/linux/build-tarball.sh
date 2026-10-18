#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>
#
# Pack a Linux release binary with its README and license:
#
#   packaging/linux/build-tarball.sh VERSION ARCH BINARY OUTDIR
#
# ARCH is x86_64 or aarch64. Writes OUTDIR/zdrive-VERSION-linux-ARCH.tar.gz
# with one top-level directory of the same name holding zdrive, README.md and
# LICENSE*. With GNU tar the archive is byte-reproducible for a fixed
# SOURCE_DATE_EPOCH (default: the last commit's time).
set -euo pipefail

die() {
    printf 'build-tarball: error: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 4 ] || die "usage: $0 VERSION ARCH BINARY OUTDIR"
version=$1
arch=$2
binary=$3
outdir=$4

case "$version" in
    [0-9]*) ;;
    *) die "VERSION must start with a digit (no leading v), got '$version'" ;;
esac
case "$arch" in
    x86_64) elf_machine='Advanced Micro Devices X86-64' ;;
    aarch64) elf_machine='AArch64' ;;
    *) die "ARCH must be x86_64 or aarch64, got '$arch'" ;;
esac

for tool in tar gzip install sed; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool '$tool' not found"
done

[ -f "$binary" ] || die "binary '$binary' does not exist"
if command -v readelf >/dev/null 2>&1; then
    binary_machine=$(readelf -h "$binary" | sed -n 's/^ *Machine: *//p')
    [ "$binary_machine" = "$elf_machine" ] ||
        die "binary '$binary' is built for '$binary_machine', not $arch"
else
    printf 'build-tarball: warning: readelf not found; architecture of %s not checked\n' "$binary" >&2
fi

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$script_dir/../.." && pwd)
[ -f "$repo_root/README.md" ] || die "$repo_root/README.md is missing"

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git -C "$repo_root" log -1 --format=%ct 2>/dev/null) ||
        die "SOURCE_DATE_EPOCH is unset and $repo_root has no readable git history"
fi
case "$SOURCE_DATE_EPOCH" in
    '' | *[!0-9]*) die "SOURCE_DATE_EPOCH must be seconds since the epoch, got '$SOURCE_DATE_EPOCH'" ;;
esac

mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
name="zdrive-$version-linux-$arch"
tarball="$outdir/$name.tar.gz"

work="$outdir/.$name"
rm -rf "$work"
trap 'rm -rf "$work"' EXIT
umask 022
install -d -m 0755 "$work/$name"
install -m 0755 "$binary" "$work/$name/zdrive"
install -m 0644 "$repo_root/README.md" "$work/$name/README.md"
licenses=0
for license in "$repo_root"/LICENSE*; do
    [ -f "$license" ] || continue
    install -m 0644 "$license" "$work/$name/$(basename "$license")"
    licenses=$((licenses + 1))
done
[ "$licenses" -gt 0 ] || die "no LICENSE* file in $repo_root"

tar_version=$(tar --version 2>/dev/null || true)
case "$tar_version" in
    *'GNU tar'*)
        tar -C "$work" --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 \
            --numeric-owner --format=gnu -cf - "$name" | gzip -9n >"$tarball"
        ;;
    *)
        printf 'build-tarball: warning: not GNU tar; %s is not byte-reproducible\n' "$tarball" >&2
        tar -C "$work" -cf - "$name" | gzip -9n >"$tarball"
        ;;
esac
printf '%s\n' "$tarball"
