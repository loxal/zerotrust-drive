#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>
#
# Build the zerotrust-drive Debian package from an already built binary:
#
#   packaging/deb/build-deb.sh VERSION ARCH BINARY OUTDIR
#
# VERSION is the upstream version without a leading "v" (0.18.0), ARCH the
# Debian architecture (amd64 or arm64) and BINARY the release build of the
# zerotrust-drive crate. Writes OUTDIR/zerotrust-drive_VERSION_ARCH.deb.
#
# Runs on Debian or Ubuntu with dpkg-dev installed, natively for ARCH:
# dpkg-shlibdeps resolves the shared-library dependencies against the host's
# dpkg database, so the build host's glibc becomes the package's floor.
# SOURCE_DATE_EPOCH (default: the last commit's time) fixes every timestamp.
set -euo pipefail

package=zerotrust-drive
maintainer='Alexander Orlov <info@lifub.com>'
homepage=https://github.com/loxal/zerotrust-drive
first_copyright_year=2026

die() {
    printf 'build-deb: error: %s\n' "$*" >&2
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
case "$version" in
    *[!0-9A-Za-z.+~]*) die "VERSION may only contain letters, digits and . + ~, got '$version'" ;;
esac

case "$arch" in
    amd64) elf_machine='Advanced Micro Devices X86-64' ;;
    arm64) elf_machine='AArch64' ;;
    *) die "ARCH must be amd64 or arm64, got '$arch'" ;;
esac

for tool in dpkg dpkg-deb dpkg-shlibdeps readelf strip gzip du find install touch date sed; do
    command -v "$tool" >/dev/null 2>&1 ||
        die "required tool '$tool' not found (install dpkg-dev, binutils, gzip and coreutils)"
done

host_arch=$(dpkg --print-architecture)
[ "$host_arch" = "$arch" ] ||
    die "dpkg-shlibdeps needs a native $arch host, but this host is $host_arch"

[ -f "$binary" ] || die "binary '$binary' does not exist"
binary_machine=$(readelf -h "$binary" | sed -n 's/^ *Machine: *//p')
[ "$binary_machine" = "$elf_machine" ] ||
    die "binary '$binary' is built for '$binary_machine', not $arch"

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$script_dir/../.." && pwd)
[ -f "$repo_root/LICENSE" ] || die "$repo_root/LICENSE is missing"
[ -f "$repo_root/README.md" ] || die "$repo_root/README.md is missing"

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git -C "$repo_root" log -1 --format=%ct 2>/dev/null) ||
        die "SOURCE_DATE_EPOCH is unset and $repo_root has no readable git history"
fi
case "$SOURCE_DATE_EPOCH" in
    '' | *[!0-9]*) die "SOURCE_DATE_EPOCH must be seconds since the epoch, got '$SOURCE_DATE_EPOCH'" ;;
esac
export SOURCE_DATE_EPOCH

mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
binary=$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")
deb="$outdir/${package}_${version}_${arch}.deb"

# dpkg-shlibdeps wants the binary inside debian/<package>/ next to a
# debian/control that declares the package, so the stage takes that shape.
work="$outdir/.${package}-deb-$arch"
rm -rf "$work"
trap 'rm -rf "$work"' EXIT
stage="$work/debian/$package"
doc="$stage/usr/share/doc/$package"

umask 022
# dpkg-shlibdeps finds the package root by its DEBIAN directory.
install -d -m 0755 "$stage/DEBIAN" "$stage/usr/bin" "$doc"
install -m 0755 "$binary" "$stage/usr/bin/zdrive"
strip --remove-section=.comment --remove-section=.note "$stage/usr/bin/zdrive"

copyright_year=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y)
if [ "$copyright_year" != "$first_copyright_year" ]; then
    copyright_year="$first_copyright_year-$copyright_year"
fi
{
    cat <<EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: $package
Upstream-Contact: $maintainer
Source: $homepage
Comment: The zdrive binary statically links Rust crates that keep their own
 licenses; Cargo.lock in the source names each crate and version.

Files: *
Copyright: $copyright_year $maintainer
License: AGPL-3.0-only

License: AGPL-3.0-only
EOF
    # Continuation lines start with a space and an empty line becomes " .".
    sed -e 's/^[[:space:]]*$/./' -e 's/^/ /' "$repo_root/LICENSE"
} >"$doc/copyright"

{
    cat <<EOF
$package ($version) unstable; urgency=medium

  * Upstream release $version:
    $homepage/releases/tag/v$version

 -- $maintainer  $(date -u -R -d "@$SOURCE_DATE_EPOCH")
EOF
} | gzip -9n >"$doc/changelog.gz"
gzip -9n <"$repo_root/README.md" >"$doc/README.md.gz"

find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -type f -exec chmod 0644 {} +
chmod 0755 "$stage/usr/bin/zdrive"
installed_size=$(du -sk --apparent-size "$stage/usr" | cut -f1)

cat >"$work/debian/control" <<EOF
Source: $package
Maintainer: $maintainer

Package: $package
Architecture: $arch
EOF
shlibs=$(cd "$work" && dpkg-shlibdeps -O -e"debian/$package/usr/bin/zdrive") ||
    die "dpkg-shlibdeps failed for the zdrive binary"
shlib_depends=$(printf '%s\n' "$shlibs" | sed -n 's/^shlibs:Depends=//p')
[ -n "$shlib_depends" ] || die "dpkg-shlibdeps reported no shared-library dependencies"
# fusermount3 from fuse3 mounts the drive for a user without CAP_SYS_ADMIN.
depends="fuse3, $shlib_depends"

cat >"$stage/DEBIAN/control" <<EOF
Package: $package
Version: $version
Architecture: $arch
Maintainer: $maintainer
Installed-Size: $installed_size
Depends: $depends
Section: utils
Priority: optional
Homepage: $homepage
Description: client-side encrypted FUSE drive with Google Drive sync
 ZeroTrust Drive (zdrive) mounts a FUSE filesystem whose files are encrypted
 on the client with XChaCha20-Poly1305 under an Argon2id-derived key before
 they reach the backing directory, so a sync folder or Google Drive only
 ever holds ciphertext.
 .
 Google Drive sync through the Drive API is built in. Synchronized data is
 encrypted by default; plain, unencrypted sync is an explicit opt-in.
EOF
chmod 0644 "$stage/DEBIAN/control"

find "$stage" -exec touch --no-dereference --date="@$SOURCE_DATE_EPOCH" {} +
dpkg-deb --root-owner-group -Zxz --build "$stage" "$deb" >/dev/null
printf '%s\n' "$deb"
