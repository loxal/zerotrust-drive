# SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

# Secrets never pass through this file: zerotrust-drive reads
# ZEROTRUST_PASSPHRASE and ZEROTRUST_NEW_PASSPHRASE from the inherited
# environment, or prompts on the terminal with echo off. Interpolating them
# here would print them, expose them in the process list and let shell
# metacharacters in a passphrase run commands.

# Empty selects zdrive's own default store, $XDG_DATA_HOME/zerotrust-drive/store,
# which also refuses to start over a pre-0.18 store in ~/g.drive. Override
# with `just encrypted_dir=DIR mount`.
encrypted_dir := ""
store_flag := if encrypted_dir != "" { "--encrypted-dir " + encrypted_dir } else { "" }
decrypted_dir := "~/z.drive"
legacy_secret_argument := "recipes no longer take passphrases as arguments; set ZEROTRUST_PASSPHRASE / ZEROTRUST_NEW_PASSPHRASE or let zerotrust-drive prompt for them"

default: build

build:
    cargo build

mount *legacy_passphrase: build
    {{ if legacy_passphrase != "" { error(legacy_secret_argument) } else { "" } }}
    mkdir -p {{decrypted_dir}}
    cargo run -- {{store_flag}} --decrypted-dir {{decrypted_dir}}

mount-release *legacy_passphrase:
    {{ if legacy_passphrase != "" { error(legacy_secret_argument) } else { "" } }}
    mkdir -p {{decrypted_dir}}
    zdrive {{store_flag}} --decrypted-dir {{decrypted_dir}}

# Ctrl+C in the mounting terminal also unmounts and flushes.
umount:
    umount {{decrypted_dir}} 2>/dev/null || fusermount3 -u {{decrypted_dir}} 2>/dev/null || fusermount -u {{decrypted_dir}} 2>/dev/null || true

run *legacy_passphrase: build
    {{ if legacy_passphrase != "" { error(legacy_secret_argument) } else { "" } }}
    cargo run -- {{store_flag}} --decrypted-dir {{decrypted_dir}}

rekey *legacy_passphrases: build
    {{ if legacy_passphrases != "" { error(legacy_secret_argument) } else { "" } }}
    cargo run -- {{store_flag}} --decrypted-dir {{decrypted_dir}} --rekey

rekey-resume *legacy_passphrases: build
    {{ if legacy_passphrases != "" { error(legacy_secret_argument) } else { "" } }}
    cargo run -- {{store_flag}} --decrypted-dir {{decrypted_dir}} --rekey --continue-rekey

migrate-v2 *legacy_passphrase: build
    {{ if legacy_passphrase != "" { error(legacy_secret_argument) } else { "" } }}
    cargo run -- {{store_flag}} --migrate-v2

populate:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=$(eval echo "{{decrypted_dir}}")
    if ! mount | grep -q "$dir"; then
        echo "ERROR: $dir is not mounted — run 'just mount' first"
        exit 1
    fi
    echo "populating $dir with test files..."
    echo "hello, zerotrust-drive" > "$dir/hello.txt"
    echo "second test file" > "$dir/notes.txt"
    mkdir -p "$dir/sub_dir"
    echo "nested file content" > "$dir/sub_dir/nested-file.txt"
    dd if=/dev/urandom bs=1024 count=64 2>/dev/null > "$dir/random-64k.bin"
    long_name=$(printf 'long-256-characters-name-filename-%.0s' {1..8} | cut -c1-251).txt
    echo "file with a 255-char filename" > "$dir/$long_name"
    echo "done — files created:"
    ls -laR "$dir"

test:
    cargo test

release:
    cargo build --release
    @cp target/release/zerotrust-drive ~/.cargo/bin/zdrive
    @echo "installed: ~/.cargo/bin/zdrive"

release-macos:
    cargo build --release --target aarch64-apple-darwin
    @mkdir -p target/dist
    @cp target/aarch64-apple-darwin/release/zerotrust-drive target/dist/zdrive-macos-aarch64
    @echo "built: target/dist/zdrive-macos-aarch64"

release-linux:
    cross build --release --target x86_64-unknown-linux-gnu
    @mkdir -p target/dist
    @cp target/x86_64-unknown-linux-gnu/release/zerotrust-drive target/dist/zdrive-linux-x86_64
    @echo "built: target/dist/zdrive-linux-x86_64"

release-windows:
    @echo "ERROR: Windows is unsupported because fuser requires Unix; use a WinFSP backend before adding a Windows artifact" >&2
    @exit 1

# Linux release packages built in podman on Ubuntu 22.04, the glibc 2.35
# baseline of the release CI job: dist/zerotrust-drive_VERSION_ARCH.deb and
# dist/zdrive-VERSION-linux-*.tar.gz for each Debian ARCH (amd64, arm64).
# Rust compiles natively in a builder for the podman machine's architecture,
# cross-linking the other one; packaging runs in a light container of the
# package's own architecture (under emulation when foreign). Cargo's target
# dir and registry live in named podman volumes. Bundled Google OAuth client
# values pass through by name only, and only when set.
deb *arches="amd64 arm64":
    #!/usr/bin/env bash
    set -euo pipefail
    version=$(awk -F'"' '/^\[/ { in_package = ($0 == "[package]") } in_package && /^version *=/ { print $2; exit }' Cargo.toml)
    [ -n "$version" ] || { echo "cannot read the package version from Cargo.toml" >&2; exit 1; }
    source_date_epoch=$(git log -1 --format=%ct)
    host_arch=$(podman info --format '{{{{.Host.Arch}}')
    case "$host_arch" in
        amd64|arm64) ;;
        *) echo "unsupported podman machine architecture '$host_arch'" >&2; exit 1 ;;
    esac
    mkdir -p dist
    oauth_env=()
    for name in ZDRIVE_GOOGLE_DESKTOP_CLIENT_ID ZDRIVE_GOOGLE_DESKTOP_CLIENT_SECRET \
        ZDRIVE_GOOGLE_DEVICE_CLIENT_ID ZDRIVE_GOOGLE_DEVICE_CLIENT_SECRET; do
        if [ -n "$(printenv "$name" || true)" ]; then oauth_env+=(--env "$name"); fi
    done
    builder="localhost/zerotrust-drive-deb-builder:$host_arch"
    podman build --platform "linux/$host_arch" --target builder -t "$builder" \
        -f packaging/deb/Containerfile packaging/deb
    for arch in {{arches}}; do
        case "$arch" in
            amd64) triple=x86_64-unknown-linux-gnu; tarball_arch=x86_64 ;;
            arm64) triple=aarch64-unknown-linux-gnu; tarball_arch=aarch64 ;;
            *) echo "unsupported ARCH '$arch' (use amd64 or arm64)" >&2; exit 1 ;;
        esac
        podman run --rm --platform "linux/$host_arch" --security-opt label=disable \
            --volume "$PWD:/src:ro" --volume zerotrust-drive-deb-target:/target \
            --volume zerotrust-drive-deb-cargo-registry:/usr/local/cargo/registry \
            --env CARGO_TARGET_DIR=/target ${oauth_env[@]+"${oauth_env[@]}"} \
            --workdir /src "$builder" cargo build --release --locked --target "$triple"
        packager="$builder"
        if [ "$arch" != "$host_arch" ]; then
            packager="localhost/zerotrust-drive-deb-packager:$arch"
            podman build --platform "linux/$arch" --target packager -t "$packager" \
                -f packaging/deb/Containerfile packaging/deb
        fi
        podman run --rm --platform "linux/$arch" --security-opt label=disable \
            --volume "$PWD:/src:ro" --volume "$PWD/dist:/dist" \
            --volume zerotrust-drive-deb-target:/target:ro \
            --env "SOURCE_DATE_EPOCH=$source_date_epoch" --workdir /src "$packager" \
            sh -euc 'packaging/deb/build-deb.sh "$1" "$2" "$4" /dist
                packaging/linux/build-tarball.sh "$1" "$3" "$4" /dist' \
            sh "$version" "$arch" "$tarball_arch" "/target/$triple/release/zerotrust-drive"
    done
    ls -l dist

# Install dist/zerotrust-drive_VERSION_ARCH.deb in fresh containers of each
# image, then run packaging/linux/smoke-test.sh as root and as a regular user
# (the fusermount3 path that the fuse3 dependency provides).
deb-test arch="arm64" *images="docker.io/library/ubuntu:22.04 docker.io/library/ubuntu:24.04 docker.io/library/ubuntu:26.04 docker.io/library/debian:12":
    #!/usr/bin/env bash
    set -euo pipefail
    version=$(awk -F'"' '/^\[/ { in_package = ($0 == "[package]") } in_package && /^version *=/ { print $2; exit }' Cargo.toml)
    deb="zerotrust-drive_${version}_{{arch}}.deb"
    [ -f "dist/$deb" ] || { echo "dist/$deb is missing; run 'just deb {{arch}}' first" >&2; exit 1; }
    for image in {{images}}; do
        podman pull --quiet --platform "linux/{{arch}}" "$image" >/dev/null
        printf '== %s %s\n' "$image" "$(podman image inspect --format '{{{{.Digest}}' "$image")"
        podman run --rm --platform "linux/{{arch}}" --device /dev/fuse --cap-add SYS_ADMIN \
            --security-opt label=disable --volume "$PWD/dist:/dist:ro" \
            --volume "$PWD/packaging/linux/smoke-test.sh:/usr/local/bin/zdrive-smoke-test:ro" \
            "$image" bash -euc '
                . /etc/os-release
                echo "os: $PRETTY_NAME"
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq
                if dpkg -s fuse3 >/dev/null 2>&1; then echo "fuse3 preinstalled"; else echo "fuse3 absent before install"; fi
                apt-get install -y -qq "/dist/$1" >/dev/null
                echo "fuse3 installed: $(dpkg-query -W -f "\${Version}" fuse3)"
                echo "depends: $(dpkg-query -W -f "\${Depends}" zerotrust-drive)"
                echo "version: $(zdrive --version)"
                dpkg -L zerotrust-drive
                zdrive-smoke-test zdrive /root/zdrive-smoke
                useradd --create-home zdrive-smoke
                su zdrive-smoke -c "zdrive-smoke-test zdrive /home/zdrive-smoke/smoke"' \
            bash "$deb"
    done

release-all: release-macos release-linux
    @echo "all supported platforms built in target/dist/"
    @ls -lh target/dist/zdrive-*

# Rebuild the committed macOS icon from its SVG source (needs rsvg-convert
# from librsvg and the iconutil that ships with macOS).
icons:
    #!/usr/bin/env bash
    set -euo pipefail
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    set="$work/zerotrust-drive.iconset"
    mkdir "$set"
    for size in 16 32 128 256 512; do
        rsvg-convert -w "$size" -h "$size" assets/icon/zerotrust-drive.svg -o "$set/icon_${size}x${size}.png"
        double=$((size * 2))
        rsvg-convert -w "$double" -h "$double" assets/icon/zerotrust-drive.svg -o "$set/icon_${size}x${size}@2x.png"
    done
    iconutil -c icns "$set" -o assets/icon/zerotrust-drive.icns
    echo "built: assets/icon/zerotrust-drive.icns"

# Build artifacts only: the encrypted store and the mount point hold real data.
clean:
    cargo clean
