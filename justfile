# SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

# Secrets never pass through this file: zerotrust-drive reads
# ZEROTRUST_PASSPHRASE and ZEROTRUST_NEW_PASSPHRASE from the inherited
# environment, or prompts on the terminal with echo off. Interpolating them
# here would print them, expose them in the process list and let shell
# metacharacters in a passphrase run commands.

encrypted_dir := "~/g.drive/.zerotrust.drive.encrypted"
decrypted_dir := "~/z.drive"
legacy_secret_argument := "recipes no longer take passphrases as arguments; set ZEROTRUST_PASSPHRASE / ZEROTRUST_NEW_PASSPHRASE or let zerotrust-drive prompt for them"

default: build

build:
    cargo build

mount *legacy_passphrase: build
    {{ if legacy_passphrase != "" { error(legacy_secret_argument) } else { "" } }}
    mkdir -p {{decrypted_dir}}
    cargo run -- --encrypted-dir {{encrypted_dir}} --decrypted-dir {{decrypted_dir}}

mount-release *legacy_passphrase:
    {{ if legacy_passphrase != "" { error(legacy_secret_argument) } else { "" } }}
    mkdir -p {{decrypted_dir}}
    zdrive --encrypted-dir {{encrypted_dir}} --decrypted-dir {{decrypted_dir}}

# Ctrl+C in the mounting terminal also unmounts and flushes.
umount:
    umount {{decrypted_dir}} 2>/dev/null || fusermount3 -u {{decrypted_dir}} 2>/dev/null || fusermount -u {{decrypted_dir}} 2>/dev/null || true

run *legacy_passphrase: build
    {{ if legacy_passphrase != "" { error(legacy_secret_argument) } else { "" } }}
    cargo run -- --encrypted-dir {{encrypted_dir}} --decrypted-dir {{decrypted_dir}}

rekey *legacy_passphrases: build
    {{ if legacy_passphrases != "" { error(legacy_secret_argument) } else { "" } }}
    cargo run -- --encrypted-dir {{encrypted_dir}} --decrypted-dir {{decrypted_dir}} --rekey

rekey-resume *legacy_passphrases: build
    {{ if legacy_passphrases != "" { error(legacy_secret_argument) } else { "" } }}
    cargo run -- --encrypted-dir {{encrypted_dir}} --decrypted-dir {{decrypted_dir}} --rekey --continue-rekey

migrate-v2 *legacy_passphrase: build
    {{ if legacy_passphrase != "" { error(legacy_secret_argument) } else { "" } }}
    cargo run -- --encrypted-dir {{encrypted_dir}} --migrate-v2

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
