encrypted_dir := "~/g.drive/.zerotrust.drive.encrypted"
decrypted_dir := "~/z.drive"
passphrase := env("ZEROTRUST_PASSPHRASE", "")

default: build

build:
    cargo build

mount passphrase=passphrase: build
    mkdir -p {{decrypted_dir}}
    cargo run -- --encrypted-dir {{encrypted_dir}} --decrypted-dir {{decrypted_dir}}{{ if passphrase != "" { " --passphrase " + passphrase } else { "" } }}

mount-release passphrase=passphrase:
    mkdir -p {{decrypted_dir}}
    zdrive --encrypted-dir {{encrypted_dir}} --decrypted-dir {{decrypted_dir}}{{ if passphrase != "" { " --passphrase " + passphrase } else { "" } }}

umount:
    umount {{decrypted_dir}} 2>/dev/null || true

run passphrase=passphrase: build
    cargo run -- --encrypted-dir {{encrypted_dir}} --decrypted-dir {{decrypted_dir}}{{ if passphrase != "" { " --passphrase " + passphrase } else { "" } }}

rekey new_passphrase passphrase=passphrase: build
    cargo run -- --encrypted-dir {{encrypted_dir}} --new-passphrase {{new_passphrase}}{{ if passphrase != "" { " --passphrase " + passphrase } else { "" } }}

rekey-resume new_passphrase passphrase=passphrase: build
    cargo run -- --encrypted-dir {{encrypted_dir}} --new-passphrase {{new_passphrase}} --continue-rekey{{ if passphrase != "" { " --passphrase " + passphrase } else { "" } }}

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
    cross build --release --target x86_64-pc-windows-gnu
    @mkdir -p target/dist
    @cp target/x86_64-pc-windows-gnu/release/zerotrust-drive.exe target/dist/zdrive-windows-x86_64.exe
    @echo "built: target/dist/zdrive-windows-x86_64.exe"

release-all: release-macos release-linux release-windows
    @echo "all platforms built in target/dist/"
    @ls -lh target/dist/zdrive-*

clean:
    cargo clean
    rm -rf {{encrypted_dir}} {{decrypted_dir}}
