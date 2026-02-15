encrypted_dir := "~/gdrive/.zerotrust.drive.encrypted"
decrypted_dir := "~/z.drive"
passphrase := env("ZEROTRUST_PASSPHRASE", "")

default: build

build:
    cargo build

mount passphrase=passphrase: build
    mkdir -p {{decrypted_dir}}
    cargo run -- --encrypted-dir {{encrypted_dir}} --decrypted-dir {{decrypted_dir}}{{ if passphrase != "" { " --passphrase " + passphrase } else { "" } }}

umount:
    umount {{decrypted_dir}} || So it {{decrypted_dir}}

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

clean:
    cargo clean
    rm -rf {{encrypted_dir}} {{decrypted_dir}}
