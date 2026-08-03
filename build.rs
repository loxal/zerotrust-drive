// Copyright 2026 Alex O <info@lifub.com>

#[cfg(target_os = "macos")]
fn main() {
    println!("cargo:rerun-if-changed=src/macos_file_coordination.h");
    println!("cargo:rerun-if-changed=src/macos_file_coordination.m");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    cc::Build::new()
        .file("src/macos_file_coordination.m")
        .flag("-fblocks")
        .flag("-fobjc-arc")
        .compile("zerotrust_drive_macos_file_coordination");
    println!("cargo:rustc-link-lib=framework=Foundation");
}

#[cfg(not(target_os = "macos"))]
fn main() {}
