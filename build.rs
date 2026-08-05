// Copyright 2026 Alex O <info@lifub.com>

#[cfg(target_os = "macos")]
fn main() {
    println!("cargo:rerun-if-changed=src/macos_file_coordination.h");
    println!("cargo:rerun-if-changed=src/macos_file_coordination.swift");
    println!("cargo:rerun-if-changed=src/macos_exception_guard.h");
    println!("cargo:rerun-if-changed=src/macos_exception_guard.m");
    println!("cargo:rerun-if-changed=src/macos_swift_bridge.h");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    // Unlike the `cc` crate, swiftc neither reads Cargo's TARGET nor honors
    // MACOSX_DEPLOYMENT_TARGET, so both must be threaded into an explicit
    // -target triple. Otherwise the Swift archive silently targets the build
    // host's architecture and OS while the Objective-C guard archive follows
    // TARGET, and a cross-arch macOS build fails at link with every
    // ztd_mac_* symbol undefined. 11.0 (the first Apple-silicon macOS, above
    // every API this shim uses) is the deployment floor when unset.
    let target = std::env::var("TARGET").expect("cargo sets TARGET for build scripts");
    let architecture = target.split('-').next().unwrap_or_default();
    let swift_architecture = match architecture {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        other => panic!("unsupported macOS target architecture for the Swift shim: {other}"),
    };
    let deployment_target =
        std::env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| String::from("11.0"));

    // The Swift archive is registered first so classic left-to-right archive
    // resolution can satisfy its ztd_mac_exception_guard reference from the
    // Objective-C guard archive that `cc` registers afterwards. The Swift
    // runtime itself resolves through the autolink records swiftc embeds in
    // the objects; macOS ships the ABI-stable runtime in the dyld shared
    // cache, so nothing is bundled.
    compile_swift_shim(swift_architecture, &deployment_target);

    // The guard follows the same deployment floor so one shim cannot carry
    // two different minos stamps.
    cc::Build::new()
        .file("src/macos_exception_guard.m")
        .flag("-fblocks")
        .flag("-fobjc-arc")
        .flag(format!("-mmacosx-version-min={deployment_target}"))
        .compile("zerotrust_drive_macos_exception_guard");
    println!("cargo:rustc-link-lib=framework=Foundation");
}

#[cfg(target_os = "macos")]
fn compile_swift_shim(swift_architecture: &str, deployment_target: &str) {
    let out_dir = std::env::var("OUT_DIR").expect("cargo sets OUT_DIR for build scripts");
    let library = std::path::Path::new(&out_dir).join("libzerotrust_drive_macos_swift.a");

    let swift_target = format!("{swift_architecture}-apple-macosx{deployment_target}");

    let mut command = std::process::Command::new("swiftc");
    command.args([
        "-target",
        &swift_target,
        "-swift-version",
        "6",
        "-parse-as-library",
        "-module-name",
        "zerotrust_drive_macos_file_coordination",
        "-import-objc-header",
        "src/macos_swift_bridge.h",
        "-emit-library",
        "-static",
    ]);
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        command.arg("-O");
    }
    command.arg("-o");
    command.arg(&library);
    command.arg("src/macos_file_coordination.swift");

    let output = command.output().expect(
        "run swiftc: the macOS file-coordination shim is Swift and needs the Xcode command line tools",
    );
    if !output.status.success() {
        panic!(
            "swiftc failed compiling the macOS file-coordination shim:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static=zerotrust_drive_macos_swift");

    // Deployment targets below the newest OS make swiftc autolink static
    // back-compatibility archives (libswiftCompatibility*.a). They live in
    // the toolchain's runtime resource directory, which rustc's link line
    // does not search by default; swiftc itself reports the authoritative
    // paths for the exact -target being built.
    for path in swift_runtime_library_paths(&swift_target) {
        println!("cargo:rustc-link-search=native={path}");
    }
}

#[cfg(target_os = "macos")]
fn swift_runtime_library_paths(swift_target: &str) -> Vec<String> {
    let output = std::process::Command::new("swiftc")
        .args(["-print-target-info", "-target", swift_target])
        .output()
        .expect("run swiftc -print-target-info");
    if !output.status.success() {
        panic!(
            "swiftc -print-target-info failed:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
    }
    // Minimal extraction of "runtimeLibraryPaths": ["..", ".."] from the JSON
    // swiftc prints, without a build-dependency JSON parser. Fail closed on an
    // unexpected shape so a silent link problem cannot hide here.
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let key = "\"runtimeLibraryPaths\"";
    let start = text
        .find(key)
        .and_then(|at| text[at..].find('[').map(|open| at + open + 1))
        .expect("swiftc -print-target-info reports runtimeLibraryPaths");
    let end = start
        + text[start..]
            .find(']')
            .expect("swiftc -print-target-info closes runtimeLibraryPaths");
    text[start..end]
        .split(',')
        .filter_map(|entry| {
            let entry = entry.trim().trim_matches('"');
            (!entry.is_empty()).then(|| entry.to_string())
        })
        .collect()
}

#[cfg(not(target_os = "macos"))]
fn main() {}
