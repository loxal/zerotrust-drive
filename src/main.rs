// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

mod crypto;
mod fs;

use std::path::PathBuf;

use clap::Parser;
use fuser::{Config, MountOption};

#[derive(Parser)]
#[command(name = "zerotrust-drive", about = "FUSE-based encrypted overlay filesystem")]
struct Cli {
    /// Directory for encrypted .age files (storage backend, auto-managed — do not modify directly)
    #[arg(long, default_value = "target/.encrypted.disk")]
    encrypted_dir: PathBuf,

    /// FUSE mount point showing decrypted files
    #[arg(long, default_value = "target/decrypted.disk")]
    decrypted_dir: PathBuf,

    /// Encryption passphrase (can also be set via ZEROTRUST_PASSPHRASE env var)
    #[arg(long)]
    passphrase: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    let passphrase_from_env = std::env::var("ZEROTRUST_PASSPHRASE").ok();
    let passphrase_from_cli = cli.passphrase;
    let using_default_passphrase = passphrase_from_env.is_none() && passphrase_from_cli.is_none();
    let passphrase = passphrase_from_env
        .or(passphrase_from_cli)
        .unwrap_or_else(|| "zerotrust-demo-passphrase".to_string());
    let base_path = cli.encrypted_dir;
    let mountpoint = cli.decrypted_dir;

    std::fs::create_dir_all(&base_path).unwrap();
    std::fs::create_dir_all(&mountpoint).unwrap();

    eprintln!("zerotrust-drive: mounting at {}", mountpoint.display());
    eprintln!("zerotrust-drive: encrypted storage at {}", base_path.display());
    if using_default_passphrase {
        eprintln!("zerotrust-drive: ⚠️  WARNING: using default passphrase — set ZEROTRUST_PASSPHRASE for real security");
    }
    eprintln!("zerotrust-drive: NOTE: in-memory filesystem — all file content is held in RAM while open");
    eprintln!("zerotrust-drive: not recommended for files larger than available memory");
    eprintln!("zerotrust-drive: press Ctrl+C to unmount");

    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RW,
        MountOption::FSName("zerotrust-drive".to_string()),
    ];

    let ztfs = fs::ZeroTrustFs::new(&passphrase, base_path);
    fuser::mount2(ztfs, &mountpoint, &config).expect("failed to mount filesystem");
}
