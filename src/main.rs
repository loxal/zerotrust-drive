// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

mod crypto;
mod fs;
mod rekey;

use std::path::PathBuf;

use clap::Parser;
use fuser::{Config, MountOption};

#[derive(Parser)]
#[command(name = "zerotrust-drive", about = "FUSE-based encrypted overlay filesystem")]
struct Cli {
    /// Directory for encrypted .age files (storage backend, auto-managed — do not modify directly)
    #[arg(long, default_value = "~/g.drive/.zerotrust.drive.encrypted")]
    encrypted_dir: PathBuf,

    /// FUSE mount point showing decrypted files
    #[arg(long, default_value = "~/z.drive")]
    decrypted_dir: PathBuf,

    /// Encryption passphrase (can also be set via ZEROTRUST_PASSPHRASE env var)
    #[arg(long)]
    passphrase: Option<String>,

    /// Re-encrypt all files with a new passphrase (mounts read-only during rotation)
    #[arg(long)]
    new_passphrase: Option<String>,

    /// Resume an interrupted rekey instead of starting over (requires --new-passphrase)
    #[arg(long)]
    continue_rekey: bool,
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

    // Recover from any interrupted rekey before doing anything else
    rekey::recover_interrupted_rekey(&base_path);

    // Validate --continue-rekey requires --new-passphrase
    let resume = cli.continue_rekey;
    if resume && cli.new_passphrase.is_none() {
        eprintln!("zerotrust-drive: error: --continue-rekey requires --new-passphrase");
        std::process::exit(1);
    }

    // Handle --new-passphrase (online rekey: mount read-only, re-encrypt in background)
    if let Some(new_passphrase) = cli.new_passphrase {
        if new_passphrase == passphrase {
            eprintln!("zerotrust-drive: error: new passphrase is the same as the current one");
            std::process::exit(1);
        }
        let index_path = base_path.join("_index.age");
        if !index_path.exists() {
            eprintln!(
                "zerotrust-drive: error: no _index.age found in {}",
                base_path.display()
            );
            std::process::exit(1);
        }

        std::fs::create_dir_all(&mountpoint).unwrap();

        let ztfs = fs::ZeroTrustFs::new(&passphrase, base_path.clone());
        let inner = ztfs.inner.clone();

        let rekey_base = base_path.clone();
        let old_pw = passphrase.clone();
        std::thread::spawn(move || {
            // Let FUSE mount establish before starting rekey
            std::thread::sleep(std::time::Duration::from_millis(500));
            rekey::rekey_online(&old_pw, &new_passphrase, &rekey_base, &inner, resume);
        });

        eprintln!("zerotrust-drive: rotating passphrase — files will be read-only until re-encryption finishes");
        eprintln!("zerotrust-drive: mounting at {}", mountpoint.display());
        eprintln!("zerotrust-drive: encrypted storage at {}", base_path.display());
        eprintln!("zerotrust-drive: the filesystem will unmount automatically when complete");

        let mut config = Config::default();
        config.mount_options = vec![
            MountOption::RW,
            MountOption::FSName("zerotrust-drive".to_string()),
        ];

        fuser::mount2(ztfs, &mountpoint, &config).expect("failed to mount filesystem");
        return;
    }

    // Refuse to mount if a rekey is in progress
    let rekey_lock = base_path.join("_rekey.lock");
    if rekey_lock.exists() {
        eprintln!("zerotrust-drive: error: _rekey.lock exists — a rekey operation may be in progress");
        eprintln!(
            "zerotrust-drive: if you are sure no rekey is running, delete {} manually",
            rekey_lock.display()
        );
        std::process::exit(1);
    }

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
