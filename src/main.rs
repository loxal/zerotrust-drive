// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

mod crypto;
mod fs;
mod migrate;
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

    /// Upgrade a pre-0.7 drive to the v1 on-disk format (Argon2id +
    /// XChaCha20-Poly1305) in place, using the current passphrase, then
    /// exit. Crash-safe; re-run to resume an interrupted migration.
    #[arg(long)]
    migrate_format: bool,
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

    // Recover from any interrupted rekey or format migration before
    // doing anything else.
    rekey::recover_interrupted_rekey(&base_path);
    migrate::recover_interrupted_migration(&base_path);

    // Handle --migrate-format (v0 → v1 on-disk upgrade) and exit.
    if cli.migrate_format {
        if cli.new_passphrase.is_some() {
            eprintln!("zerotrust-drive: error: --migrate-format upgrades in place with the current passphrase; do not combine it with --new-passphrase");
            std::process::exit(1);
        }
        if !base_path.join("_index.age").exists() {
            eprintln!(
                "zerotrust-drive: error: no _index.age found in {} — nothing to migrate",
                base_path.display()
            );
            std::process::exit(1);
        }
        if !migrate::needs_migration(&base_path) {
            eprintln!("zerotrust-drive: drive is already in the v1 on-disk format — nothing to do");
            return;
        }
        eprintln!("zerotrust-drive: migrating {} to v1 (Argon2id + XChaCha20-Poly1305)...", base_path.display());
        eprintln!("zerotrust-drive: NOTE: every blob is re-encrypted, so a cloud-sync backend will re-upload the whole drive");
        match migrate::migrate_v0_to_v1(&passphrase, &base_path) {
            Ok(()) => {
                eprintln!("zerotrust-drive: migration complete — mount normally to use the drive");
                return;
            }
            Err(e) => {
                eprintln!("zerotrust-drive: error: migration failed: {e}");
                eprintln!("zerotrust-drive: the drive was left untouched in its previous format");
                std::process::exit(1);
            }
        }
    }

    // Refuse to operate on a pre-0.7 drive until it is migrated. This
    // guards both the normal mount and the --new-passphrase rekey path
    // (rekey assumes the v1 KDF + cipher).
    if migrate::needs_migration(&base_path) {
        eprintln!(
            "zerotrust-drive: error: {} uses the pre-0.7 on-disk format (no _kdf.json)",
            base_path.display()
        );
        eprintln!("zerotrust-drive: run `zerotrust-drive --migrate-format` (with the current passphrase) to upgrade it");
        eprintln!("zerotrust-drive: ChaCha20-Poly1305 → XChaCha20-Poly1305 and the homemade KDF → Argon2id");
        std::process::exit(1);
    }

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
