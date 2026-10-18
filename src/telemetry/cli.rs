// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! `zdrive telemetry ...`: inspect, summarize, export, configure and
//! delete the local telemetry.

use std::path::{Path, PathBuf};

use crate::remote::config::Paths;

use super::{
    DIR_NAME, ENV_VAR, Level, LevelSource, RETENTION_DAYS, config_level, report, resolve_level,
    save_config_level, system, tar, validate_instance, writer,
};

#[derive(clap::Subcommand, Debug)]
pub(crate) enum TelemetryCommand {
    /// Show the effective level, its source, data location and size
    Status,
    /// Summarize collected telemetry (latency percentiles, errors, retries, restarts, crashes)
    Report {
        /// Window to summarize, e.g. 90m, 24h or 7d [default: 24h]
        #[arg(long, value_name = "DURATION")]
        since: Option<String>,
        /// Print one JSON object instead of text
        #[arg(long)]
        json: bool,
        /// Only this instance [default: all instances]
        #[arg(long)]
        instance: Option<String>,
    },
    /// Write all telemetry into an uncompressed tar archive for manual sharing; nothing is uploaded
    Export {
        /// Archive to create; an existing file is never replaced
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Enable collection at the standard level (keeps full if already full)
    On,
    /// Disable collection; existing data is kept until `purge`
    Off,
    /// Set the collection level
    Level { level: Level },
    /// Delete all collected telemetry
    Purge {
        /// Confirm the deletion
        #[arg(long)]
        yes: bool,
    },
}

/// A failed command: the message for stderr and the exit code.
#[derive(Debug)]
pub(crate) struct Failure {
    pub(crate) message: String,
    pub(crate) code: i32,
}

impl Failure {
    fn runtime(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 1,
        }
    }

    fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 2,
        }
    }
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::runtime(message)
    }
}

pub(crate) fn run(command: TelemetryCommand) -> i32 {
    let paths = match Paths::from_env() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("zerotrust-drive: error: {error}");
            return 1;
        }
    };
    let env = std::env::var_os(ENV_VAR).map(|value| value.to_string_lossy().into_owned());
    match execute(command, &paths, env.as_deref(), system::now_ms()) {
        Ok(output) => {
            print!("{output}");
            0
        }
        Err(failure) => {
            eprintln!("zerotrust-drive: error: {}", failure.message);
            failure.code
        }
    }
}

/// Runs `command` against explicit directories and environment value.
pub(crate) fn execute(
    command: TelemetryCommand,
    paths: &Paths,
    env: Option<&str>,
    now_ms: u64,
) -> Result<String, Failure> {
    let root = paths.state.join(DIR_NAME);
    match command {
        TelemetryCommand::Status => status(paths, &root, env),
        TelemetryCommand::Report {
            since,
            json,
            instance,
        } => {
            if let Some(instance) = &instance {
                validate_instance(instance).map_err(Failure::usage)?;
            }
            let label = since.unwrap_or_else(|| "24h".to_string());
            let window = report::parse_since(&label).map_err(Failure::usage)?;
            let summary = report::build(&root, instance.as_deref(), window, &label, now_ms)?;
            Ok(if json {
                format!("{}\n", summary.to_json())
            } else {
                summary.to_text()
            })
        }
        TelemetryCommand::Export { output } => {
            let exported = tar::export(&root, &output)?;
            Ok(format!(
                "exported {} telemetry files ({}) to {}\nnothing was uploaded; review the archive before sharing it\n",
                exported.files,
                human_bytes(exported.bytes),
                output.display()
            ))
        }
        TelemetryCommand::On => {
            let level = match config_level(&paths.config)? {
                Some(Level::Full) => Level::Full,
                _ => Level::Standard,
            };
            set_level(paths, env, level)
        }
        TelemetryCommand::Off => set_level(paths, env, Level::Off),
        TelemetryCommand::Level { level } => set_level(paths, env, level),
        TelemetryCommand::Purge { yes } => purge(&root, yes),
    }
}

fn status(paths: &Paths, root: &Path, env: Option<&str>) -> Result<String, Failure> {
    let (level, source) = resolve_level(None, env, &paths.config)?;
    let source = match source {
        LevelSource::Config => format!(
            "{} {}",
            source.describe(),
            paths.config.join(super::CONFIG_FILE).display()
        ),
        _ => source.describe().to_string(),
    };
    let mut out = format!("telemetry: {} (from {source})\n", level.as_str());
    out.push_str(&format!("data: {}\n", root.display()));
    let instances = tar::instance_dirs(root)?;
    if instances.is_empty() {
        out.push_str("  no telemetry collected yet\n");
    }
    for (name, dir) in instances {
        let files =
            writer::day_files(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        let bytes: u64 = files.iter().map(|(_, _, len)| len).sum();
        let range = match (files.first(), files.last()) {
            (Some((first, _, _)), Some((last, _, _))) => {
                format!(", {}..{}", day_stamp(*first), day_stamp(*last))
            }
            _ => String::new(),
        };
        out.push_str(&format!(
            "  {name}: {} files, {}{range}\n",
            files.len(),
            human_bytes(bytes)
        ));
    }
    out.push_str(&format!(
        "retention: {RETENTION_DAYS} days; cap per instance {} at standard, {} at full\n",
        human_bytes(Level::Standard.cap_bytes()),
        human_bytes(Level::Full.cap_bytes())
    ));
    out.push_str(
        "privacy: local only, nothing leaves this machine; records hold no file names, paths, \
         contents or credentials\n",
    );
    out.push_str(
        "opt out: zdrive telemetry off, ZDRIVE_TELEMETRY=off or --telemetry off; \
         delete: zdrive telemetry purge --yes; share: zdrive telemetry export --output FILE\n",
    );
    Ok(out)
}

/// Bytes of telemetry kept under `state_dir`, across every instance.
pub(crate) fn stored_bytes(state_dir: &Path) -> Result<u64, String> {
    let mut total = 0u64;
    for (_, dir) in tar::instance_dirs(&state_dir.join(DIR_NAME))? {
        let files =
            writer::day_files(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        total = total.saturating_add(files.iter().map(|(_, _, len)| len).sum());
    }
    Ok(total)
}

fn set_level(paths: &Paths, env: Option<&str>, level: Level) -> Result<String, Failure> {
    save_config_level(&paths.config, level)?;
    let mut out = format!(
        "telemetry level set to {} in {}; a running zdrive keeps its level until it restarts\n",
        level.as_str(),
        paths.config.join(super::CONFIG_FILE).display()
    );
    if let Some(value) = env.filter(|value| !value.trim().is_empty()) {
        match Level::parse(value) {
            Some(effective) if effective == level => {}
            Some(effective) => out.push_str(&format!(
                "note: {ENV_VAR}={} overrides this setting while it is set\n",
                effective.as_str()
            )),
            None => out.push_str(&format!(
                "note: {ENV_VAR} holds an invalid value; valid levels are off, standard or full\n"
            )),
        }
    }
    if level == Level::Off {
        out.push_str("existing telemetry is kept; delete it with: zdrive telemetry purge --yes\n");
    }
    Ok(out)
}

fn purge(root: &Path, yes: bool) -> Result<String, Failure> {
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok("no telemetry to delete\n".to_string());
        }
        Err(error) => return Err(Failure::runtime(format!("{}: {error}", root.display()))),
    };
    if !metadata.is_dir() {
        return Err(Failure::runtime(format!(
            "{} is not a real directory; refusing to delete it",
            root.display()
        )));
    }
    let (files, bytes) = tar::instance_dirs(root)?
        .iter()
        .filter_map(|(_, dir)| writer::day_files(dir).ok())
        .flatten()
        .fold((0usize, 0u64), |(files, bytes), (_, _, len)| {
            (files + 1, bytes + len)
        });
    if !yes {
        return Err(Failure::usage(format!(
            "refusing to delete {} ({files} files, {}) without --yes",
            root.display(),
            human_bytes(bytes)
        )));
    }
    std::fs::remove_dir_all(root)
        .map_err(|error| Failure::runtime(format!("delete {}: {error}", root.display())))?;
    Ok(format!(
        "deleted {} ({files} files, {})\na running zdrive keeps collecting until it stops; \
         run `zdrive telemetry off` first to stop collection\n",
        root.display(),
        human_bytes(bytes)
    ))
}

fn day_stamp(day: i64) -> String {
    let (year, month, day) = system::civil_from_days(day);
    format!("{year:04}-{month:02}-{day:02}")
}

pub(crate) fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = "B";
    for next in UNITS {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    format!("{value:.1} {unit}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;

    fn paths(dir: &TestDir) -> Paths {
        Paths {
            config: dir.path().join("config").join("zerotrust-drive"),
            state: dir.path().join("state").join("zerotrust-drive"),
            data: dir.path().join("data").join("zerotrust-drive"),
        }
    }

    fn ok(command: TelemetryCommand, paths: &Paths, env: Option<&str>) -> String {
        execute(command, paths, env, system::now_ms()).expect("command succeeds")
    }

    #[test]
    fn level_commands_persist_a_private_config_and_status_reports_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new("telemetry-cli-level");
        let paths = paths(&dir);
        let status = ok(TelemetryCommand::Status, &paths, None);
        assert!(
            status.starts_with("telemetry: standard (from default)"),
            "{status}"
        );
        assert!(status.contains("nothing leaves this machine"), "{status}");
        assert!(status.contains("zdrive telemetry off"), "{status}");

        ok(TelemetryCommand::Level { level: Level::Full }, &paths, None);
        let config = paths.config.join(super::super::CONFIG_FILE);
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "{\"level\":\"full\"}\n"
        );
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&config), 0o600);
        assert_eq!(mode(&paths.config), 0o700);

        ok(TelemetryCommand::On, &paths, None);
        assert_eq!(
            config_level(&paths.config),
            Ok(Some(Level::Full)),
            "on keeps full"
        );
        let off = ok(TelemetryCommand::Off, &paths, Some("full"));
        assert!(off.contains("ZDRIVE_TELEMETRY=full overrides"), "{off}");
        assert_eq!(config_level(&paths.config), Ok(Some(Level::Off)));
        ok(TelemetryCommand::On, &paths, None);
        assert_eq!(config_level(&paths.config), Ok(Some(Level::Standard)));
        let status = ok(TelemetryCommand::Status, &paths, None);
        assert!(
            status.starts_with("telemetry: standard (from config file"),
            "{status}"
        );

        let failure = execute(TelemetryCommand::Status, &paths, Some("loud"), 0).unwrap_err();
        assert!(
            failure.message.contains("off, standard or full"),
            "{failure:?}"
        );
    }

    #[test]
    fn purge_requires_yes_and_report_rejects_bad_arguments() {
        let dir = TestDir::new("telemetry-cli-purge");
        let paths = paths(&dir);
        let instance = paths.state.join(DIR_NAME).join("zdrive");
        std::fs::create_dir_all(&instance).unwrap();
        std::fs::write(instance.join("20260101.jsonl"), b"{}\n").unwrap();

        let refused = execute(TelemetryCommand::Purge { yes: false }, &paths, None, 0).unwrap_err();
        assert_eq!(refused.code, 2);
        assert!(refused.message.contains("without --yes"), "{refused:?}");
        assert!(instance.join("20260101.jsonl").exists());
        let purged = ok(TelemetryCommand::Purge { yes: true }, &paths, None);
        assert!(purged.contains("1 files"), "{purged}");
        assert!(!paths.state.join(DIR_NAME).exists());
        assert_eq!(
            ok(TelemetryCommand::Purge { yes: true }, &paths, None),
            "no telemetry to delete\n"
        );

        for (since, instance) in [(Some("soon"), None), (None, Some("Bad/Name"))] {
            let failure = execute(
                TelemetryCommand::Report {
                    since: since.map(str::to_string),
                    json: false,
                    instance: instance.map(str::to_string),
                },
                &paths,
                None,
                0,
            )
            .unwrap_err();
            assert_eq!(failure.code, 2, "{failure:?}");
        }
    }

    #[test]
    fn human_bytes_are_compact() {
        assert_eq!(human_bytes(12), "12 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(64 << 20), "64.0 MiB");
    }
}
