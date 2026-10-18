// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! macOS LaunchAgent per instance in the user's GUI domain.

use std::ffi::OsString;
use std::path::PathBuf;

use super::definition::{Definition, STOP_TIMEOUT_SECS};
use super::{
    Host, Output, Runner, ServiceStatus, failure, os_args, remove_if_present, run_checked,
    run_command, write_public_file,
};

pub(crate) const LABEL_PREFIX: &str = "net.loxal.zerotrust-drive.";
const LAUNCHCTL: &str = "/bin/launchctl";
/// launchd's minimum delay between two starts of a crashing instance.
const THROTTLE_INTERVAL_SECS: u64 = 30;

pub(crate) fn label(name: &str) -> String {
    format!("{LABEL_PREFIX}{name}")
}

pub(crate) fn plist_path(host: &Host, name: &str) -> PathBuf {
    host.home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{}.plist", label(name)))
}

pub(crate) fn log_dir(host: &Host) -> PathBuf {
    host.home
        .join("Library")
        .join("Logs")
        .join("zerotrust-drive")
}

pub(crate) fn log_path(host: &Host, name: &str) -> PathBuf {
    log_dir(host).join(format!("{name}.log"))
}

fn domain(host: &Host) -> String {
    format!("gui/{}", host.uid)
}

fn service_target(host: &Host, name: &str) -> String {
    format!("{}/{}", domain(host), label(name))
}

fn xml_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// The LaunchAgent property list of instance `name`.
///
/// ProcessType is Interactive: the FUSE server sits on the path of every
/// file operation that Finder and applications perform on the mount, so
/// launchd's Background throttling of CPU and I/O would stall those
/// foreground applications behind it.
pub(crate) fn plist(host: &Host, name: &str, binary: &str) -> String {
    let string = |value: &str| format!("<string>{}</string>", xml_escape(value));
    let log = log_path(host, name).to_string_lossy().into_owned();
    let mut lines = vec![
        r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_string(),
        r#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">"#.to_string(),
        r#"<plist version="1.0">"#.to_string(),
        "<dict>".to_string(),
        "\t<key>Label</key>".to_string(),
        format!("\t{}", string(&label(name))),
        "\t<key>ProgramArguments</key>".to_string(),
        "\t<array>".to_string(),
    ];
    for argument in [binary, "service", "run", name] {
        lines.push(format!("\t\t{}", string(argument)));
    }
    lines.push("\t</array>".to_string());
    if !host.xdg_environment.is_empty() {
        lines.push("\t<key>EnvironmentVariables</key>".to_string());
        lines.push("\t<dict>".to_string());
        for (key, value) in &host.xdg_environment {
            lines.push(format!("\t\t<key>{}</key>", xml_escape(key)));
            lines.push(format!("\t\t{}", string(value)));
        }
        lines.push("\t</dict>".to_string());
    }
    lines.extend([
        "\t<key>RunAtLoad</key>".to_string(),
        "\t<true/>".to_string(),
        "\t<key>KeepAlive</key>".to_string(),
        "\t<dict>".to_string(),
        "\t\t<key>SuccessfulExit</key>".to_string(),
        "\t\t<false/>".to_string(),
        "\t</dict>".to_string(),
        "\t<key>ThrottleInterval</key>".to_string(),
        format!("\t<integer>{THROTTLE_INTERVAL_SECS}</integer>"),
        "\t<key>ExitTimeOut</key>".to_string(),
        format!("\t<integer>{STOP_TIMEOUT_SECS}</integer>"),
        "\t<key>LimitLoadToSessionType</key>".to_string(),
        format!("\t{}", string("Aqua")),
        "\t<key>ProcessType</key>".to_string(),
        format!("\t{}", string("Interactive")),
        "\t<key>StandardOutPath</key>".to_string(),
        format!("\t{}", string(&log)),
        "\t<key>StandardErrorPath</key>".to_string(),
        format!("\t{}", string(&log)),
        "</dict>".to_string(),
        "</plist>".to_string(),
    ]);
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// launchctl's answer for a job that is not loaded: ESRCH (3) on older
/// releases, 113 ("Could not find specified service") on newer ones.
fn not_loaded(output: &Output) -> bool {
    let stderr = output.stderr_text();
    matches!(output.status, Some(3) | Some(113))
        || stderr.contains("No such process")
        || stderr.contains("Could not find")
}

/// `launchctl bootout`; `Ok(true)` when a loaded job was removed.
fn bootout(host: &Host, name: &str, runner: &dyn Runner) -> Result<bool, String> {
    let args = os_args(["bootout".to_string(), service_target(host, name)]);
    let output = run_command(runner, LAUNCHCTL, &args, None)?;
    if output.success() {
        Ok(true)
    } else if not_loaded(&output) {
        Ok(false)
    } else {
        Err(failure(LAUNCHCTL, &args, &output))
    }
}

pub(crate) fn install(
    host: &Host,
    def: &Definition,
    binary: &str,
    runner: &dyn Runner,
) -> Result<Vec<String>, String> {
    let name = &def.name;
    let plist_path = plist_path(host, name);
    if let Some(dir) = plist_path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
    }
    crate::remote::ensure_private_dir(&log_dir(host)).map_err(|error| error.to_string())?;
    write_public_file(&plist_path, plist(host, name, binary).as_bytes())?;
    let mut lines = vec![format!("wrote {}", plist_path.display())];
    if bootout(host, name, runner)? {
        lines.push(format!("stopped the previous {}", label(name)));
    }
    let args = vec![
        OsString::from("bootstrap"),
        OsString::from(domain(host)),
        plist_path.clone().into_os_string(),
    ];
    run_checked(runner, LAUNCHCTL, &args, None).map_err(|error| {
        format!(
            "{error}; check `plutil -lint {}` and that {} is logged in to the graphical session",
            super::shell_path(&plist_path),
            host.user
        )
    })?;
    lines.push(format!(
        "started {} now and at every login; log: {}",
        label(name),
        log_path(host, name).display()
    ));
    Ok(lines)
}

pub(crate) fn uninstall(
    host: &Host,
    name: &str,
    runner: &dyn Runner,
) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    if bootout(host, name, runner)? {
        lines.push(format!("stopped {}", label(name)));
    } else {
        lines.push(format!("{} was not loaded", label(name)));
    }
    let plist_path = plist_path(host, name);
    if remove_if_present(&plist_path)? {
        lines.push(format!("deleted {}", plist_path.display()));
    }
    Ok(lines)
}

/// The fields of `launchctl print` that [`ServiceStatus`] reports. Only the
/// job's own top-level `key = value` lines count; nested blocks such as
/// `environment = { ... }` are indented further.
pub(crate) fn parse_print(text: &str, status: &mut ServiceStatus) {
    for line in text.lines() {
        let Some(line) = line.strip_prefix('\t') else {
            continue;
        };
        if line.starts_with('\t') {
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        let value = value.trim();
        let leading_int = |value: &str| {
            let end = value
                .char_indices()
                .find(|&(index, character)| {
                    !(character.is_ascii_digit() || (index == 0 && character == '-'))
                })
                .map_or(value.len(), |(index, _)| index);
            value[..end].parse::<i64>().ok()
        };
        match key.trim() {
            "state" => status.state = value.to_string(),
            "pid" => status.pid = leading_int(value).and_then(|pid| u32::try_from(pid).ok()),
            "last exit code" => {
                status.last_exit_status =
                    leading_int(value).and_then(|code| i32::try_from(code).ok());
            }
            "runs" => status.runs = leading_int(value).and_then(|runs| u32::try_from(runs).ok()),
            _ => {}
        }
    }
    status.running = status.state == "running";
}

pub(crate) fn status(
    host: &Host,
    name: &str,
    runner: &dyn Runner,
) -> Result<ServiceStatus, String> {
    let mut status = ServiceStatus {
        name: name.to_string(),
        installed: plist_path(host, name).exists(),
        ..ServiceStatus::default()
    };
    let args = os_args(["print".to_string(), service_target(host, name)]);
    let output = run_command(runner, LAUNCHCTL, &args, None)?;
    if output.success() {
        parse_print(&output.stdout_text(), &mut status);
        if status.state.is_empty() {
            status.state = "loaded".to_string();
        }
    } else if not_loaded(&output) {
        status.state = "not loaded".to_string();
    } else {
        return Err(failure(LAUNCHCTL, &args, &output));
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;
    use crate::service::definition::{Custody, Instance};
    use crate::service::testing::{FakeRunner, exit, host, ok, secret_file};
    use crate::service::{Platform, install_on, status_on, uninstall_on};

    /// A minimal reader for the plist subset that [`plist`] writes.
    #[derive(Debug, PartialEq)]
    enum Value {
        String(String),
        Integer(i64),
        Bool(bool),
        Array(Vec<Value>),
        Dict(Vec<(String, Value)>),
    }

    fn unescape(text: &str) -> String {
        text.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&")
    }

    fn tokens(xml: &str) -> Vec<String> {
        let body = xml
            .split_once("<plist version=\"1.0\">")
            .unwrap()
            .1
            .rsplit_once("</plist>")
            .unwrap()
            .0;
        let mut tokens = Vec::new();
        let mut rest = body;
        while let Some(start) = rest.find('<') {
            let text = rest[..start].trim();
            if !text.is_empty() {
                tokens.push(text.to_string());
            }
            let end = rest[start..].find('>').unwrap() + start;
            tokens.push(rest[start..=end].to_string());
            rest = &rest[end + 1..];
        }
        tokens
    }

    fn parse(tokens: &[String], at: &mut usize) -> Value {
        let tag = tokens[*at].clone();
        *at += 1;
        let text = |at: &mut usize, close: &str| {
            let value = if tokens[*at] == close {
                String::new()
            } else {
                *at += 1;
                unescape(&tokens[*at - 1])
            };
            assert_eq!(tokens[*at], close);
            *at += 1;
            value
        };
        match tag.as_str() {
            "<true/>" => Value::Bool(true),
            "<false/>" => Value::Bool(false),
            "<string>" => Value::String(text(at, "</string>")),
            "<integer>" => Value::Integer(text(at, "</integer>").parse().unwrap()),
            "<array>" => {
                let mut items = Vec::new();
                while tokens[*at] != "</array>" {
                    items.push(parse(tokens, at));
                }
                *at += 1;
                Value::Array(items)
            }
            "<dict>" => {
                let mut entries = Vec::new();
                while tokens[*at] != "</dict>" {
                    assert_eq!(tokens[*at], "<key>");
                    let key = unescape(&tokens[*at + 1]);
                    assert_eq!(tokens[*at + 2], "</key>");
                    *at += 3;
                    entries.push((key, parse(tokens, at)));
                }
                *at += 1;
                Value::Dict(entries)
            }
            other => panic!("unexpected token {other}"),
        }
    }

    fn parse_plist(xml: &str) -> Vec<(String, Value)> {
        let tokens = tokens(xml);
        let mut at = 0;
        let Value::Dict(entries) = parse(&tokens, &mut at) else {
            panic!("the plist root is not a dict");
        };
        assert_eq!(at, tokens.len());
        entries
    }

    fn string(text: &str) -> Value {
        Value::String(text.to_string())
    }

    fn definition(dir: &TestDir) -> Definition {
        let secret = secret_file(dir);
        Definition {
            name: "encrypted".to_string(),
            instance: Instance::Encrypted {
                remote: Some("home".to_string()),
                encrypted_dir: PathBuf::from("/abs/store"),
                mount_dir: PathBuf::from("/abs/mount"),
                custody: Custody::File(secret),
            },
            final_push_wait_secs: 60,
        }
    }

    #[test]
    fn service_plist_has_every_documented_key() {
        let dir = TestDir::new("service-plist");
        let host = host(&dir, Platform::MacOs);
        let log = log_path(&host, "encrypted").display().to_string();
        let entries = parse_plist(&plist(&host, "encrypted", "/opt/z drive/zdrive"));
        let expected = vec![
            ("Label", string("net.loxal.zerotrust-drive.encrypted")),
            (
                "ProgramArguments",
                Value::Array(vec![
                    string("/opt/z drive/zdrive"),
                    string("service"),
                    string("run"),
                    string("encrypted"),
                ]),
            ),
            ("RunAtLoad", Value::Bool(true)),
            (
                "KeepAlive",
                Value::Dict(vec![("SuccessfulExit".to_string(), Value::Bool(false))]),
            ),
            ("ThrottleInterval", Value::Integer(30)),
            ("ExitTimeOut", Value::Integer(90)),
            ("LimitLoadToSessionType", string("Aqua")),
            ("ProcessType", string("Interactive")),
            ("StandardOutPath", string(&log)),
            ("StandardErrorPath", string(&log)),
        ];
        let expected: Vec<(String, Value)> = expected
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect();
        assert_eq!(entries, expected);
        assert!(log.ends_with("/home/Library/Logs/zerotrust-drive/encrypted.log"));
    }

    #[test]
    fn service_plist_escapes_xml_and_carries_xdg_environment() {
        let dir = TestDir::new("service-plist-escape");
        let mut host = host(&dir, Platform::MacOs);
        host.xdg_environment = vec![("XDG_CONFIG_HOME".to_string(), "/cfg/<a&b>".to_string())];
        let xml = plist(&host, "x", "/opt/a&b<c>'\"/zdrive");
        assert!(xml.contains("<string>/opt/a&amp;b&lt;c&gt;&apos;&quot;/zdrive</string>"));
        let entries = parse_plist(&xml);
        assert_eq!(
            entries[1].1,
            Value::Array(vec![
                string("/opt/a&b<c>'\"/zdrive"),
                string("service"),
                string("run"),
                string("x"),
            ])
        );
        assert_eq!(entries[2].0, "EnvironmentVariables");
        assert_eq!(
            entries[2].1,
            Value::Dict(vec![("XDG_CONFIG_HOME".to_string(), string("/cfg/<a&b>"))])
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn service_plist_passes_plutil_lint() {
        let dir = TestDir::new("service-plutil");
        let mut host = host(&dir, Platform::MacOs);
        host.xdg_environment = vec![("XDG_STATE_HOME".to_string(), "/s & t".to_string())];
        let path = dir.path().join("agent.plist");
        std::fs::write(&path, plist(&host, "lint", "/opt/a&b/zdrive")).unwrap();
        let output = std::process::Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    fn service_launchd_install_writes_plist_then_bootout_and_bootstrap() {
        let dir = TestDir::new("service-launchd-install");
        let host = host(&dir, Platform::MacOs);
        let def = definition(&dir);
        let runner = FakeRunner::new(|argv, _| {
            if argv.contains("bootout") {
                exit(
                    113,
                    "",
                    "Boot-out failed: 113: Could not find specified service",
                )
            } else {
                ok("")
            }
        });
        let lines = install_on(&host, &def, std::path::Path::new("/opt/zdrive"), &runner).unwrap();
        let plist_file = plist_path(&host, "encrypted");
        assert_eq!(
            runner.argv(),
            [
                "/bin/launchctl bootout gui/501/net.loxal.zerotrust-drive.encrypted".to_string(),
                format!("/bin/launchctl bootstrap gui/501 {}", plist_file.display()),
            ]
        );
        assert!(
            plist_file
                .ends_with("home/Library/LaunchAgents/net.loxal.zerotrust-drive.encrypted.plist")
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&plist_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
        let logs = std::fs::metadata(log_dir(&host))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(logs & 0o777, 0o700);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].contains("at every login"));
    }

    #[test]
    fn service_launchd_install_reports_bootout_and_bootstrap_failures() {
        let dir = TestDir::new("service-launchd-install-fail");
        let host = host(&dir, Platform::MacOs);
        let def = definition(&dir);
        let reloaded = FakeRunner::succeeding();
        let lines =
            install_on(&host, &def, std::path::Path::new("/opt/zdrive"), &reloaded).unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("stopped the previous"))
        );

        let bootout = FakeRunner::new(|_, _| exit(5, "", "Boot-out failed: 5: Input/output error"));
        let error =
            install_on(&host, &def, std::path::Path::new("/opt/zdrive"), &bootout).unwrap_err();
        assert!(error.contains("Input/output error"), "{error}");
        assert_eq!(bootout.argv().len(), 1);

        let bootstrap = FakeRunner::new(|argv, _| {
            if argv.contains("bootstrap") {
                exit(
                    125,
                    "",
                    "Bootstrap failed: 125: Domain does not support specified action",
                )
            } else {
                exit(3, "", "Boot-out failed: 3: No such process")
            }
        });
        let error =
            install_on(&host, &def, std::path::Path::new("/opt/zdrive"), &bootstrap).unwrap_err();
        assert!(error.contains("Domain does not support"), "{error}");
        assert!(
            error.contains("logged in to the graphical session"),
            "{error}"
        );
    }

    #[test]
    fn service_launchd_uninstall_boots_out_and_removes_the_plist() {
        let dir = TestDir::new("service-launchd-uninstall");
        let host = host(&dir, Platform::MacOs);
        let def = definition(&dir);
        def.save(&host.paths).unwrap();
        install_on(
            &host,
            &def,
            std::path::Path::new("/opt/zdrive"),
            &FakeRunner::succeeding(),
        )
        .unwrap();
        let runner = FakeRunner::succeeding();
        let lines = uninstall_on(&host, "encrypted", false, &runner).unwrap();
        assert_eq!(
            runner.argv(),
            ["/bin/launchctl bootout gui/501/net.loxal.zerotrust-drive.encrypted"]
        );
        assert!(!plist_path(&host, "encrypted").exists());
        assert!(lines[0].starts_with("stopped"));
        assert!(lines.last().unwrap().contains("kept the definition"));
        assert!(Definition::load(&host.paths, "encrypted").is_ok());

        let again = FakeRunner::new(|_, _| exit(3, "", "Boot-out failed: 3: No such process"));
        let lines = uninstall_on(&host, "encrypted", false, &again).unwrap();
        assert!(lines[0].contains("was not loaded"), "{lines:?}");
    }

    #[test]
    fn service_launchd_status_parses_launchctl_print() {
        let dir = TestDir::new("service-launchd-status");
        let host = host(&dir, Platform::MacOs);
        let print = "gui/501/net.loxal.zerotrust-drive.encrypted = {\n\tactive count = 1\n\tpath = /Users/alex/Library/LaunchAgents/net.loxal.zerotrust-drive.encrypted.plist\n\ttype = LaunchAgent\n\tstate = running\n\n\tprogram = /opt/zdrive\n\targuments = {\n\t\t/opt/zdrive\n\t\tservice\n\t}\n\n\tenvironment = {\n\t\tstate = nested\n\t\tpid = 1\n\t}\n\n\truns = 3\n\tpid = 4242\n\timmediate reason = speculative\n\tlast exit code = 1: Operation not permitted\n}\n";
        let runner = FakeRunner::new(move |_, _| ok(print));
        let status = status_on(&host, "encrypted", &runner).unwrap();
        assert_eq!(
            runner.argv(),
            ["/bin/launchctl print gui/501/net.loxal.zerotrust-drive.encrypted"]
        );
        assert_eq!(
            status,
            ServiceStatus {
                name: "encrypted".to_string(),
                installed: false,
                running: true,
                state: "running".to_string(),
                pid: Some(4242),
                last_exit_status: Some(1),
                runs: Some(3),
                restarts: None,
            }
        );

        let mut never = ServiceStatus::default();
        parse_print(
            "x = {\n\tstate = not running\n\truns = 0\n\tlast exit code = (never exited)\n}\n",
            &mut never,
        );
        assert_eq!(never.state, "not running");
        assert!(!never.running);
        assert_eq!(never.last_exit_status, None);
        assert_eq!(never.runs, Some(0));

        let unloaded = FakeRunner::new(|_, _| {
            exit(
                113,
                "",
                "Could not find service \"x\" in domain for user gui: 501",
            )
        });
        let status = status_on(&host, "encrypted", &unloaded).unwrap();
        assert_eq!(status.state, "not loaded");
        assert!(!status.running);

        let broken = FakeRunner::new(|_, _| exit(1, "", "launchctl exploded"));
        assert!(status_on(&host, "encrypted", &broken).is_err());
    }
}
