// © Pranav Verma | 2026
// config.rs

//! A configuration file for the options that would otherwise be a long command
//! line.
//!
//! Precedence, strongest first: a flag on the command line, then an
//! environment variable, then this file, then the built-in default. The file
//! speaks the same words as the flags (`--max-flows` is `max-flows`), so there
//! is one vocabulary to learn and nothing to keep in step: a key is checked
//! against the real options of the command being run, and a misspelt or
//! unknown key is an error that lists the valid ones, never silently ignored.
//!
//! Top-level keys are the options every command accepts (`rules`,
//! `alert-file`, `max-flows`). A table named after a command holds that
//! command's own options (`[serve]`, `[live]`, `[pcap]`).
//!
//! Applied by rewriting the argument list before the real parse: each key the
//! operator did not already supply becomes the flag it names. That keeps one
//! parser and one set of validations (value ranges, types) for both sources.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::parser::ValueSource;
use clap::{Arg, ArgMatches, Command, CommandFactory};

use crate::cli::Cli;

/// The file name looked for in the data directory when `--config` is not given.
pub const FILE_NAME: &str = "tlsfp.toml";

/// Where the configuration is looked for when `--config` is not given.
#[must_use]
pub fn default_path() -> PathBuf {
    tlsfp_intel::default_db_path().with_file_name(FILE_NAME)
}

/// The template `tlsfp config example` prints.
pub const EXAMPLE: &str = r#"# tlsfp.toml: options you would otherwise type on the command line.
#
# Precedence, strongest first: a flag, an environment variable, this file,
# the built-in default. Keys are the flag names without the leading dashes.
# Run `tlsfp serve --help` to see every option. An unknown key is an error.
#
# Use it with:  tlsfp --config tlsfp.toml serve
# or put it at the default location (`tlsfp config path` prints it) and it is
# read automatically.

# Options every command accepts ----------------------------------------------
# rules = "my-rules.toml"
# alert-file = "alerts.jsonl"
# alert-syslog = "udp://siem.example:514"
# alert-min-severity = "medium"
# max-flows = 200000
# idle-timeout = 60
# stream-limit-kib = 256

[serve]
# live = "auto"
# bind = "127.0.0.1:8080"
# location = "DC-2 rack 14"
# library = ["/srv/captures"]
# local-network = ["203.0.113.0/24"]
# shared-network = ["10.0.0.0/8"]
# allowed-host = ["dash.lan"]
# filter = "tcp or (udp and (port 443 or port 53))"
# buffer-mib = 64
# keep-days = 90
# keep-alert-days = 365
# max-observations = 5000000

[live]
# filter = "tcp port 443"
# buffer-mib = 64
# detect = true
# intel = true
"#;

/// Returns the argument list with the configuration file folded in. When there
/// is no file, or the arguments do not parse (the real parse will say why), the
/// list comes back unchanged.
pub fn apply(args: Vec<OsString>) -> Result<Vec<OsString>> {
    let mut command = Cli::command();
    let Ok(matches) = command.try_get_matches_from_mut(args.clone()) else {
        return Ok(args);
    };
    let explicit = matches.get_one::<PathBuf>("config").cloned();
    let path = if let Some(path) = explicit {
        path
    } else {
        let fallback = default_path();
        if !fallback.is_file() {
            return Ok(args);
        }
        fallback
    };
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading the configuration file {}", path.display()))?;
    let table: toml::Table = text
        .parse()
        .with_context(|| format!("{} is not valid TOML", path.display()))?;
    let merged = inject(&Cli::command(), &matches, args, &table)
        .with_context(|| format!("configuration file {}", path.display()))?;
    tracing::debug!(file = %path.display(), "configuration file applied");
    Ok(merged)
}

fn id_of(key: &str) -> String {
    key.replace('-', "_")
}

/// True when the operator already supplied this option, by flag or variable.
fn supplied(matches: &ArgMatches, id: &str) -> bool {
    matches!(
        matches.value_source(id),
        Some(ValueSource::CommandLine | ValueSource::EnvVariable)
    )
}

fn scalar(key: &str, value: &toml::Value) -> Result<String> {
    match value {
        toml::Value::String(s) => Ok(s.clone()),
        toml::Value::Integer(n) => Ok(n.to_string()),
        toml::Value::Float(f) => Ok(f.to_string()),
        toml::Value::Boolean(b) => Ok(b.to_string()),
        _ => bail!("`{key}` must be text, a number, or a list of them"),
    }
}

/// The arguments a configuration value stands for.
fn flags_for(arg: &Arg, key: &str, value: &toml::Value) -> Result<Vec<String>> {
    let long = arg
        .get_long()
        .with_context(|| format!("`{key}` cannot be set in the configuration file"))?;
    if !arg.get_action().takes_values() {
        return match value {
            toml::Value::Boolean(true) => Ok(vec![format!("--{long}")]),
            toml::Value::Boolean(false) => Ok(Vec::new()),
            _ => bail!("`{key}` is a switch: use true or false"),
        };
    }
    let mut out = Vec::new();
    match value {
        toml::Value::Array(items) => {
            for item in items {
                out.push(format!("--{long}"));
                out.push(scalar(key, item)?);
            }
        }
        other => {
            out.push(format!("--{long}"));
            out.push(scalar(key, other)?);
        }
    }
    Ok(out)
}

fn valid_keys(command: &Command, global_only: bool) -> String {
    let mut keys: Vec<&str> = command
        .get_arguments()
        .filter(|a| a.get_id() != "help" && a.get_id() != "version" && a.get_id() != "config")
        .filter(|a| !global_only || a.is_global_set())
        .filter_map(|a| {
            a.get_long()
                .or_else(|| a.is_positional().then(|| a.get_id().as_str()))
        })
        .collect();
    keys.sort_unstable();
    keys.join(", ")
}

/// Folds `table` into `args` for the command `matches` selected.
fn inject(
    root: &Command,
    matches: &ArgMatches,
    args: Vec<OsString>,
    table: &toml::Table,
) -> Result<Vec<OsString>> {
    let (sub_name, sub_matches) = matches.subcommand().unzip();

    let mut global_flags: Vec<String> = Vec::new();
    let mut sub_flags: Vec<String> = Vec::new();
    let mut trailing: Vec<String> = Vec::new();

    for (key, value) in table {
        if let toml::Value::Table(section) = value {
            // A table is a command's own options; only the running command's applies.
            if root.find_subcommand(key).is_none() {
                bail!(
                    "unknown section [{key}]; sections are named after commands ({})",
                    root.get_subcommands()
                        .map(Command::get_name)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            let running = Some(key.as_str()) == sub_name;
            let Some(command) = root.find_subcommand(key) else {
                continue;
            };
            for (k, v) in section {
                // Every section is checked, so a typo is caught even in a table
                // for a command that is not running now; only the running
                // command's options are applied.
                let arg = command
                    .get_arguments()
                    .find(|a| a.get_id().as_str() == id_of(k))
                    .filter(|a| !a.is_global_set())
                    .with_context(|| {
                        format!(
                            "unknown option `{k}` in [{key}]; valid options: {}",
                            valid_keys(command, false)
                        )
                    })?;
                let (true, Some(m)) = (running, sub_matches) else {
                    continue;
                };
                if supplied(m, arg.get_id().as_str()) {
                    continue;
                }
                let flags = if arg.is_positional() {
                    vec![scalar(k, v)?]
                } else {
                    flags_for(arg, k, v)?
                };
                if arg.is_positional() {
                    trailing.extend(flags);
                } else {
                    sub_flags.extend(flags);
                }
            }
        } else {
            let arg = root
                .get_arguments()
                .find(|a| a.get_id().as_str() == id_of(key) && a.is_global_set())
                .filter(|a| a.get_id() != "config")
                .with_context(|| {
                    format!(
                        "unknown option `{key}`; options every command accepts: {}. \
                         Options of one command go in a [command] table",
                        valid_keys(root, true)
                    )
                })?;
            let seen = sub_matches.is_some_and(|m| supplied(m, arg.get_id().as_str()))
                || supplied(matches, arg.get_id().as_str());
            if !seen {
                global_flags.extend(flags_for(arg, key, value)?);
            }
        }
    }

    let mut out: Vec<OsString> = Vec::with_capacity(args.len() + 8);
    let mut rest = args.into_iter();
    out.extend(rest.next());
    out.extend(global_flags.into_iter().map(OsString::from));
    let mut placed = sub_flags.is_empty();
    for arg in rest {
        let is_sub = !placed && sub_name.is_some_and(|name| arg == name);
        out.push(arg);
        if is_sub {
            out.extend(
                std::mem::take(&mut sub_flags)
                    .into_iter()
                    .map(OsString::from),
            );
            placed = true;
        }
    }
    out.extend(trailing.into_iter().map(OsString::from));
    Ok(out)
}

/// What `tlsfp config path` prints.
#[must_use]
pub fn describe_default(path: &Path) -> String {
    if path.is_file() {
        format!("{} (exists and is read automatically)", path.display())
    } else {
        format!(
            "{} (does not exist; create it to have it read automatically)",
            path.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn run(args: &[&str], config: &str) -> Result<Cli> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let matches = Cli::command().try_get_matches_from(args.clone())?;
        let table: toml::Table = config.parse()?;
        let merged = inject(&Cli::command(), &matches, args, &table)?;
        Ok(Cli::try_parse_from(merged)?)
    }

    fn serve(cli: &Cli) -> (&Option<String>, &String, bool) {
        match &cli.command {
            crate::cli::Command::Serve {
                live,
                bind,
                no_promisc,
                ..
            } => (live, bind, *no_promisc),
            other => panic!("expected serve, got {other:?}"),
        }
    }

    #[test]
    fn a_key_the_operator_did_not_give_is_taken_from_the_file() {
        let cli = run(
            &["tlsfp", "serve"],
            "[serve]\nlive = \"eth0\"\nbind = \"0.0.0.0:9000\"\nno-promisc = true\n",
        )
        .unwrap();
        let (live, bind, no_promisc) = serve(&cli);
        assert_eq!(live.as_deref(), Some("eth0"));
        assert_eq!(bind, "0.0.0.0:9000");
        assert!(no_promisc);
    }

    #[test]
    fn a_flag_beats_the_file() {
        let cli = run(
            &["tlsfp", "serve", "--live", "wlan0"],
            "[serve]\nlive = \"eth0\"\n",
        )
        .unwrap();
        assert_eq!(serve(&cli).0.as_deref(), Some("wlan0"));
    }

    #[test]
    fn options_every_command_accepts_go_at_the_top_and_lists_repeat() {
        let cli = run(
            &["tlsfp", "serve"],
            "max-flows = 123456\nalert-file = \"a.jsonl\"\n\n[serve]\nlocal-network = [\"10.1.0.0/16\", \"10.2.0.0/16\"]\n",
        )
        .unwrap();
        assert_eq!(cli.engine.max_flows, 123_456);
        assert_eq!(cli.alert_file.as_deref(), Some(Path::new("a.jsonl")));
        match &cli.command {
            crate::cli::Command::Serve { local_network, .. } => assert_eq!(local_network.len(), 2),
            _ => panic!("expected serve"),
        }
    }

    #[test]
    fn another_commands_section_is_left_alone() {
        let cli = run(
            &["tlsfp", "serve"],
            "[live]\nfilter = \"tcp port 22\"\n[serve]\nlive = \"eth0\"\n",
        )
        .unwrap();
        assert_eq!(serve(&cli).0.as_deref(), Some("eth0"));
    }

    #[test]
    fn a_misspelt_key_is_an_error_that_lists_the_valid_ones() {
        let error = run(&["tlsfp", "serve"], "[serve]\nfiter = \"x\"\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown option `fiter`"), "{error}");
        assert!(error.contains("filter"), "{error}");
        let top = run(&["tlsfp", "serve"], "max-flowz = 1\n")
            .unwrap_err()
            .to_string();
        assert!(top.contains("unknown option `max-flowz`"), "{top}");
        let section = run(&["tlsfp", "serve"], "[servee]\nlive = \"x\"\n")
            .unwrap_err()
            .to_string();
        assert!(section.contains("unknown section [servee]"), "{section}");
    }

    #[test]
    fn a_typo_is_caught_even_in_a_section_for_another_command() {
        let error = run(&["tlsfp", "serve"], "[live]\nfiltr = \"x\"\n")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("unknown option `filtr` in [live]"),
            "{error}"
        );
    }

    #[test]
    fn values_are_still_validated_by_the_normal_parser() {
        // max-flows has a range; the file does not get to bypass it.
        assert!(run(&["tlsfp", "serve"], "max-flows = 5\n").is_err());
    }

    #[test]
    fn a_switch_must_be_true_or_false() {
        assert!(run(&["tlsfp", "serve"], "[serve]\nno-promisc = \"yes\"\n").is_err());
        let cli = run(&["tlsfp", "serve"], "[serve]\nno-promisc = false\n").unwrap();
        assert!(!serve(&cli).2);
    }

    #[test]
    fn the_example_is_valid_and_changes_nothing_until_a_line_is_uncommented() {
        let table: toml::Table = EXAMPLE.parse().unwrap();
        assert!(table.contains_key("serve") && table.contains_key("live"));
        let cli = run(&["tlsfp", "serve"], EXAMPLE).unwrap();
        assert_eq!(serve(&cli).1, "127.0.0.1:8080");
    }

    #[test]
    fn every_uncommented_example_line_is_accepted() {
        let live: String = EXAMPLE
            .lines()
            .map(|l| {
                l.strip_prefix("# ")
                    .filter(|r| r.contains(" = "))
                    .unwrap_or(l)
            })
            .collect::<Vec<_>>()
            .join("\n");
        // A key from [live] with no [live] header would be misplaced, so only
        // check that the whole uncommented file parses as TOML and loads for serve.
        let table: toml::Table = live.parse().unwrap();
        let cli = run(&["tlsfp", "serve"], &live);
        assert!(cli.is_ok(), "{:?} {table:?}", cli.err());
    }
}
