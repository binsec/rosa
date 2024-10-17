//! Generate ROSA configs based on presets.
//!
//! This binary helps create configuration files for new targets without delving into all of the
//! configuration options.

use std::{io, path::PathBuf, process::ExitCode};

use colored::Colorize;

#[macro_use]
#[allow(unused_macros)]
mod logging;

use rosa::{
    config::{Config, FuzzerConfig, SeedConditions},
    error,
    error::RosaError,
};

/// Get (and parse) some input from stdin.
///
/// # Parameters
/// * `question` - The question to ask the user (e.g., "Username").
/// * `convert` - A conversion function from raw input ([String]) to the expected type `T`.
/// * `default` - A default value (in case the input is empty).
/// * `printable_default` - A printable version of the default value that we can show to the user.
fn get_input<T, F>(
    question: &str,
    convert: F,
    default: T,
    printable_default: &str,
) -> Result<T, RosaError>
where
    T: std::cmp::PartialEq + Clone + std::fmt::Debug,
    F: Fn(&str) -> Option<T>,
{
    let stdin = io::stdin();

    loop {
        let mut buffer = String::new();

        print_info!("{}? [default: {}] > ", question, printable_default);
        stdin
            .read_line(&mut buffer)
            .map_err(|err| error!("could not read value from stdin: {}", err))?;

        // Remove the trailing newline.
        let buffer = buffer.trim().to_string();

        match buffer.is_empty() {
            true => break Ok(default.clone()),
            false => {
                if let Some(choice) = convert(&buffer) {
                    break Ok(choice);
                }
            }
        }
    }
}

/// Generate a configuration interactively, through stdin.
///
/// Ask the user for the most important configuration settings, and generate a template-based
/// configuration file.
fn generate_config() -> Result<(Config, PathBuf), RosaError> {
    let default_config_file_name = PathBuf::from("config.toml");
    let default_rosa_output_dir = PathBuf::from("rosa-out");
    let default_phase_1_duration = 20;
    let default_target_path: PathBuf = ["/path", "to", "target"].iter().collect();
    let default_target_arguments = "--arg1 --arg2".to_string();
    let default_fuzzer_path: PathBuf = ["/root", "aflpp", "afl-fuzz"].iter().collect();
    let default_fuzzer_output_dir = PathBuf::from("fuzzer-out");
    let default_seed_dir_path = PathBuf::from("seeds");

    let default_fuzzer_configs = vec![
        FuzzerConfig {
            name: "main".to_string(),
            env: vec![
                ("AFL_INST_LIBS", "1"),
                ("AFL_NO_ARITH", "1"),
                ("AFL_SYNC_TIME", "1"),
                ("AFL_COMPCOV_LEVEL", "2"),
                ("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1"),
                ("AFL_SKIP_CPUFREQ", "1"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
            cmd: vec![
                "-r", "-Q", "-c", "0", "-a", "ascii", "-p", "explore", "-M", "main",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            test_input_dir: vec!["main", "queue"].into_iter().collect(),
            trace_dump_dir: vec!["main", "trace_dumps"].into_iter().collect(),
            crashes_dir: vec!["main", "crashes"].into_iter().collect(),
        },
        FuzzerConfig {
            name: "fast-libs".to_string(),
            env: vec![
                ("AFL_INST_LIBS", "1"),
                ("AFL_NO_ARITH", "1"),
                ("AFL_SYNC_TIME", "1"),
                ("AFL_COMPCOV_LEVEL", "2"),
                ("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1"),
                ("AFL_SKIP_CPUFREQ", "1"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
            cmd: vec![
                "-r",
                "-Q",
                "-c",
                "0",
                "-a",
                "ascii",
                "-p",
                "fast",
                "-S",
                "fast-libs",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            test_input_dir: vec!["fast-libs", "queue"].into_iter().collect(),
            trace_dump_dir: vec!["fast-libs", "trace_dumps"].into_iter().collect(),
            crashes_dir: vec!["fast-libs", "crashes"].into_iter().collect(),
        },
        FuzzerConfig {
            name: "exploit-libs".to_string(),
            env: vec![
                ("AFL_INST_LIBS", "1"),
                ("AFL_SYNC_TIME", "1"),
                ("AFL_COMPCOV_LEVEL", "2"),
                ("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1"),
                ("AFL_SKIP_CPUFREQ", "1"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
            cmd: vec!["-r", "-Q", "-c", "0", "-p", "exploit", "-S", "exploit-libs"]
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
            test_input_dir: vec!["exploit-libs", "queue"].into_iter().collect(),
            trace_dump_dir: vec!["exploit-libs", "trace_dumps"].into_iter().collect(),
            crashes_dir: vec!["exploit-libs", "crashes"].into_iter().collect(),
        },
        FuzzerConfig {
            name: "explore-bin".to_string(),
            env: vec![
                ("AFL_NO_ARITH", "1"),
                ("AFL_SYNC_TIME", "1"),
                ("AFL_COMPCOV_LEVEL", "2"),
                ("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1"),
                ("AFL_SKIP_CPUFREQ", "1"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
            cmd: vec![
                "-r",
                "-Q",
                "-c",
                "0",
                "-a",
                "ascii",
                "-p",
                "explore",
                "-S",
                "explore-bin",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            test_input_dir: vec!["explore-bin", "queue"].into_iter().collect(),
            trace_dump_dir: vec!["explore-bin", "trace_dumps"].into_iter().collect(),
            crashes_dir: vec!["explore-bin", "crashes"].into_iter().collect(),
        },
        FuzzerConfig {
            name: "fast-bin".to_string(),
            env: vec![
                ("AFL_NO_ARITH", "1"),
                ("AFL_SYNC_TIME", "1"),
                ("AFL_COMPCOV_LEVEL", "2"),
                ("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1"),
                ("AFL_SKIP_CPUFREQ", "1"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
            cmd: vec![
                "-r", "-Q", "-c", "0", "-a", "ascii", "-p", "fast", "-S", "fast-bin",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            test_input_dir: vec!["fast-bin", "queue"].into_iter().collect(),
            trace_dump_dir: vec!["fast-bin", "trace_dumps"].into_iter().collect(),
            crashes_dir: vec!["fast-bin", "crashes"].into_iter().collect(),
        },
        FuzzerConfig {
            name: "exploit-bin".to_string(),
            env: vec![
                ("AFL_SYNC_TIME", "1"),
                ("AFL_COMPCOV_LEVEL", "2"),
                ("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1"),
                ("AFL_SKIP_CPUFREQ", "1"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
            cmd: vec!["-r", "-Q", "-c", "0", "-p", "exploit", "-S", "exploit-bin"]
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
            test_input_dir: vec!["exploit-bin", "queue"].into_iter().collect(),
            trace_dump_dir: vec!["exploit-bin", "trace_dumps"].into_iter().collect(),
            crashes_dir: vec!["exploit-bin", "crashes"].into_iter().collect(),
        },
    ];

    let config_file_name = get_input(
        "Configuration file name",
        |x| Some(x.to_string().into()),
        default_config_file_name.clone(),
        &default_config_file_name.display().to_string(),
    )?;
    let rosa_output_dir = get_input(
        "ROSA output directory name",
        |x| Some(x.to_string().into()),
        default_rosa_output_dir.clone(),
        &default_rosa_output_dir.display().to_string(),
    )?;
    let phase_1_duration = get_input(
        "Phase 1 duration (in seconds)",
        |x| x.parse::<u64>().ok(),
        default_phase_1_duration,
        &default_phase_1_duration.to_string(),
    )?;
    let target_path = get_input(
        "Path to target program (absolute)",
        |x| Some(x.to_string().into()),
        default_target_path.clone(),
        &default_target_path.display().to_string(),
    )?;
    let target_arguments = get_input(
        "Path to target program (absolute)",
        |x| Some(x.to_string()),
        default_target_arguments.clone(),
        &default_target_arguments,
    )?;
    let fuzzer_path = get_input(
        "Path to fuzzer (absolute)",
        |x| Some(x.to_string().into()),
        default_fuzzer_path.clone(),
        &default_fuzzer_path.display().to_string(),
    )?;
    let fuzzer_output_dir = get_input(
        "Fuzzer output directory name",
        |x| Some(x.to_string().into()),
        default_fuzzer_output_dir.clone(),
        &default_fuzzer_output_dir.display().to_string(),
    )?;
    let seed_dir_path = get_input(
        "Path to seed directory (absolute)",
        |x| Some(x.to_string().into()),
        default_seed_dir_path.clone(),
        &default_seed_dir_path.display().to_string(),
    )?;

    Ok((
        Config {
            output_dir: rosa_output_dir,
            fuzzers: default_fuzzer_configs
                .into_iter()
                .map(|fuzzer_config| FuzzerConfig {
                    name: fuzzer_config.name,
                    env: fuzzer_config.env,
                    cmd: [
                        vec![
                            fuzzer_path.display().to_string(),
                            "-i".to_string(),
                            seed_dir_path.display().to_string(),
                        ],
                        fuzzer_config.cmd,
                        vec!["--".to_string(), target_path.display().to_string()],
                        target_arguments.split(" ").map(|s| s.to_string()).collect(),
                    ]
                    .concat(),
                    test_input_dir: fuzzer_output_dir.join(&fuzzer_config.test_input_dir),
                    trace_dump_dir: fuzzer_output_dir.join(&fuzzer_config.trace_dump_dir),
                    crashes_dir: fuzzer_output_dir.join(&fuzzer_config.crashes_dir),
                })
                .collect(),
            seed_conditions: SeedConditions {
                seconds: Some(phase_1_duration),
                edge_coverage: None,
                syscall_coverage: None,
            },
            deduplicator: None,
            cluster_formation_criterion: Config::default_cluster_formation_criterion(),
            cluster_formation_distance_metric: Config::default_cluster_formation_distance_metric(),
            cluster_formation_edge_tolerance: Config::default_cluster_formation_edge_tolerance(),
            cluster_formation_syscall_tolerance:
                Config::default_cluster_formation_syscall_tolerance(),
            cluster_selection_criterion: Config::default_cluster_selection_criterion(),
            cluster_selection_distance_metric: Config::default_cluster_selection_distance_metric(),
            oracle: Config::default_oracle(),
            oracle_criterion: Config::default_oracle_criterion(),
            oracle_distance_metric: Config::default_oracle_distance_metric(),
        },
        config_file_name,
    ))
}

fn main() -> ExitCode {
    let config_file: Result<PathBuf, RosaError> = generate_config()
        .and_then(|(config, config_file)| config.save(&config_file).map(|()| config_file));

    match config_file {
        Ok(config_file) => {
            println_info!(
                "Done! The configuration is saved in '{}'.",
                config_file.display()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            println_error!(err);
            ExitCode::FAILURE
        }
    }
}
