//! Generate ROSA configs based on presets.
//!
//! This binary helps create configuration files for new targets without delving into all of the
//! configuration options.

use std::{io, path::PathBuf, process::ExitCode};

use colored::Colorize;

mod common;
#[macro_use]
#[allow(unused_macros)]
mod logging;

use rosa::{
    config::{Config, SeedConditions},
    error,
    error::RosaError,
    fuzzer::FuzzerConfig,
};

/// Generate a configuration for a fuzzer.
///
/// This is a helper function to avoid repetition when generating fuzzer configurations.
fn generate_fuzzer_config(
    name: &str,
    power_schedule: &str,
    instrument_libs: bool,
    ascii: bool,
    main: bool,
) -> FuzzerConfig {
    let env = vec![
        ("AFL_SYNC_TIME", "1"),
        ("AFL_COMPCOV_LEVEL", "2"),
        ("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1"),
        ("AFL_SKIP_CPUFREQ", "1"),
    ];
    let cmd = vec!["-Q", "-c", "0", "-p", power_schedule];

    let env = if instrument_libs {
        [env, vec![("AFL_INST_LIBS", "1")]].concat()
    } else {
        env
    };

    let (env, cmd) = if ascii {
        (
            [env, vec![("AFL_NO_ARITH", "1")]].concat(),
            [cmd, vec!["-a", "ascii"]].concat(),
        )
    } else {
        (env, cmd)
    };

    let cmd = if main {
        // Only the main instance needs to dump traces by default.
        [cmd, vec!["-r", "-M", name]].concat()
    } else {
        [cmd, vec!["-S", name]].concat()
    };

    FuzzerConfig {
        name: name.to_string(),
        env: env
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        cmd: cmd.into_iter().map(|s| s.to_string()).collect(),
        test_input_dir: vec![name, "queue"].into_iter().collect(),
        trace_dump_dir: vec![name, "trace_dumps"].into_iter().collect(),
        crashes_dir: vec![name, "crashes"].into_iter().collect(),
    }
}

/// Get (and parse) some input from `stdin`.
///
/// Ask a question and parse some input. The input will be passed to a conversion function, and if
/// it is empty a default value will be used instead. A printable default is supplied to be shown
/// to the user.
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
    let default_phase_1_duration = 60;
    let default_target_path: PathBuf = ["/path", "to", "target"].iter().collect();
    let default_target_arguments = "".to_string();
    let default_fuzzer_path: PathBuf = ["/root", "aflpp", "afl-fuzz"].iter().collect();
    let default_fuzzer_output_dir = PathBuf::from("fuzzer-out");
    let default_seed_dir_path = PathBuf::from("seeds");

    let default_fuzzer_configs = vec![
        generate_fuzzer_config("main", "explore", true, true, true),
        generate_fuzzer_config("fast-libs", "fast", true, true, false),
        generate_fuzzer_config("exploit-libs", "exploit", true, false, false),
        generate_fuzzer_config("explore-bin", "explore", false, true, false),
        generate_fuzzer_config("fast-bin", "fast", false, true, false),
        generate_fuzzer_config("exploit-bin", "exploit", false, false, false),
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
        "Path to target program",
        |x| Some(x.to_string().into()),
        default_target_path.clone(),
        &default_target_path.display().to_string(),
    )?;
    let target_arguments = get_input(
        "Arguments to target program",
        |x| Some(x.to_string()),
        default_target_arguments.clone(),
        "<none>",
    )?;
    let fuzzer_path = get_input(
        "Path to fuzzer",
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
        "Path to seed directory",
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
                            "-o".to_string(),
                            fuzzer_output_dir.display().to_string(),
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
    common::reset_sigpipe();
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
