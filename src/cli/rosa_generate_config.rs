//! Generate ROSA configs based on presets.
//!
//! This binary helps create configuration files for new targets without delving into all of the
//! configuration options.

use std::{
    io,
    path::{Path, PathBuf},
    process::ExitCode,
};

use colored::Colorize;

use rosa::{
    config::{Config, SeedConditions},
    error,
    error::RosaError,
    fuzzer::{aflpp::AFLPlusPlus, FuzzerConfig},
};

mod common;
#[macro_use]
#[allow(unused_macros)]
mod logging;

/// Generate a configuration for a fuzzer.
///
/// This is a helper function to avoid repetition when generating fuzzer configurations.
#[allow(clippy::too_many_arguments)]
fn generate_fuzzer_config(
    name: &str,
    afl_fuzz: &Path,
    input_dir: &Path,
    output_dir: &Path,
    target: &[String],
    power_schedule: &str,
    is_main: bool,
    has_instrument_libs: bool,
    is_ascii: bool,
) -> FuzzerConfig {
    let env = vec![
        ("AFL_SYNC_TIME", "1"),
        ("AFL_COMPCOV_LEVEL", "2"),
        ("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1"),
        ("AFL_SKIP_CPUFREQ", "1"),
    ];
    let extra_args = vec!["-Q", "-c", "0", "-p", power_schedule];

    let env = if has_instrument_libs {
        [env, vec![("AFL_INST_LIBS", "1")]].concat()
    } else {
        env
    };

    let (env, extra_args) = if is_ascii {
        (
            [env, vec![("AFL_NO_ARITH", "1")]].concat(),
            [extra_args, vec!["-a", "ascii"]].concat(),
        )
    } else {
        (env, extra_args)
    };

    let extra_args = if is_main {
        // Only the main instance needs to dump traces by default.
        [extra_args, vec!["-r"]].concat()
    } else {
        extra_args
    };

    FuzzerConfig {
        backend: Box::new(AFLPlusPlus {
            name: name.to_string(),
            is_main,
            afl_fuzz: afl_fuzz.to_path_buf(),
            input_dir: input_dir.to_path_buf(),
            output_dir: output_dir.to_path_buf(),
            target: target.iter().map(|arg| arg.to_string()).collect(),
            extra_args: extra_args.iter().map(|arg| arg.to_string()).collect(),
            env: env
                .into_iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        }),
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

        if buffer.is_empty() {
            break Ok(default.clone());
        } else if let Some(choice) = convert(&buffer) {
            break Ok(choice);
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
    let default_fuzzer_path: PathBuf = ["/root", "rosa", "fuzzers", "aflpp", "aflpp", "afl-fuzz"]
        .iter()
        .collect();
    let default_fuzzer_output_dir = PathBuf::from("fuzzer-out");
    let default_seed_dir = PathBuf::from("seeds");

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
        "Path to afl-fuzz",
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
    let seed_dir = get_input(
        "Path to seed directory",
        |x| Some(x.to_string().into()),
        default_seed_dir.clone(),
        &default_seed_dir.display().to_string(),
    )?;

    let full_target_command: Vec<String> = [
        vec![target_path.display().to_string()],
        target_arguments
            .split(" ")
            .map(|arg| arg.to_string())
            .collect(),
    ]
    .concat();

    Ok((
        Config {
            output_dir: rosa_output_dir,
            fuzzers: vec![
                generate_fuzzer_config(
                    "main",
                    &fuzzer_path,
                    &seed_dir,
                    &fuzzer_output_dir,
                    &full_target_command,
                    "explore",
                    // Is main?
                    true,
                    // Has AFL_INST_LIBS?
                    true,
                    // Is ASCII?
                    true,
                ),
                generate_fuzzer_config(
                    "fast-libs",
                    &fuzzer_path,
                    &seed_dir,
                    &fuzzer_output_dir,
                    &full_target_command,
                    "fast",
                    // Is main?
                    false,
                    // Has AFL_INST_LIBS?
                    true,
                    // Is ASCII?
                    true,
                ),
                generate_fuzzer_config(
                    "exploit-libs",
                    &fuzzer_path,
                    &seed_dir,
                    &fuzzer_output_dir,
                    &full_target_command,
                    "exploit",
                    // Is main?
                    false,
                    // Has AFL_INST_LIBS?
                    true,
                    // Is ASCII?
                    false,
                ),
                generate_fuzzer_config(
                    "explore-bin",
                    &fuzzer_path,
                    &seed_dir,
                    &fuzzer_output_dir,
                    &full_target_command,
                    "explore",
                    // Is main?
                    false,
                    // Has AFL_INST_LIBS?
                    false,
                    // Is ASCII?
                    true,
                ),
                generate_fuzzer_config(
                    "fast-bin",
                    &fuzzer_path,
                    &seed_dir,
                    &fuzzer_output_dir,
                    &full_target_command,
                    "fast",
                    // Is main?
                    false,
                    // Has AFL_INST_LIBS?
                    false,
                    // Is ASCII?
                    true,
                ),
                generate_fuzzer_config(
                    "exploit-bin",
                    &fuzzer_path,
                    &seed_dir,
                    &fuzzer_output_dir,
                    &full_target_command,
                    "exploit",
                    // Is main?
                    false,
                    // Has AFL_INST_LIBS?
                    false,
                    // Is ASCII?
                    false,
                ),
            ],
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
