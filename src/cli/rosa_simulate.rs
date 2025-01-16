//! Simulate a ROSA detection campaign using data from an existing campaign.
//!
//! In order to avoid the costly (in terms of time) part of a detection campaign (i.e., waiting for
//! a given amount of hours in order for the fuzzer to generate inputs), we can reuse the generated
//! inputs but change various configuration parameters (e.g., phase 1 duration). This tool allows
//! us to "simulate" a detection campaign via this mechanism, while reusing inputs.

use std::{
    collections::HashMap,
    fs,
    io::ErrorKind,
    os::unix,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
use colored::Colorize;

use rosa::{
    clustering,
    config::Config,
    error,
    error::RosaError,
    fail,
    oracle::{Decision, DecisionReason, Discriminants, TimedDecision},
    trace::{self, Trace},
};

mod common;
#[macro_use]
#[allow(unused_macros)]
mod logging;

/// A "timed" variant of [rosa::trace::Trace].
#[derive(Debug, Clone)]
struct TimedTrace {
    /// The trace itself.
    trace: Trace,
    /// The time at which the trace was discovered (in seconds).
    seconds: u64,
}

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Simulate a backdoor detection campaign based on existing data.",
    long_about = None,
    propagate_version = true
)]
struct Cli {
    /// The existing ROSA output directory to pull test inputs from.
    #[arg(
        long_help,
        value_name = "ROSA DIR",
        help = "Existing ROSA output directory"
    )]
    rosa_dir: PathBuf,
    /// The configuration file to use.
    #[arg(
        long_help,
        default_value = "config.toml",
        value_name = "CONFIG FILE",
        help = "Configuration file"
    )]
    config_file: PathBuf,
    /// Perform a true copy of the test inputs and trace files instead of using a symbolic link.
    #[arg(long_help, short = 'C', long, help = "Use true copy")]
    copy_inputs: bool,
    /// Force the creation of the output directory, potentially overwriting existing results.
    #[arg(
        long_help,
        short,
        long,
        help = "Force (auto-delete existing) output directory"
    )]
    force: bool,
}

/// Run the simulation.
fn run(
    existing_rosa_dir: &Path,
    config_file: &Path,
    copy_inputs: bool,
    force: bool,
) -> Result<(), RosaError> {
    let config = Config::load(config_file)?;
    let old_traces_dir = existing_rosa_dir
        .to_path_buf()
        .join("traces")
        .canonicalize()
        .expect("failed to canonicalize old traces directory path.");
    let old_decisions_dir = existing_rosa_dir
        .to_path_buf()
        .join("decisions")
        .canonicalize()
        .expect("failed to canonicalize old decisions directory path.");
    let old_stats_file = existing_rosa_dir
        .to_path_buf()
        .join("stats")
        .with_extension("csv")
        .canonicalize()
        .expect("failed to canonicalize old stats file path.");

    println_info!("Setting up new output directory...");
    config.setup_dirs(force)?;
    config.save(&config.output_dir.join("config").with_extension("toml"))?;
    fs::copy(
        &old_stats_file,
        config.output_dir.join("stats").with_extension("csv"),
    )
    .map_err(|err| {
        error!(
            "could not copy stats file from {}: {}.",
            old_stats_file.display(),
            err
        )
    })?;

    println_info!(
        "Copying traces from {} ({})...",
        existing_rosa_dir.display(),
        if copy_inputs {
            "with true copy"
        } else {
            "with symbolic link"
        }
    );
    if copy_inputs {
        // Copy every test input and trace from the old directory to the new one.
        let test_inputs_and_traces: Vec<PathBuf> = fs::read_dir(&old_traces_dir).map_or_else(
            |err| {
                fail!(
                    "invalid traces directory '{}': {}.",
                    old_traces_dir.display(),
                    err
                )
            },
            |res| {
                Ok(res
                    // Ignore files/dirs we cannot read.
                    .filter_map(|item| item.ok())
                    .map(|item| item.path())
                    // Pick up everything except the README file.
                    .filter(|path| {
                        path.is_file()
                            && path
                                .file_name()
                                .is_none_or(|file_name| file_name == "README.txt")
                    })
                    .collect())
            },
        )?;

        test_inputs_and_traces.into_iter().try_for_each(|file| {
            fs::copy(
                &file,
                config.traces_dir().join(
                    file.file_name()
                        .expect("failed to get file name for test input/trace."),
                ),
            )
            .map_or_else(
                |err| {
                    fail!(
                        "could not copy test inputs and traces to {}: {}.",
                        config.traces_dir().display(),
                        err
                    )
                },
                |_| Ok(()),
            )
        })?;
    } else {
        // Remove the newly created (empty) `traces/` directory.
        fs::remove_dir_all(config.traces_dir()).map_err(|err| {
            error!(
                "could not remove '{}': {}.",
                &config.traces_dir().display(),
                err
            )
        })?;
        unix::fs::symlink(&old_traces_dir, config.traces_dir()).map_err(|err| {
            error!(
                "could not create symbolic link {} -> {}: {}.",
                &old_traces_dir.display(),
                &config.traces_dir().display(),
                err
            )
        })?;
    }

    println_info!("Loading traces...");
    let mut known_traces = HashMap::new();
    let all_traces = trace::load_traces(
        &config.traces_dir(),
        &config.traces_dir(),
        "rosa",
        &mut known_traces,
        true,
    )?;

    let timed_traces: Vec<TimedTrace> = all_traces
        .into_iter()
        .map(|trace| {
            TimedDecision::load(&old_decisions_dir.join(trace.uid()).with_extension("toml")).map(
                |timed_decision| TimedTrace {
                    trace,
                    seconds: timed_decision.seconds,
                },
            )
        })
        .collect::<Result<Vec<TimedTrace>, RosaError>>()?;

    // Separate phase 1 and phase 2 traces.
    let (phase_1_timed_traces, phase_2_timed_traces): (Vec<TimedTrace>, Vec<TimedTrace>) =
        timed_traces.clone().into_iter().partition(|timed_trace| {
            timed_trace.seconds
                <= config
                    .seed_conditions
                    .seconds
                    .expect("failed to get phase 1 duration from config.")
        });

    // Cluster phase 1 traces.
    println_info!(
        "Clustering phase 1 traces ({})...",
        phase_1_timed_traces.len()
    );
    let phase_1_traces: Vec<Trace> = phase_1_timed_traces
        .iter()
        .map(|timed_trace| timed_trace.trace.clone())
        .collect();
    let clusters = clustering::cluster_traces(
        &phase_1_traces,
        config.cluster_formation_criterion,
        config.cluster_formation_distance_metric.clone(),
        config.cluster_formation_edge_tolerance,
        config.cluster_formation_syscall_tolerance,
    );
    // Save clusters.
    clustering::save_clusters(&clusters, &config.clusters_dir())?;

    // Save decisions for phase 1 traces.
    phase_1_timed_traces
        .into_iter()
        .try_for_each(|timed_trace| {
            let timed_decision = TimedDecision {
                decision: Decision {
                    trace_uid: timed_trace.trace.uid(),
                    trace_name: timed_trace.trace.name.clone(),
                    cluster_uid: "<none>".to_string(),
                    is_backdoor: false,
                    reason: DecisionReason::Seed,
                    discriminants: Discriminants {
                        trace_edges: Vec::new(),
                        cluster_edges: Vec::new(),
                        trace_syscalls: Vec::new(),
                        cluster_syscalls: Vec::new(),
                    },
                },
                seconds: timed_trace.seconds,
            };

            timed_decision.save(&config.decisions_dir())
        })?;

    // Run the oracle on phase 2 traces & save decisions and backdoors..
    println_info!(
        "Running the oracle on phase 2 traces ({})...",
        phase_2_timed_traces.len()
    );
    phase_2_timed_traces
        .into_iter()
        .try_for_each(|timed_trace| {
            let most_similar_cluster = clustering::get_most_similar_cluster(
                &timed_trace.trace,
                &clusters,
                config.cluster_selection_criterion,
                config.cluster_selection_distance_metric.clone(),
            )
            .expect("failed to get most similar cluster.");

            let timed_decision = TimedDecision {
                decision: config.oracle.decide(
                    &timed_trace.trace,
                    most_similar_cluster,
                    config.oracle_criterion,
                    config.oracle_distance_metric.clone(),
                ),
                seconds: timed_trace.seconds,
            };

            // Save decision.
            timed_decision.save(&config.decisions_dir())?;

            if timed_decision.decision.is_backdoor {
                // Get the fingerprint to deduplicate backdoor.
                // Essentially, if the backdoor was detected for the same reason as a
                // pre-existing backdoor, we should avoid listing them as two different
                // backdoors.
                let fingerprint = timed_decision.decision.discriminants.fingerprint(
                    config.oracle_criterion,
                    &timed_decision.decision.cluster_uid,
                );

                // Attempt to create a directory for this category of backdoor.
                let backdoor_dir = config.backdoors_dir().join(fingerprint);
                match fs::create_dir(&backdoor_dir) {
                    Ok(_) => Ok(()),
                    Err(error) => match error.kind() {
                        ErrorKind::AlreadyExists => Ok(()),
                        _ => Err(error),
                    },
                }
                .map_err(|err| error!("could not create '{}': {}", &backdoor_dir.display(), err))?;

                // Save backdoor.
                trace::save_trace_test_input(&timed_trace.trace, &backdoor_dir)?;
            }

            Ok(())
        })?;

    println_info!("Done!");

    Ok(())
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let cli = Cli::parse();

    match run(&cli.rosa_dir, &cli.config_file, cli.copy_inputs, cli.force) {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            println_error!(err);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert()
    }
}
