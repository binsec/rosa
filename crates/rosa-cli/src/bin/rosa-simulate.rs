//! Simulate a ROSA detection campaign using data from an existing campaign.
//!
//! In order to avoid the costly (in terms of time) part of a detection campaign (i.e., waiting for
//! a given amount of hours in order for the fuzzer to generate inputs), we can reuse the generated
//! inputs but change various configuration parameters (e.g., phase 1 duration). This tool allows
//! us to "simulate" a detection campaign via this mechanism, while reusing inputs.

use std::{
    fs,
    io::ErrorKind,
    os::unix,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
use colored::Colorize;
use itertools::Itertools;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

use rosa_cli::{
    config::{Config, phase_one::PhaseOne},
    error_message, info_message, println_error, println_info, rosa_message,
};
use rosa_core::{
    clustering, error,
    error::RosaError,
    fail,
    oracle::{Decision, DecisionReason, Discriminants, Oracle, TimedDecision},
    trace::Trace,
};

/// A "timed" variant of [rosa_core::trace::Trace].
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

    /// Force the use of a phase-1 corpus directory (regardless of what the configuration says).
    #[arg(long_help, long, help = "Force use of phase-1 corpus directory")]
    phase_one_corpus: Option<PathBuf>,
}

/// Run the simulation.
fn run(
    existing_rosa_dir: &Path,
    config_file: &Path,
    copy_inputs: bool,
    force: bool,
    phase_one_corpus: Option<&Path>,
) -> Result<(), RosaError> {
    // Load the configuration and set up the output directories.
    let mut config = Config::load(config_file)?;
    if let Some(phase_one_corpus_dir) = phase_one_corpus {
        // Make the config use a phase-1 corpus.
        config.phase_one = PhaseOne::Corpus(phase_one_corpus_dir.to_path_buf());
    }

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
                                .is_none_or(|file_name| file_name != "README.txt")
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
    let all_traces = rosa_cli::trace::load_traces_from_dir(&config.traces_dir())?;

    let timed_traces: Vec<TimedTrace> = all_traces
        .par_iter()
        .map(|trace: &Trace| {
            rosa_cli::oracle::load_decision_from_file(
                &old_decisions_dir.join(trace.id()).with_extension("toml"),
            )
            .map(|timed_decision| TimedTrace {
                trace: trace.clone(),
                seconds: timed_decision.seconds,
            })
        })
        .collect::<Result<Vec<TimedTrace>, RosaError>>()?;

    // Handle phase-1 corpus.
    let (phase_1_timed_traces, phase_2_timed_traces) = match config.phase_one {
        PhaseOne::Corpus(ref corpus_dir) => {
            let phase_one_traces = rosa_cli::trace::load_traces_from_dir(corpus_dir)?;
            // Save the traces in the output directory.
            rosa_cli::trace::save_traces_to_dir(&phase_one_traces, &config.traces_dir())?;
            // Save the trace decisions and log the traces in the database.
            phase_one_traces.clone().into_iter().try_for_each(|trace| {
                let decision = TimedDecision {
                    decision: Decision {
                        trace_id: trace.id(),
                        trace_name: trace.name.clone(),
                        cluster_id: "<none>".to_string(),
                        is_backdoor: false,
                        reason: DecisionReason::Seed,
                        discriminants: Discriminants {
                            trace_edges: Vec::new(),
                            cluster_edges: Vec::new(),
                            trace_syscalls: Vec::new(),
                            cluster_syscalls: Vec::new(),
                        },
                    },
                    seconds: 0,
                };
                rosa_cli::oracle::save_decision_to_file(&decision, &config.decisions_dir())
            })?;

            (
                phase_one_traces
                    .into_iter()
                    .map(|trace| TimedTrace { trace, seconds: 0 })
                    .collect(),
                timed_traces,
            )
        }
        PhaseOne::Seconds(seconds) => timed_traces
            .clone()
            .into_iter()
            .partition(|timed_trace| timed_trace.seconds <= seconds),
        _ => unimplemented!("phase one condition not supported."),
    };

    // Cluster phase 1 traces.
    println_info!(
        "Clustering phase 1 traces ({})...",
        phase_1_timed_traces.len()
    );
    let phase_1_traces: Vec<Trace> = phase_1_timed_traces
        .iter()
        .sorted_by_key(|timed_trace| timed_trace.seconds)
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
    rosa_cli::clustering::save_clusters_to_dir(&clusters, &config.clusters_dir())?;

    // Save decisions for phase 1 traces.
    phase_1_timed_traces
        .into_iter()
        .try_for_each(|timed_trace| {
            let timed_decision = TimedDecision {
                decision: Decision {
                    trace_id: timed_trace.trace.id(),
                    trace_name: timed_trace.trace.name.clone(),
                    cluster_id: "<none>".to_string(),
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

            rosa_cli::oracle::save_decision_to_file(&timed_decision, &config.decisions_dir())
        })?;

    // Run the oracle on phase 2 traces & save decisions and backdoors..
    println_info!(
        "Running the oracle on phase 2 traces ({})...",
        phase_2_timed_traces.len()
    );
    phase_2_timed_traces
        .par_iter()
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
            rosa_cli::oracle::save_decision_to_file(&timed_decision, &config.decisions_dir())?;

            if timed_decision.decision.is_backdoor {
                // Get the fingerprint to deduplicate backdoor.
                // Essentially, if the backdoor was detected for the same reason as a
                // pre-existing backdoor, we should avoid listing them as two different
                // backdoors.
                let fingerprint = timed_decision
                    .decision
                    .discriminants
                    .fingerprint(config.oracle_criterion, &timed_decision.decision.cluster_id);

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
                rosa_cli::trace::save_test_input_to_file(
                    &timed_trace.trace,
                    &backdoor_dir.join(timed_trace.trace.id()),
                )?;
            }

            Ok(())
        })?;

    println_info!("Done!");

    Ok(())
}

fn main() -> ExitCode {
    rosa_cli::reset_sigpipe();

    let cli = Cli::parse();

    match run(
        &cli.rosa_dir,
        &cli.config_file,
        cli.copy_inputs,
        cli.force,
        cli.phase_one_corpus.as_deref(),
    ) {
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
