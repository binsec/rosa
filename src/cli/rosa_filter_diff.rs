//! Filter ROSA's findings through differential testing.

use std::{
    collections::HashMap,
    fs::{self, File},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use clap::Parser;
use colored::Colorize;
use itertools::Itertools;

use rosa::{
    clustering::Cluster,
    config::Config,
    error,
    error::RosaError,
    fail,
    oracle::{Decision, DecisionReason, Discriminants, TimedDecision},
    trace::{self, Trace, TraceDatabase},
};

mod common;
#[macro_use]
#[allow(unused_macros)]
mod logging;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Detect backdoors in binary programs.",
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
    /// The configuration file to use for the "base" version of the target program.
    #[arg(
        long_help,
        value_name = "BASE CONFIG FILE",
        help = "Configuration file for base program"
    )]
    base_config_file: PathBuf,
    /// The output directory where to store the findings.
    #[arg(long_help, value_name = "OUTPUT DIR", help = "Output directory")]
    output_dir: PathBuf,
    /// Force the creation of the output directory, potentially overwriting existing results.
    #[arg(
        long_help,
        short,
        long,
        help = "Force (auto-delete existing) output directory"
    )]
    force: bool,
    /// Provide more verbose output about each reevaluation.
    #[arg(long_help, short, long, help = "Be more verbose")]
    verbose: bool,
}

/// Reevaluate a decision.
///
/// In the context of differential filtering, reevaluate a decision by comparing it to a "base"
/// version of the target program. This function takes in a `config` (referring to the "current"
/// version of the program) and a `base_config_file` (referring to the "base" version of the
/// program) and, after running the oracle through the "base" version, decides whether or not the
/// initial decision should be updated.
fn reevaluate_decision(
    trace: &Trace,
    timed_decision: &TimedDecision,
    config: &Config,
    base_config_file: &Path,
    verbose: bool,
) -> Result<TimedDecision, RosaError> {
    let temp_dir = tempfile::tempdir()
        .map_err(|err| error!("could not create temporary directory: {}.", err))?;

    let temp_dir_path = temp_dir.path().to_path_buf();

    // Save the input to a temporary input file, so we can trace it through the base program.
    let input_file_path = temp_dir_path.join("input");
    let mut input_file = File::create(&input_file_path)
        .map_err(|err| error!("could not create temporary input file: {}.", err))?;
    input_file
        .write_all(&trace.test_input)
        .map_err(|err| error!("could not write data to temporary input file: {}.", err))?;

    let trace_file_path = temp_dir_path.join("input.trace");

    // Trace the input through the base program.
    Command::new("rosa-trace")
        .args([
            base_config_file.display().to_string(),
            input_file_path.display().to_string(),
            "--output".to_string(),
            trace_file_path.display().to_string(),
        ])
        .status()
        .map_err(|err| error!("could not run rosa-trace successfully: {}.", err))?
        .success()
        .then_some(())
        .ok_or(error!("rosa-trace failed."))?;
    let base_trace = Trace::load(&trace.uid(), &input_file_path, &trace_file_path)?;

    // Load the cluster to use with the base program.
    let mut cluster = Cluster::load(
        &config
            .output_dir
            .join("clusters")
            .join(&timed_decision.decision.cluster_uid)
            .with_extension("txt"),
        &config.output_dir.join("traces"),
    )?;
    // We need to remap the cluster's traces through the base program.
    cluster.traces = cluster
        .traces
        .into_iter()
        .map(|trace| {
            let input_file_path = temp_dir_path.join("input");
            let mut input_file = File::create(&input_file_path)
                .map_err(|err| error!("could not create temporary input file: {}.", err))?;
            input_file
                .write_all(&trace.test_input)
                .map_err(|err| error!("could not write data to temporary input file: {}.", err))?;

            let trace_file_path = temp_dir_path.join("input.trace");
            Command::new("rosa-trace")
                .args([
                    base_config_file.display().to_string(),
                    input_file_path.display().to_string(),
                    "--output".to_string(),
                    trace_file_path.display().to_string(),
                ])
                .status()
                .map_err(|err| error!("could not run rosa-trace: {}.", err))?
                .success()
                .then_some(())
                .ok_or(error!("rosa-trace failed."))?;

            Trace::load(&trace.uid(), &input_file_path, &trace_file_path)
        })
        .collect::<Result<Vec<Trace>, RosaError>>()?;

    // TODO treat the case where this is not true (essentially, we have to compute these anew).
    cluster.min_edge_distance = config.cluster_formation_edge_tolerance;
    cluster.max_edge_distance = config.cluster_formation_edge_tolerance;
    cluster.min_syscall_distance = config.cluster_formation_syscall_tolerance;
    cluster.max_syscall_distance = config.cluster_formation_syscall_tolerance;

    // Run the oracle on the new trace and the cluster.
    let base_decision = config.oracle.decide(
        &base_trace,
        &cluster,
        config.oracle_criterion,
        config.oracle_distance_metric.clone(),
    );

    if (timed_decision.decision.discriminants.cluster_syscalls
        != base_decision.discriminants.cluster_syscalls)
        || (timed_decision.decision.discriminants.trace_syscalls
            != base_decision.discriminants.trace_syscalls)
    {
        if verbose {
            println_verbose!("  Discriminants are different:");
            if timed_decision.decision.discriminants.cluster_syscalls
                != base_decision.discriminants.cluster_syscalls
            {
                println_verbose!(
                    "    Cluster syscall discriminants in new version: {}",
                    timed_decision
                        .decision
                        .discriminants
                        .cluster_syscalls
                        .iter()
                        .join(", ")
                );
                println_verbose!(
                    "    Cluster syscall discriminants in base version: {}",
                    base_decision
                        .discriminants
                        .cluster_syscalls
                        .iter()
                        .join(", ")
                );
            }
            if timed_decision.decision.discriminants.trace_syscalls
                != base_decision.discriminants.trace_syscalls
            {
                println_verbose!(
                    "    Trace syscall discriminants in new version: {}",
                    timed_decision
                        .decision
                        .discriminants
                        .trace_syscalls
                        .iter()
                        .join(", ")
                );
                println_verbose!(
                    "    Trace syscall discriminants in base version: {}",
                    base_decision.discriminants.trace_syscalls.iter().join(", ")
                );
            }
        }
        // Backdoor is valid, since it does not appear in the base version.
        Ok(timed_decision.clone())
    } else {
        // Backdoor is a false positive, since the exact same discriminants appear in the base
        // version.
        Ok(TimedDecision {
            decision: Decision {
                trace_uid: timed_decision.decision.trace_uid.clone(),
                trace_name: timed_decision.decision.trace_name.clone(),
                cluster_uid: timed_decision.decision.cluster_uid.clone(),
                is_backdoor: false,
                reason: DecisionReason::DiffFiltering,
                discriminants: Discriminants {
                    trace_edges: Vec::new(),
                    cluster_edges: Vec::new(),
                    trace_syscalls: Vec::new(),
                    cluster_syscalls: Vec::new(),
                },
            },
            seconds: timed_decision.seconds,
        })
    }
}

/// Run the differential trace filtering.
///
/// The `existing_rosa_dir` refers to the output directory of ROSA targeting the "current" version
/// of the target program, while the `base_config_file` refers to the ROSA config file targeting the
/// "base" version of the target program.
fn run(
    existing_rosa_dir: &Path,
    base_config_file: &Path,
    output_dir: &Path,
    force: bool,
    verbose: bool,
) -> Result<(), RosaError> {
    let mut config = Config::load(&existing_rosa_dir.join("config").with_extension("toml"))?;
    config.output_dir = output_dir.to_path_buf();
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
    let old_clusters_dir = existing_rosa_dir
        .to_path_buf()
        .join("clusters")
        .canonicalize()
        .expect("failed to canonicalize old clusters directory path.");

    println_info!("Setting up new output directory...");
    config.setup_dirs(force)?;
    config.save(&config.output_dir.join("config").with_extension("toml"))?;

    println_info!("Copying traces from {}...", existing_rosa_dir.display(),);
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

    // Copy every cluster file.
    let cluster_files: Vec<PathBuf> = fs::read_dir(&old_clusters_dir).map_or_else(
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

    cluster_files.into_iter().try_for_each(|file| {
        fs::copy(
            &file,
            config.clusters_dir().join(
                file.file_name()
                    .expect("failed to get file name for cluster."),
            ),
        )
        .map_or_else(
            |err| {
                fail!(
                    "could not copy clusters to {}: {}.",
                    config.clusters_dir().display(),
                    err
                )
            },
            |_| Ok(()),
        )
    })?;

    println_info!("Loading traces...");
    let mut trace_db = TraceDatabase::new();
    let traces = trace::load_traces(
        &config.traces_dir(),
        &config.traces_dir(),
        "rosa",
        &mut trace_db,
        true,
    )?;

    let traces_and_decisions = traces
        .into_iter()
        .map(|trace| {
            TimedDecision::load(&old_decisions_dir.join(trace.uid()).with_extension("toml"))
                .map(|timed_decision| (trace, timed_decision))
        })
        .collect::<Result<Vec<(Trace, TimedDecision)>, RosaError>>()?;

    println_info!("Re-evaluating oracle decisions for potential backdoors...");
    // We will not evaluate every single backdoor finding.
    //
    // Since ROSA deduplicates findings by their discriminant fingerprint (see
    // rosa::oracle::Discriminants), we will only pick the first backdoor finding per fingerprint.
    // The rest of the backdoor findings will be classified in the same way as that fingerprint.
    let mut findings_map = HashMap::new();

    traces_and_decisions
        .into_iter()
        .sorted_by(|(_, timed_decision1), (_, timed_decision2)| {
            Ord::cmp(&timed_decision1.seconds, &timed_decision2.seconds)
        })
        .try_for_each(|(trace, timed_decision)| {
            // Re-evaluate decisions that were flagged as backdoors to remove false positives.
            let timed_decision = if timed_decision.decision.is_backdoor {
                let fingerprint = timed_decision.decision.discriminants.fingerprint(
                    config.oracle_criterion,
                    &timed_decision.decision.cluster_uid,
                );
                // If we've already covered this fingerprint, then apply the same decision without
                // reevaluating.
                if let Some(is_backdoor) = findings_map.get(&fingerprint) {
                    let mut changed_decision = timed_decision.clone();
                    changed_decision.decision.is_backdoor = *is_backdoor;
                    changed_decision.decision.reason = DecisionReason::DiffFiltering;

                    changed_decision
                } else {
                    // We have not covered this fingerprint yet, so we will reevaluate the decision
                    // and store the result in the findings map, to apply it to other findings with
                    // the same fingerprint.
                    if verbose {
                        println_verbose!("Reevaluating decision for {}...", &trace.uid());
                    }
                    let new_decision = reevaluate_decision(
                        &trace,
                        &timed_decision,
                        &config,
                        base_config_file,
                        verbose,
                    )?;
                    if verbose {
                        println_verbose!(
                            "New decision: {}",
                            if new_decision.decision.is_backdoor {
                                "suspicious"
                            } else {
                                "safe"
                            }
                        );
                    }
                    findings_map.insert(fingerprint, new_decision.decision.is_backdoor);

                    new_decision
                }
            } else {
                timed_decision
            };

            timed_decision.save(&config.decisions_dir())?;

            // Save backdoor as per usual.
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
                trace.save_test_input(&backdoor_dir.join(trace.uid()))?;
            }

            Ok(())
        })?;

    Ok(())
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let cli = Cli::parse();

    match run(
        &cli.rosa_dir,
        &cli.base_config_file,
        &cli.output_dir,
        cli.force,
        cli.verbose,
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
