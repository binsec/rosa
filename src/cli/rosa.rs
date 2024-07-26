//! Detect backdoors in binary programs.
//!
//! This is the main ROSA binary; it can be used directly for backdoor detection.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    process::ExitCode,
    sync::mpsc::{self, TryRecvError},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use clap::Parser;
use colored::Colorize;
use rand::Rng;

use rosa::{
    clustering,
    config::{self, Config, RosaPhase},
    decision::{Decision, DecisionReason, TimedDecision},
    error,
    error::RosaError,
    fuzzer::{self, FuzzerProcess, FuzzerStatus},
    trace::{self, Trace},
};

use crate::tui::RosaTui;

#[macro_use]
mod logging;
mod tui;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Detect backdoors in binary programs.",
    long_about = None,
    propagate_version = true
)]
struct Cli {
    /// The configuration file to use.
    #[arg(
        short = 'c',
        long = "config-file",
        default_value = "config.toml",
        value_name = "FILE"
    )]
    config_file: PathBuf,

    /// Force the creation of the output directory, potentially overwriting existing results.
    #[arg(short = 'f', long = "force")]
    force: bool,

    /// Do not wait until all fuzzers have stabilized before starting the detection.
    #[arg(short = 'W', long = "dont-wait-on-fuzzers", action = clap::ArgAction::SetFalse)]
    wait_for_fuzzers: bool,

    /// Be more verbose.
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Disable the TUI and display more linear output on the console.
    #[arg(long = "no-tui")]
    no_tui: bool,

    /// Collect traces from all the fuzzers if there are multiple instances (by default, only
    /// traces from the "main" instance will be collected). Be warned: this will probably speed up
    /// backdoor detection, but it might also produce duplicate traces. Use afl-cmin after the
    /// fact to eliminate duplicates.
    #[arg(long = "collect-from-all-fuzzers")]
    collect_from_all_fuzzers: bool,
}

macro_rules! with_cleanup {
    ( $action:expr, $fuzzer_processes:expr ) => {{
        $action.or_else(|err| {
            $fuzzer_processes
                .iter_mut()
                .try_for_each(|fuzzer_process| fuzzer_process.stop())?;
            Err(err)
        })
    }};
}

/// Helper function to start a fuzzer process.
///
/// Whenever we start up a fuzzer, we should make sure to wait for it to fully stabilize before
/// continuing; especially when loading multiple seed inputs, the fuzzer might take a moment to
/// start. This function blocks until the fuzzer has fully started running if provided with
/// `wait_for_each_fuzzer`, otherwise it starts up the main process before all fuzzers have
/// stabilized.
///
/// # Parameters
/// * `fuzzer_process` - The fuzzer process to start.
/// * `wait_for_each_fuzzer` - Fully block until every fuzzer has fully started up.
/// * `verbose` - Whether we're being verbose or not (affects messages printed to stdout).
fn start_fuzzer_process(
    fuzzer_process: &mut FuzzerProcess,
    wait_for_fuzzers: bool,
    verbose: bool,
) -> Result<(), RosaError> {
    if verbose {
        println_verbose!("  Fuzzer process '{}':", fuzzer_process.name);
        println_verbose!("    Env: {}", fuzzer_process.env_as_string());
        println_verbose!("    Cmd: {}", fuzzer_process.cmd_as_string());
    }

    fuzzer_process.spawn()?;

    // Give the process 200 ms to get up and running.
    thread::sleep(Duration::from_millis(200));

    if wait_for_fuzzers
        && fuzzer::get_fuzzer_status(&fuzzer_process.working_dir)? == FuzzerStatus::Starting
    {
        // Wait until fuzzer is up and running.
        while fuzzer::get_fuzzer_status(&fuzzer_process.working_dir)? != FuzzerStatus::Running {
            if fuzzer::get_fuzzer_status(&fuzzer_process.working_dir)? == FuzzerStatus::Stopped
                || !fuzzer_process.is_running()?
            {
                break;
            }
        }
    }

    Ok(())
}

/// Run the backdoor detection tool.
///
/// # Arguments
/// * `config_file` - Path to the configuration file.
/// * `force` - Force the overwrite of the output directory if it exists.
/// * `wait_for_fuzzers` - Fully block until all fuzzers have started and are stable before
///   starting the detection campaign.
/// * `verbose` - Display verbose messages.
/// * `no_tui` - Disable the TUI.
/// * `collect_from_all_fuzzers` - Collect traces from all fuzzer instances (instead of just
///   "main").
fn run(
    config_file: &Path,
    force: bool,
    wait_for_fuzzers: bool,
    verbose: bool,
    no_tui: bool,
    collect_from_all_fuzzers: bool,
) -> Result<(), RosaError> {
    // Load the configuration and set up the output directories.
    let config = Config::load(config_file)?;
    config.setup_dirs(force)?;
    config.save(&config.output_dir)?;
    config.set_current_phase(RosaPhase::Starting)?;
    config.set_current_coverage(0.0, 0.0)?;
    config.init_stats_file()?;

    // Set up a "global" running boolean, and create a Ctrl-C handler that just sets it to false.
    let rosa_should_stop = Arc::new(AtomicBool::new(false));
    let should_stop_flag = rosa_should_stop.clone();
    ctrlc::set_handler(move || {
        should_stop_flag.store(true, Ordering::SeqCst);
    })
    .expect("could not set Ctrl-C handler.");

    // Set up a hashmap to keep track of known traces via their UIDs.
    let mut known_traces = HashMap::new();

    // Set up a random number to use as a seed for the fuzzers.
    let fuzzer_seed = rand::thread_rng().gen_range(u32::MIN..=u32::MAX);

    // Set up fuzzer processes.
    let mut fuzzer_processes: Vec<FuzzerProcess> = config
        .fuzzers
        .iter()
        .map(|fuzzer_config| {
            FuzzerProcess::create(
                fuzzer_config.name.clone(),
                fuzzer_config.test_input_dir.parent().unwrap().to_path_buf(),
                fuzzer_config
                    .cmd
                    .iter()
                    .map(|arg| arg.replace("{{ROSA_SEED}}", &fuzzer_seed.to_string()))
                    .collect(),
                fuzzer_config.env.clone(),
                config
                    .logs_dir()
                    .clone()
                    .join(format!("fuzzer_{}", fuzzer_config.name))
                    .with_extension("log"),
            )
        })
        .collect::<Result<Vec<FuzzerProcess>, RosaError>>()?;

    // Setup communication channel with TUI.
    let (tx, rx) = mpsc::channel::<()>();
    // Keep track of backdoors.
    let mut nb_backdoors = 0;
    // Keep track of crash warnings.
    let mut already_warned_about_crashes = false;
    // Keep track of clusters.
    let mut clusters = Vec::new();

    // Print some config info before starting.
    println_info!(
        "** rosa backdoor detector - version {} **",
        env!("CARGO_PKG_VERSION")
    );

    println_info!("Cluster formation config:");
    println_info!(
        "  Distance metric: {}",
        config.cluster_formation_distance_metric
    );
    println_info!("  Criterion: {}", config.cluster_formation_criterion);
    println_info!(
        "  Edge tolerance: {}",
        config.cluster_formation_edge_tolerance
    );
    println_info!(
        "  Syscall tolerance: {}",
        config.cluster_formation_syscall_tolerance
    );

    println_info!("Cluster selection config:");
    println_info!(
        "  Distance metric: {}",
        config.cluster_selection_distance_metric
    );
    println_info!("  Criterion: {}", config.cluster_selection_criterion);

    println_info!("Oracle config:");
    println_info!("  Distance metric: {}", config.oracle_distance_metric);
    println_info!("  Criterion: {}", config.oracle_criterion);
    println_info!("  Algorithm: {}", config.oracle);

    println_info!("Ready to go!");
    // Pause for a sec to let the user read the config.
    thread::sleep(Duration::from_secs(2));

    println_info!("Starting up fuzzers...");
    // Start the fuzzers.
    fuzzer_processes.iter_mut().try_for_each(|fuzzer_process| {
        start_fuzzer_process(fuzzer_process, wait_for_fuzzers, verbose)
    })?;

    // Start the time counter.
    let start_time = Instant::now();
    let mut last_log_time = Instant::now();

    // Start the TUI thread.
    let monitor_dir = config.output_dir.clone();
    let config_file_path = config_file.to_path_buf();
    let tui_thread_handle = match no_tui {
        true => None,
        false => Some(thread::spawn(move || -> Result<(), RosaError> {
            let mut tui = RosaTui::new(&config_file_path, &monitor_dir);
            tui.start()?;

            loop {
                tui.render()?;

                // Give some time to the renderer to do its job.
                thread::sleep(Duration::from_millis(200));

                // Check for a signal to kill thread.
                match rx.try_recv() {
                    Ok(_) | Err(TryRecvError::Disconnected) => {
                        break;
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }

            tui.stop()?;

            Ok(())
        })),
    };

    // We're good to go, update the current phase.
    config.set_current_phase(RosaPhase::CollectingSeeds)?;

    // Loop until Ctrl-C.
    while !rosa_should_stop.load(Ordering::SeqCst) {
        if !already_warned_about_crashes && no_tui {
            // Check for crashes; if some of the inputs crash, the fuzzer will most likely get
            // oriented towards that family of inputs, which decreases the overall chance of
            // finding backdoors.
            config.fuzzers.iter().try_for_each(|fuzzer_config| {
                if with_cleanup!(
                    fuzzer::fuzzer_found_crashes(&fuzzer_config.crashes_dir),
                    fuzzer_processes
                )? {
                    println_warning!(
                        "the fuzzer '{}' has detected one or more crashes in {}. This is probably \
                        hindering the thorough exploration of the binary; it is recommended that \
                        you fix the crashes and try again.",
                        fuzzer_config.name,
                        &fuzzer_config.crashes_dir.display()
                    );
                    already_warned_about_crashes = true;
                }

                Ok(())
            })?;
        }

        // Collect new traces.
        let new_traces = with_cleanup!(
            match collect_from_all_fuzzers {
                true => {
                    config
                        .fuzzers
                        .iter()
                        .try_fold(Vec::new(), |mut new_traces, fuzzer_config| {
                            let mut traces = trace::load_traces(
                                &fuzzer_config.test_input_dir,
                                &fuzzer_config.trace_dump_dir,
                                &fuzzer_config.name,
                                &mut known_traces,
                                // Skip missing traces, because the fuzzer is continually producing
                                // new ones, and we might miss some because of the timing of the
                                // writes; it's okay, we'll pick them up on the next iteration.
                                true,
                            )?;

                            new_traces.append(&mut traces);
                            Ok(new_traces)
                        })
                }
                false => {
                    let main_fuzzer = config.main_fuzzer()?;
                    trace::load_traces(
                        &main_fuzzer.test_input_dir,
                        &main_fuzzer.trace_dump_dir,
                        "main",
                        &mut known_traces,
                        // Skip missing traces, because the fuzzer is continually producing new
                        // ones, and we might miss some because of the timing of the writes; it's
                        // okay, we'll pick them up on the next iteration.
                        true,
                    )
                }
            },
            fuzzer_processes
        )?;
        // Save traces to output dir for later inspection.
        with_cleanup!(
            trace::save_traces(&new_traces, &config.traces_dir()),
            fuzzer_processes
        )?;

        // Update coverage.
        let current_traces: Vec<Trace> = known_traces.clone().into_values().collect();
        let (edge_coverage, syscall_coverage) = trace::get_coverage(&current_traces);
        config.set_current_coverage(edge_coverage, syscall_coverage)?;

        if Instant::now().duration_since(last_log_time).as_secs() >= 1 {
            with_cleanup!(
                config.log_stats(
                    start_time.elapsed().as_secs(),
                    known_traces.len() as u64,
                    nb_backdoors,
                    edge_coverage,
                    syscall_coverage,
                ),
                fuzzer_processes
            )?;
            last_log_time = Instant::now();

            if no_tui {
                println_info!(
                    "Time: {} s | Traces: {} | Backdoors: {} | Edge coverage: {:.2}% | \
                        Syscall coverage: {:.2}%",
                    start_time.elapsed().as_secs(),
                    known_traces.len() as u64,
                    nb_backdoors,
                    edge_coverage * 100.0,
                    syscall_coverage * 100.0
                );
            }
        }

        if with_cleanup!(config.get_current_phase(), fuzzer_processes)?
            == RosaPhase::CollectingSeeds
        {
            // We're in the seed collection phase.

            // Save the decisions for the seed traces, even though we know what they're gonna be.
            with_cleanup!(
                new_traces.iter().try_for_each(|trace| {
                    let decision = TimedDecision {
                        decision: Decision {
                            trace_uid: trace.uid(),
                            trace_name: trace.name.clone(),
                            cluster_uid: "<none>".to_string(),
                            is_backdoor: false,
                            reason: DecisionReason::Seed,
                        },
                        seconds: start_time.elapsed().as_secs(),
                    };

                    decision.save(&config.decisions_dir())
                }),
                fuzzer_processes
            )?;

            // Check if the seed stopping conditions have been met.
            if config.seed_conditions.check(
                start_time.elapsed().as_secs(),
                edge_coverage,
                syscall_coverage,
            ) {
                // We're entering seed clustering phase; write it into the phase file so that the
                // TUI can keep up.
                with_cleanup!(
                    config.set_current_phase(RosaPhase::ClusteringSeeds),
                    fuzzer_processes
                )?;

                // Form seed clusters.
                if no_tui {
                    println_info!("Clustering seed traces...");
                }
                clusters = clustering::cluster_traces(
                    &current_traces,
                    config.cluster_formation_criterion,
                    config.cluster_formation_distance_metric,
                    config.cluster_formation_edge_tolerance,
                    config.cluster_formation_syscall_tolerance,
                );
                // Save clusters to output dir for later inspection.
                with_cleanup!(
                    clustering::save_clusters(&clusters, &config.clusters_dir()),
                    fuzzer_processes
                )?;
                if no_tui {
                    println_info!("Created {} clusters.", clusters.len());
                }

                // We're entering detection phase; write it into the phase file so that the TUI can
                // keep up.
                with_cleanup!(
                    config.set_current_phase(RosaPhase::DetectingBackdoors),
                    fuzzer_processes
                )?;
            }
        } else {
            // We're in the backdoor detection phase.

            new_traces
                .iter()
                // Get most similar cluster.
                .map(|trace| {
                    (
                        trace,
                        clustering::get_most_similar_cluster(
                            trace,
                            &clusters,
                            config.cluster_selection_criterion,
                            config.cluster_selection_distance_metric,
                        )
                        .expect("failed to get most similar cluster."),
                    )
                })
                // Perform oracle inference.
                .map(|(trace, cluster)| {
                    let decision = config.oracle.decide(
                        trace,
                        cluster,
                        config.oracle_criterion,
                        config.oracle_distance_metric,
                    );
                    (trace, decision)
                })
                .try_for_each(|(trace, decision)| {
                    if decision.is_backdoor {
                        nb_backdoors += 1;

                        // Save backdoor.
                        with_cleanup!(
                            trace::save_trace_test_input(trace, &config.backdoors_dir()),
                            fuzzer_processes
                        )?;
                    }

                    let timed_decision = TimedDecision {
                        decision,
                        seconds: start_time.elapsed().as_secs(),
                    };

                    with_cleanup!(
                        timed_decision.save(&config.decisions_dir()),
                        fuzzer_processes
                    )
                })?;
        }
    }

    // Shut down TUI thread.
    let _ = tx.send(());
    if let Some(handle) = tui_thread_handle {
        let _ = handle.join();
    }

    println_info!("Stopping fuzzer processes.");
    fuzzer_processes
        .iter_mut()
        .try_for_each(|fuzzer_process| fuzzer_process.stop())?;

    // Run the deduplicator.
    if let Some(deduplicator) = config.deduplicator.clone() {
        config.set_current_phase(RosaPhase::DeduplicatingFindings)?;

        if no_tui {
            println_info!("Running deduplicator...");
        }

        let backup_backdoors_dir = config.output_dir.join("backdoors-original");
        let backup_traces_dir = config.output_dir.join("traces-original");

        // Backup the original findings.
        // Maybe using `fs` would be better here, but I'm not sure it's worth it to write so much
        // code for something so simple...
        Command::new("cp")
            .arg("-r")
            .arg(&config.traces_dir())
            .arg(backup_traces_dir)
            .status()
            .map_err(|err| error!("failed to back up original traces: {}.", err))?;
        Command::new("cp")
            .arg("-r")
            .arg(&config.backdoors_dir())
            .arg(backup_backdoors_dir.clone())
            .status()
            .map_err(|err| error!("failed to back up original backdoors: {}.", err))?;

        // Remove the `backdoors` directory to re-create it with the deduplicator.
        fs::remove_dir_all(config.backdoors_dir()).map_err(|err| {
            error!(
                "failed to remove '{}' after backup: {}.",
                config.backdoors_dir().display(),
                err
            )
        })?;

        // Deduplicate the backdoor inputs.
        Command::new(&deduplicator.cmd[0])
            .args(
                // Replace the `"{{INPUT}}"` and `"{{OUTPUT}}"` strings as per the doc.
                &deduplicator.cmd[1..]
                    .iter()
                    .map(|arg| {
                        arg.replace(
                            "{{INPUT}}",
                            &backup_backdoors_dir
                                .clone()
                                .into_os_string()
                                .into_string()
                                .expect("could not convert backup backdoors dir path to string."),
                        )
                        .replace(
                            "{{OUTPUT}}",
                            &config
                                .backdoors_dir()
                                .into_os_string()
                                .into_string()
                                .expect("could not convert backdoors dir path to string."),
                        )
                    })
                    .collect::<Vec<String>>(),
            )
            .envs(config::replace_env_var_placeholders(&deduplicator.env))
            .status()
            .map_err(|err| error!("failed to run deduplicator on backdoors: {}.", err))?;

        // Make sure to copy the README over (deduplicator thinks it's an input file).
        fs::copy(
            backup_backdoors_dir.join("README.txt"),
            config.backdoors_dir().join("README.txt"),
        )
        .map_err(|err| {
            error!(
                "failed to copy README.txt into deduplicated backdoors directory: {}.",
                err
            )
        })?;

        // Remove any findings that are not in both the backup and the deduplicated backdoor
        // directories.
        let original_backdoor_test_inputs: Vec<String> =
            trace::get_test_input_files(&backup_backdoors_dir)?
                .into_iter()
                .map(|file| {
                    file.file_name()
                        .expect("could not get file name.")
                        .to_string_lossy()
                        .to_string()
                })
                .collect();
        let deduplicated_backdoor_test_inputs: Vec<String> =
            trace::get_test_input_files(&config.backdoors_dir())?
                .into_iter()
                .map(|file| {
                    file.file_name()
                        .expect("could not get file name.")
                        .to_string_lossy()
                        .to_string()
                })
                .collect();
        original_backdoor_test_inputs
            .into_iter()
            // Skip READMEs.
            .filter(|original_test_input| *original_test_input != "README.txt")
            .try_for_each(|original_test_input| {
                match deduplicated_backdoor_test_inputs.contains(&original_test_input) {
                    true => (),
                    false => {
                        let finding_to_remove =
                            config.traces_dir().join(original_test_input.clone());
                        fs::remove_file(finding_to_remove.clone()).map_err(|err| {
                            error!(
                                "Failed to remove finding (test input) '{}': {}.",
                                original_test_input, err
                            )
                        })?;
                        fs::remove_file(finding_to_remove.with_extension("trace")).map_err(
                            |err| {
                                error!(
                                    "Failed to remove finding (trace) '{}': {}.",
                                    original_test_input, err
                                )
                            },
                        )?;
                    }
                }

                Ok(())
            })?;
    };

    config.set_current_phase(RosaPhase::Stopped)?;

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(
        &cli.config_file,
        cli.force,
        cli.wait_for_fuzzers,
        cli.verbose,
        cli.no_tui,
        cli.collect_from_all_fuzzers,
    ) {
        Ok(_) => {
            println_info!("Bye :)");
            ExitCode::SUCCESS
        }
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
