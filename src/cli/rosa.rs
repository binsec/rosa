//! Detect backdoors in binary programs.
//!
//! This is the main ROSA binary; it can be used directly for backdoor detection.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
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

use rosa::{
    clustering,
    config::Config,
    decision::{Decision, DecisionReason, TimedDecision},
    error::RosaError,
    fuzzer::{self, FuzzerProcess, FuzzerStatus},
    trace,
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

    /// Be more verbose.
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Disable the TUI and display more linear output on the console.
    #[arg(long = "no-tui")]
    no_tui: bool,
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
/// start. This function blocks until the fuzzer has fully started running.
///
/// TODO arguments & examples
fn start_fuzzer_process(
    fuzzer_process: &mut FuzzerProcess,
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

    if fuzzer::get_fuzzer_status(&fuzzer_process.working_dir)? == FuzzerStatus::Starting {
        // Wait until fuzzer is up and running.
        while fuzzer::get_fuzzer_status(&fuzzer_process.working_dir)? != FuzzerStatus::Running {
            if fuzzer::get_fuzzer_status(&fuzzer_process.working_dir)? == FuzzerStatus::Stopped {
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
/// * `verbose` - Display verbose messages.
/// * `no_tui` - Disable the TUI.
fn run(config_file: &Path, force: bool, verbose: bool, no_tui: bool) -> Result<(), RosaError> {
    // Load the configuration and set up the output directories.
    let config = Config::load(config_file)?;
    config.setup_dirs(force)?;
    config.save(&config.output_dir)?;

    // Set up a "global" running boolean, and create a Ctrl-C handler that just sets it to false.
    let rosa_should_stop = Arc::new(AtomicBool::new(false));
    let should_stop_flag = rosa_should_stop.clone();
    ctrlc::set_handler(move || {
        should_stop_flag.store(true, Ordering::SeqCst);
    })
    .expect("could not set Ctrl-C handler.");

    // Set up a hashmap to keep track of known traces via their UIDs.
    let mut known_traces = HashMap::new();

    // Set up fuzzer processes.
    let mut seed_phase_fuzzer_processes: Vec<FuzzerProcess> = config
        .seed_phase_fuzzers
        .iter()
        .map(|fuzzer_config| {
            FuzzerProcess::create(
                fuzzer_config.name.clone(),
                fuzzer_config.test_input_dir.parent().unwrap().to_path_buf(),
                fuzzer_config.cmd.clone(),
                fuzzer_config.env.clone(),
                config
                    .logs_dir()
                    .clone()
                    .join(format!("seed_phase_fuzzer_{}", fuzzer_config.name))
                    .with_extension("log"),
            )
        })
        .collect::<Result<Vec<FuzzerProcess>, RosaError>>()?;
    let mut detection_phase_fuzzer_processes: Vec<FuzzerProcess> = config
        .detection_phase_fuzzers
        .iter()
        .map(|fuzzer_config| {
            FuzzerProcess::create(
                fuzzer_config.name.clone(),
                fuzzer_config.test_input_dir.parent().unwrap().to_path_buf(),
                fuzzer_config.cmd.clone(),
                fuzzer_config.env.clone(),
                config
                    .logs_dir()
                    .clone()
                    .join(format!("detection_phase_fuzzer_{}", fuzzer_config.name))
                    .with_extension("log"),
            )
        })
        .collect::<Result<Vec<FuzzerProcess>, RosaError>>()?;

    // Setup communication channel with TUI.
    let (tx, rx) = mpsc::channel::<()>();

    // Spawn the fuzzer seed process.
    println_info!("Collecting seed traces...");
    if verbose {
        println_verbose!("Fuzzer seed processes:");
    }
    seed_phase_fuzzer_processes
        .iter_mut()
        .try_for_each(|fuzzer_process| start_fuzzer_process(fuzzer_process, verbose))?;

    // Wait for the fuzzer process (or for a Ctrl-C).
    while seed_phase_fuzzer_processes
        .iter_mut()
        .any(|fuzzer_process| fuzzer_process.is_running().unwrap_or(false))
        && !rosa_should_stop.load(Ordering::Acquire)
    {}

    // Check to see if we received a Ctrl-C while waiting.
    if seed_phase_fuzzer_processes
        .iter_mut()
        .any(|fuzzer_process| fuzzer_process.is_running().unwrap_or(false))
        && rosa_should_stop.load(Ordering::Acquire)
    {
        println_info!("Stopping seed phase fuzzer processes.");
        seed_phase_fuzzer_processes
            .iter_mut()
            .try_for_each(|fuzzer_process| fuzzer_process.stop())?;
        return Ok(());
    }

    // Check the exit code of the fuzzer seed process.
    seed_phase_fuzzer_processes
        .iter_mut()
        .try_for_each(|fuzzer_process| {
            fuzzer_process.check_success().map_err(|err| {
                rosa::error!(
                    "seed phase fuzzer command failed: {}. See {}.",
                    err,
                    fuzzer_process.log_file.display()
                )
            })
        })?;

    // Check for crashes; if some of the inputs crash, the fuzzer will most likely get oriented
    // towards that family of inputs, which decreases the overall chance of finding backdoors.
    config
        .seed_phase_fuzzers
        .iter()
        .try_for_each(|fuzzer_config| {
            if fuzzer::fuzzer_found_crashes(&fuzzer_config.crashes_dir)? {
                println_warning!(
                    "the fuzzer '{}' has detected one or more crashes in {}. This is probably \
                hindering the thorough exploration of the binary; it is recommended that you fix \
                the crashes and try again.",
                    fuzzer_config.name,
                    &fuzzer_config.crashes_dir.display(),
                )
            }

            Ok(())
        })?;
    // Collect seed traces.
    let seed_traces = trace::load_traces(
        &config.main_seed_phase_fuzzer()?.test_input_dir,
        &config.main_seed_phase_fuzzer()?.trace_dump_dir,
        &mut known_traces,
        false,
    )?;
    // Save traces to output dir for later inspection.
    trace::save_traces(&seed_traces, &config.traces_dir())?;
    println_info!("Collected {} seed traces.", seed_traces.len());

    // Form seed clusters.
    println_info!("Clustering seed traces...");
    let clusters = clustering::cluster_traces(
        &seed_traces,
        config.cluster_formation_criterion,
        config.cluster_formation_distance_metric,
        config.cluster_formation_edge_tolerance,
        config.cluster_formation_syscall_tolerance,
    );
    // Save clusters to output dir for later inspection.
    clustering::save_clusters(&clusters, &config.clusters_dir())?;
    println_info!("Created {} clusters.", clusters.len());
    // Save the decisions for the seed traces too, even though we know what they're gonna be.
    clusters.iter().try_for_each(|cluster| {
        cluster.traces.iter().try_for_each(|trace| {
            let decision = TimedDecision {
                decision: Decision {
                    trace_uid: trace.uid(),
                    trace_name: trace.name.clone(),
                    cluster_uid: cluster.uid.clone(),
                    is_backdoor: false,
                    reason: DecisionReason::Seed,
                },
                seconds: 0,
            };

            decision.save(&config.decisions_dir())
        })
    })?;

    // Spawn the fuzzer detection processes.
    println_info!("Starting backdoor detection...");
    if verbose {
        println_verbose!("Fuzzer detection processes:");
    }
    detection_phase_fuzzer_processes
        .iter_mut()
        .try_for_each(|fuzzer_process| start_fuzzer_process(fuzzer_process, verbose))?;
    let mut nb_backdoors = 0;

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

    // Start the time counter.
    let detection_start_time = Instant::now();

    let mut already_warned_about_crashes = false;
    // Loop until Ctrl-C.
    while !rosa_should_stop.load(Ordering::SeqCst) {
        if no_tui {
            // Check how many fuzzers are alive; if some have crashed/not started, let the user
            // know.
            config
                .detection_phase_fuzzers
                .iter()
                .try_for_each(|fuzzer_config| {
                    let fuzzer_state = with_cleanup!(
                        fuzzer::get_fuzzer_status(fuzzer_config.test_input_dir.parent().expect(
                            "failed to get parent directory for fuzzer test input directory."
                        )),
                        detection_phase_fuzzer_processes
                    )?;

                    if fuzzer_state == FuzzerStatus::Stopped {
                        println_warning!(
                            "fuzzer '{}' is not running; attempting to respawn it...",
                            fuzzer_config.name,
                        );
                        let dead_fuzzer_process: &mut FuzzerProcess =
                            detection_phase_fuzzer_processes
                                .iter_mut()
                                .find(|fuzzer_process| fuzzer_process.name == fuzzer_config.name)
                                .expect(
                                    "failed to get fuzzer process when attempting to respawn it.",
                                );

                        dead_fuzzer_process.stop()?;
                        start_fuzzer_process(dead_fuzzer_process, verbose)?;
                    }

                    Ok(())
                })?;
        }

        if !already_warned_about_crashes && no_tui {
            // Check for crashes; if some of the inputs crash, the fuzzer will most likely get
            // oriented towards that family of inputs, which decreases the overall chance of
            // finding backdoors.
            config
                .detection_phase_fuzzers
                .iter()
                .try_for_each(|fuzzer_config| {
                    if with_cleanup!(
                        fuzzer::fuzzer_found_crashes(&fuzzer_config.crashes_dir),
                        detection_phase_fuzzer_processes
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
            trace::load_traces(
                &config.main_detection_phase_fuzzer()?.test_input_dir,
                &config.main_detection_phase_fuzzer()?.trace_dump_dir,
                &mut known_traces,
                // Skip missing traces, because the fuzzer is continually producing new
                // ones, and we might miss some because of the timing of the writes; it's
                // okay, we'll pick them up on the next iteration.
                true,
            ),
            detection_phase_fuzzer_processes
        )?;
        // Save traces to output dir for later inspection.
        with_cleanup!(
            trace::save_traces(&new_traces, &config.traces_dir()),
            detection_phase_fuzzer_processes
        )?;

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
                    if no_tui {
                        nb_backdoors += 1;
                        println_info!(
                            "!!!! BACKDOOR FOUND !!!! (backdoors: {} | traces: {})",
                            nb_backdoors,
                            known_traces.len()
                        );

                        if verbose {
                            println_verbose!("Trace {}:", trace.uid());
                            println_verbose!("  Test input: {}", trace.printable_test_input());
                            println_verbose!("  Edges: {}", trace.edges_as_string());
                            println_verbose!("  Syscalls: {}", trace.syscalls_as_string());
                            println_verbose!("  Most similar cluster: {}", decision.cluster_uid);
                            println_verbose!("  Decision reason: {}", decision.reason);
                        }
                    }

                    // Save backdoor.
                    with_cleanup!(
                        trace::save_trace_test_input(trace, &config.backdoors_dir()),
                        detection_phase_fuzzer_processes
                    )?;
                }

                let timed_decision = TimedDecision {
                    decision,
                    seconds: detection_start_time.elapsed().as_secs(),
                };

                with_cleanup!(
                    timed_decision.save(&config.decisions_dir()),
                    detection_phase_fuzzer_processes
                )
            })?;
    }

    // Shut down TUI thread.
    let _ = tx.send(());
    if let Some(handle) = tui_thread_handle {
        let _ = handle.join();
    }
    println_info!("Stopping detection phase fuzzer processes.");
    detection_phase_fuzzer_processes
        .iter_mut()
        .try_for_each(|fuzzer_process| fuzzer_process.stop())?;

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli.config_file, cli.force, cli.verbose, cli.no_tui) {
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
