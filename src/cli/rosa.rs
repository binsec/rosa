//! Detect backdoors in binary programs.
//!
//! This is the main ROSA binary; it can be used directly for backdoor detection.

use std::{
    collections::HashMap,
    fs,
    io::ErrorKind,
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
use rand::Rng;

use rosa::{
    clustering,
    config::{Config, RosaPhase},
    decision::{Decision, DecisionReason, Discriminants, TimedDecision},
    error,
    error::RosaError,
    fuzzer::{self, FuzzerProcess, FuzzerStatus},
    trace::{self, Trace},
};

use crate::tui::RosaTui;

mod common;
#[macro_use]
#[allow(unused_macros)]
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
    /// The configuration file to use. Generate the default configuration with
    /// `rosa-generate-config` or see the documentation (in doc/) for a detailed guide.
    #[arg(
        long_help,
        default_value = "config.toml",
        value_name = "FILE",
        help = "The configuration file to use"
    )]
    config_file: PathBuf,

    /// Force the creation of the output directory, potentially overwriting existing results.
    #[arg(
        long_help,
        short,
        long,
        help = "Force (auto-delete existing) output directory"
    )]
    force: bool,

    /// Provide more verbose output about each fuzzer instance.
    #[arg(long_help, short, long, help = "Be more verbose")]
    verbose: bool,

    /// Disable the TUI (Terminal User Interface) and display more linear output on the console.
    #[arg(long_help, short, long, help = "Disable the TUI")]
    no_tui: bool,

    /// Wait until all fuzzer instances have stabilized before starting the detection campaign.
    /// This means that some fuzzer instances might have stabilized early and thus might have been
    /// running for a while when the detection campaign actually begins.
    #[arg(
        long_help,
        long,
        action = clap::ArgAction::SetFalse,
        help = "Wait until all fuzzer instances have stabilized before starting"
    )]
    wait_for_fuzzers: bool,

    /// Collect traces from all the fuzzer instances if there are multiple of them. By default,
    /// only traces from the "main" instance will be collected. Be warned: this will probably speed
    /// up backdoor detection, but it might also produce duplicate traces, since there may be
    /// instrumentation differences between different instances.
    #[arg(long_help, long, help = "Collect traces from all fuzzers")]
    collect_from_all_fuzzers: bool,
}

/// Evaluate an expression and clean up any fuzzer instance processes if the expression evaluates
/// to [Err].
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

/// Start a fuzzer instance process.
///
/// If `wait_for_fuzzers` is [false], then all fuzzer instances are started in a non-blocking way
/// (i.e., we do not wait for them to stabilize). Otherwise, we block and wait for them to fully
/// stabilize, which means that some instances may have been running for longer than others when
/// all instances have been started.
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
/// This function implements the backdoor detection approach introduced by ROSA:
/// * Phase 1: collect family-representative inputs
/// * Phase 2: collect new inputs and use metamorphic oracle with family-representative inputs
fn run(
    config_file: &Path,
    force: bool,
    verbose: bool,
    no_tui: bool,
    wait_for_fuzzers: bool,
    collect_from_all_fuzzers: bool,
) -> Result<(), RosaError> {
    // Load the configuration and set up the output directories.
    let config = Config::load(config_file)?;
    config.setup_dirs(force)?;
    // We save the config in the output directory for reproducibility puproses.
    config.save(&config.output_dir.join("config").with_extension("toml"))?;
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

    // Set up a random number that the fuzzers may use as a seed.
    let fuzzer_seed = rand::thread_rng().gen_range(u32::MIN..=u32::MAX);

    // Set up the fuzzer processes.
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
    let mut nb_unique_backdoors = 0;
    let mut nb_total_backdoors = 0;
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
    let tui_thread_handle = if no_tui {
        None
    } else {
        Some(thread::spawn(move || -> Result<(), RosaError> {
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
        }))
    };

    // We're good to go, update the current phase.
    config.set_current_phase(RosaPhase::CollectingSeeds)?;

    // Loop until Ctrl-C.
    while !rosa_should_stop.load(Ordering::SeqCst) {
        if !already_warned_about_crashes && no_tui {
            // Check for crashes; if some of the inputs crash, the crashes might hide backdoor
            // behavior or otherwise impede backdoor detection.
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
            if collect_from_all_fuzzers {
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
            } else {
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

        // Update stats every second.
        if Instant::now().duration_since(last_log_time).as_secs() >= 1 {
            with_cleanup!(
                config.log_stats(
                    start_time.elapsed().as_secs(),
                    known_traces.len() as u64,
                    nb_unique_backdoors,
                    nb_total_backdoors,
                    edge_coverage,
                    syscall_coverage,
                ),
                fuzzer_processes
            )?;
            last_log_time = Instant::now();

            if no_tui {
                println_info!(
                    "Time: {} s | Traces: {} | Backdoors: {} unique ({} total) | \
                        Edge coverage: {:.2}% | Syscall coverage: {:.2}%",
                    start_time.elapsed().as_secs(),
                    known_traces.len() as u64,
                    nb_unique_backdoors,
                    nb_total_backdoors,
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
                            discriminants: Discriminants {
                                trace_edges: Vec::new(),
                                cluster_edges: Vec::new(),
                                trace_syscalls: Vec::new(),
                                cluster_syscalls: Vec::new(),
                            },
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
                        nb_total_backdoors += 1;

                        // Get the discriminants UID to deduplicate backdoor.
                        // Essentially, if the backdoor was detected for the same reason as a
                        // pre-existing backdoor, we should avoid listing them as two different
                        // backdoors.
                        let discriminants_uid = decision
                            .discriminants
                            .uid(config.oracle_criterion, &decision.cluster_uid);

                        // Attempt to create a directory for this category of backdoor.
                        let backdoor_dir = config.backdoors_dir().join(discriminants_uid);
                        match fs::create_dir(&backdoor_dir) {
                            Ok(_) => {
                                nb_unique_backdoors += 1;
                                Ok(())
                            }
                            Err(error) => match error.kind() {
                                ErrorKind::AlreadyExists => Ok(()),
                                _ => Err(error),
                            },
                        }
                        .map_err(|err| {
                            error!("could not create '{}': {}", &backdoor_dir.display(), err)
                        })?;

                        // Save backdoor.
                        with_cleanup!(
                            trace::save_trace_test_input(trace, &backdoor_dir),
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

    config.set_current_phase(RosaPhase::Stopped)?;

    Ok(())
}

fn main() -> ExitCode {
    common::reset_sigpipe();
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
