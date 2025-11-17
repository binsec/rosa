//! Detect backdoors in binary programs.
//!
//! This is the main ROSA binary; it can be used directly for backdoor detection.

use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::mpsc::{self, TryRecvError},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use clap::Parser;
use colored::Colorize;

use rosa::{
    clustering,
    config::{Config, RosaPhase, phase_one::PhaseOne},
    error,
    error::RosaError,
    fuzzer::{FuzzerInstance, FuzzerStatus},
    oracle::{Decision, DecisionReason, Discriminants, TimedDecision},
    trace::{self, Trace, TraceDatabase},
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
        value_name = "CONFIG FILE",
        help = "Configuration file"
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

    /// Force the use of a phase-1 corpus directory (regardless of what the configuration says).
    #[arg(long_help, long, help = "Force use of phase-1 corpus directory")]
    phase_one_corpus: Option<PathBuf>,

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
        help = "Wait until all fuzzer instances have stabilized before starting"
    )]
    wait_for_fuzzers: bool,

    /// Stop immediately after Ctrl-C/SIGINT without collecting any remaining fuzzer inputs.
    /// By default, ROSA will not stop immediately after Ctrl-C/SIGINT, but will spend some time
    /// collecting any unprocessed/not yet seen fuzzer-generated inputs. This option overrides that
    /// behavior and can be used to stop ROSA immediately.
    #[arg(
        long_help,
        long,
        help = "Stop immediately (will not collect any remaining fuzzer inputs)"
    )]
    hard_stop: bool,

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
    ( $action:expr, $fuzzer_instances:expr ) => {{
        $action.or_else(|err| {
            $fuzzer_instances
                .iter_mut()
                .try_for_each(|fuzzer_instance| fuzzer_instance.stop())?;
            Err(err)
        })
    }};
}

/// Start a fuzzer instance.
///
/// If `wait_for_fuzzers` is [false], then all fuzzer instances are started in a non-blocking way
/// (i.e., we do not wait for them to stabilize). Otherwise, we block and wait for them to fully
/// stabilize, which means that some instances may have been running for longer than others when
/// all instances have been started.
fn start_fuzzer_instance(
    fuzzer_instance: &mut FuzzerInstance,
    wait_for_fuzzers: bool,
    verbose: bool,
) -> Result<(), RosaError> {
    if verbose {
        println_verbose!(
            "  Fuzzer process '{}':",
            fuzzer_instance.config.backend.name()
        );
        println_verbose!("    Env: {}", fuzzer_instance.env_as_string());
        println_verbose!("    Cmd: {}", fuzzer_instance.cmd_as_string());
    }

    fuzzer_instance.spawn()?;

    // Give the process 200 ms to get up and running.
    thread::sleep(Duration::from_millis(200));

    if wait_for_fuzzers && fuzzer_instance.config.backend.status() == FuzzerStatus::Starting {
        // Wait until fuzzer is up and running.
        while fuzzer_instance.config.backend.status() != FuzzerStatus::Running {
            if fuzzer_instance.config.backend.status() == FuzzerStatus::Stopped
                || !fuzzer_instance.is_running()?
            {
                break;
            }
        }
    }

    Ok(())
}

/// Collect new traces from one or more fuzzer instances.
///
/// Note that this function will attempt to collect at most one trace from each fuzzer.
fn collect_new_traces(
    config: &Config,
    trace_db: &mut TraceDatabase,
    skip_missing_traces: bool,
    collect_from_all_fuzzers: bool,
    collect_all_traces: bool,
) -> Result<Vec<Trace>, RosaError> {
    if collect_from_all_fuzzers {
        let traces = if collect_all_traces {
            config
                .fuzzers
                .iter()
                .flat_map(|fuzzer_config| {
                    match fuzzer_config.backend.collect_all_traces(
                        trace_db,
                        skip_missing_traces,
                        &config.fuzzer_scratch_dir(fuzzer_config),
                        None,
                    ) {
                        // We have to do this little dance because `flat_map()` will
                        // essentially strip `Err()`s out. We want to keep them in explicitly.
                        //
                        // See https://stackoverflow.com/a/59852696.
                        Ok(vec) => vec.into_iter().map(Ok).collect(),
                        Err(err) => vec![Err(err)],
                    }
                })
                .collect::<Result<Vec<Trace>, RosaError>>()?
        } else {
            config
                .fuzzers
                .iter()
                .map(|fuzzer_config| {
                    fuzzer_config.backend.collect_one_trace(
                        trace_db,
                        skip_missing_traces,
                        &config.fuzzer_scratch_dir(fuzzer_config),
                        None,
                    )
                })
                .collect::<Result<Vec<Option<Trace>>, RosaError>>()?
                .into_iter()
                .flatten()
                .collect()
        };

        Ok(traces)
    } else {
        let main_fuzzer = config.main_fuzzer()?;

        if collect_all_traces {
            main_fuzzer.backend.collect_all_traces(
                trace_db,
                skip_missing_traces,
                &config.fuzzer_scratch_dir(main_fuzzer),
                None,
            )
        } else {
            let new_trace = main_fuzzer.backend.collect_one_trace(
                trace_db,
                skip_missing_traces,
                &config.fuzzer_scratch_dir(main_fuzzer),
                None,
            )?;

            Ok(new_trace.map(|trace| vec![trace]).unwrap_or(Vec::new()))
        }
    }
}

/// Check if the phase-1 criteria have been met.
fn check_phase_one(
    phase_one: &PhaseOne,
    seconds: u64,
    edge_coverage: f64,
    syscall_coverage: f64,
) -> bool {
    match phase_one {
        PhaseOne::Seconds(s) => seconds >= *s,
        PhaseOne::EdgeCoverage(c) => edge_coverage >= *c,
        PhaseOne::SyscallCoverage(c) => syscall_coverage >= *c,
        // Since the corpus condition will be taken care of before the campaign even starts, we
        // will assume it's been done whenever this function is called.
        PhaseOne::Corpus(_) => true,
    }
}

/// Run the backdoor detection tool.
///
/// This function implements the backdoor detection approach introduced by ROSA:
/// * Phase 1: collect family-representative inputs
/// * Phase 2: collect new inputs and use metamorphic oracle with family-representative inputs
#[allow(clippy::too_many_arguments)]
fn run(
    config_file: &Path,
    force: bool,
    phase_one_corpus: Option<&Path>,
    verbose: bool,
    no_tui: bool,
    wait_for_fuzzers: bool,
    hard_stop: bool,
    collect_from_all_fuzzers: bool,
) -> Result<(), RosaError> {
    // Load the configuration and set up the output directories.
    let mut config = Config::load(config_file)?;
    if let Some(phase_one_corpus_dir) = phase_one_corpus {
        // Make the config use a phase-1 corpus.
        config.phase_one = PhaseOne::Corpus(phase_one_corpus_dir.to_path_buf());
    }

    config.setup_dirs(force)?;
    // We save the config in the output directory for reproducibility purposes.
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
    let mut trace_db = TraceDatabase::new();

    // Set up the fuzzer processes.
    let mut fuzzer_instances: Vec<FuzzerInstance> = config
        .fuzzers
        .iter()
        .map(|fuzzer_config| {
            let scratch_dir = config.fuzzer_scratch_dir(fuzzer_config);

            let log_file_path = config
                .logs_dir()
                .clone()
                .join(format!("fuzzer_{}", fuzzer_config.backend.name()))
                .with_extension("log");

            let fuzzer_instance =
                FuzzerInstance::create(fuzzer_config.clone(), scratch_dir, log_file_path)?;
            // Run the setup for each instance.
            fuzzer_instance
                .config
                .backend
                .setup(&fuzzer_instance.scratch_dir)?;

            Ok(fuzzer_instance)
        })
        .collect::<Result<Vec<FuzzerInstance>, RosaError>>()?;

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

    // Print the configuration details.
    println_info!(
        "{}",
        [
            "Configuration:".to_string(),
            "  Phase 1:".to_string(),
            match config.phase_one {
                PhaseOne::Corpus(ref dir) =>
                    format!("    Using existing corpus ({})", dir.display()),
                PhaseOne::Seconds(seconds) => format!("    Stopping at {} seconds", seconds),
                PhaseOne::EdgeCoverage(coverage) =>
                    format!("    Stopping at {:.2}% edge coverage", coverage * 100.0),
                PhaseOne::SyscallCoverage(coverage) =>
                    format!("    Stopping at {:.2}% syscall coverage", coverage * 100.0),
            },
            "  Cluster formation:".to_string(),
            format!(
                "    Distance metric: {}",
                config.cluster_formation_distance_metric.name()
            ),
            format!("    Criterion: {}", config.cluster_formation_criterion),
            format!(
                "    Edge tolerance: {}",
                config.cluster_formation_edge_tolerance
            ),
            format!(
                "    Syscall tolerance: {}",
                config.cluster_formation_syscall_tolerance
            ),
            "  Cluster selection:".to_string(),
            format!(
                "    Distance metric: {}",
                config.cluster_selection_distance_metric.name()
            ),
            format!("    Criterion: {}", config.cluster_selection_criterion),
            "  Oracle:".to_string(),
            format!("    Algorithm: {}", config.oracle.name()),
            format!(
                "    Distance metric: {}",
                config.oracle_distance_metric.name()
            ),
            format!("    Criterion: {}", config.oracle_criterion)
        ]
        .join("\n")
    );

    println_info!("Ready to go!");
    // Pause for a sec to let the user read the config.
    thread::sleep(Duration::from_secs(2));

    // Load phase-1 corpus if needed.
    if let PhaseOne::Corpus(ref corpus_dir) = config.phase_one {
        let phase_one_traces = trace::load_traces(corpus_dir)?;
        // Save the traces in the output directory.
        trace::save_traces(&phase_one_traces, &config.traces_dir())?;

        // We should start by clustering the inputs (no more time is allocated to phase 1).
        clusters = clustering::cluster_traces(
            &phase_one_traces,
            config.cluster_formation_criterion,
            config.cluster_formation_distance_metric.clone(),
            config.cluster_formation_edge_tolerance,
            config.cluster_formation_syscall_tolerance,
        );
        // Save clusters to output dir for later inspection.
        clustering::save_clusters(&clusters, &config.clusters_dir())?;

        // Save the trace decisions and log the traces in the database.
        phase_one_traces.into_iter().try_for_each(|trace| {
            trace_db.insert_trace(trace.clone());

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
                seconds: 0,
            };
            decision.save(&config.decisions_dir())
        })?;

        config.set_current_phase(RosaPhase::DetectingBackdoors)?;
    }

    println_info!("Starting up fuzzers...");
    // Start the fuzzers.
    fuzzer_instances
        .iter_mut()
        .try_for_each(|fuzzer_instance| {
            start_fuzzer_instance(fuzzer_instance, wait_for_fuzzers, verbose)
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
    config.set_current_phase(RosaPhase::CollectingInputs)?;

    // Loop until Ctrl-C.
    while !rosa_should_stop.load(Ordering::SeqCst) {
        if !already_warned_about_crashes && no_tui {
            // Check for crashes; if some of the inputs crash, the crashes might hide backdoor
            // behavior or otherwise impede backdoor detection.
            config.fuzzers.iter().try_for_each(|fuzzer_config| {
                if with_cleanup!(fuzzer_config.backend.found_crashes(), fuzzer_instances)? {
                    println_warning!(
                        "the fuzzer '{}' has detected one or more crashes. This is probably \
                        hindering the thorough exploration of the binary; it is recommended that \
                        you fix the crashes and try again.",
                        fuzzer_config.backend.name(),
                    );
                    already_warned_about_crashes = true;
                }

                Ok(())
            })?;
        }

        // Collect new traces.
        let new_traces = with_cleanup!(
            collect_new_traces(
                &config,
                &mut trace_db,
                // Skip missing traces, because the fuzzer(s) is/are continually producing new ones,
                // and we might miss some because of the timing of the writes; it's okay, we'll pick
                // them up on the next iteration.
                true,
                collect_from_all_fuzzers,
                // Only collect one trace to keep performance optimal.
                false,
            ),
            fuzzer_instances
        )?;
        // Save traces to output dir for later inspection.
        with_cleanup!(
            trace::save_traces(&new_traces, &config.traces_dir()),
            fuzzer_instances
        )?;

        // Update coverage.
        let current_traces: Vec<Trace> = trace_db.traces().clone();
        let (edge_coverage, syscall_coverage) = trace::get_coverage(&current_traces);
        config.set_current_coverage(edge_coverage, syscall_coverage)?;

        // Check whether the seed stopping conditions have been met.
        if with_cleanup!(config.get_current_phase(), fuzzer_instances)?
            == RosaPhase::CollectingInputs
            && check_phase_one(
                &config.phase_one,
                start_time.elapsed().as_secs(),
                edge_coverage,
                syscall_coverage,
            )
            // Make sure we have *at least one* trace before we switch to clustering, otherwise we
            // won't be able to have any clusters.
            //
            // This does mean that we may spend more time than expected in phase one, but we can't
            // move on without at least one trace (i.e., at least one cluster). This probably
            // happens because the fuzzer instances and/or the target program are too slow.
            && !current_traces.is_empty()
        {
            // We're entering seed clustering phase; write it into the phase file so that the
            // TUI can keep up.
            with_cleanup!(
                config.set_current_phase(RosaPhase::ClusteringInputs),
                fuzzer_instances
            )?;
        }

        // Take care of clustering (if we've hit that phase).
        if with_cleanup!(config.get_current_phase(), fuzzer_instances)?
            == RosaPhase::ClusteringInputs
        {
            // Form seed clusters.
            if no_tui {
                println_info!("Clustering family-representative inputs...");
            }
            clusters = clustering::cluster_traces(
                &current_traces,
                config.cluster_formation_criterion,
                config.cluster_formation_distance_metric.clone(),
                config.cluster_formation_edge_tolerance,
                config.cluster_formation_syscall_tolerance,
            );
            // Save clusters to output dir for later inspection.
            with_cleanup!(
                clustering::save_clusters(&clusters, &config.clusters_dir()),
                fuzzer_instances
            )?;
            if no_tui {
                println_info!("Created {} clusters.", clusters.len());
            }

            // We're entering detection phase; write it into the phase file so that the TUI can
            // keep up.
            with_cleanup!(
                config.set_current_phase(RosaPhase::DetectingBackdoors),
                fuzzer_instances
            )?;
        }

        // Save decisions.
        match with_cleanup!(config.get_current_phase(), fuzzer_instances)? {
            RosaPhase::Starting | RosaPhase::CollectingInputs | RosaPhase::ClusteringInputs => {
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
                    fuzzer_instances
                )?;
            }
            RosaPhase::DetectingBackdoors | RosaPhase::Stopped => {
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
                                config.cluster_selection_distance_metric.clone(),
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
                            config.oracle_distance_metric.clone(),
                        );
                        (trace, decision)
                    })
                    .try_for_each(|(trace, decision)| {
                        if decision.is_backdoor {
                            nb_total_backdoors += 1;

                            // Get the fingeprint to deduplicate backdoor.
                            // Essentially, if the backdoor was detected for the same reason as a
                            // pre-existing backdoor, we should avoid listing them as two different
                            // backdoors.
                            let fingerprint = decision
                                .discriminants
                                .fingerprint(config.oracle_criterion, &decision.cluster_uid);

                            // Attempt to create a directory for this category of backdoor.
                            let backdoor_dir = config.backdoors_dir().join(fingerprint);
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
                                trace.save_test_input(&backdoor_dir.join(trace.uid())),
                                fuzzer_instances
                            )?;
                        }

                        let timed_decision = TimedDecision {
                            decision,
                            seconds: start_time.elapsed().as_secs(),
                        };

                        with_cleanup!(
                            timed_decision.save(&config.decisions_dir()),
                            fuzzer_instances
                        )
                    })?;
            }
        }

        // Update stats every second.
        if Instant::now().duration_since(last_log_time).as_secs() >= 1 {
            with_cleanup!(
                config.log_stats(
                    start_time.elapsed().as_secs(),
                    current_traces.len() as u64,
                    nb_unique_backdoors,
                    nb_total_backdoors,
                    edge_coverage,
                    syscall_coverage,
                ),
                fuzzer_instances
            )?;
            last_log_time = Instant::now();

            if no_tui {
                println_info!(
                    "Time: {} s | Traces: {} | Backdoors: {} unique ({} total) | \
                        Edge coverage: {:.2}% | Syscall coverage: {:.2}%",
                    start_time.elapsed().as_secs(),
                    current_traces.len() as u64,
                    nb_unique_backdoors,
                    nb_total_backdoors,
                    edge_coverage * 100.0,
                    syscall_coverage * 100.0
                );
            }
        }
    }

    // Shut down TUI thread.
    let _ = tx.send(());
    if let Some(handle) = tui_thread_handle {
        let _ = handle.join();
    }

    // Print a newline to clear screen after exiting TUI.
    eprintln!();
    println_info!("Stopping fuzzer processes.");
    fuzzer_instances
        .iter_mut()
        .try_for_each(|fuzzer_instance| {
            fuzzer_instance.stop()?;
            // Run the teardown for each instance.
            fuzzer_instance
                .config
                .backend
                .teardown(&fuzzer_instance.scratch_dir)
        })?;

    if !hard_stop {
        println_info!("Collecting remaining fuzzer inputs...");
        let new_traces = collect_new_traces(
            &config,
            &mut trace_db,
            // Do not skip missing traces. The fuzzers are stopped, so every trace we're
            // interested in should be there.
            false,
            collect_from_all_fuzzers,
            // Collect all remaining traces. We don't care about iterating fast per trace here,
            // since the fuzzers are stopped.
            true,
        )?;
        // Save traces to output dir for later inspection.
        trace::save_traces(&new_traces, &config.traces_dir())?;

        // Run the oracle on the traces.
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
                        config.cluster_selection_distance_metric.clone(),
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
                    config.oracle_distance_metric.clone(),
                );
                (trace, decision)
            })
            .try_for_each(|(trace, decision)| {
                if decision.is_backdoor {
                    nb_total_backdoors += 1;

                    // Get the fingeprint to deduplicate backdoor.
                    // Essentially, if the backdoor was detected for the same reason as a
                    // pre-existing backdoor, we should avoid listing them as two different
                    // backdoors.
                    let fingerprint = decision
                        .discriminants
                        .fingerprint(config.oracle_criterion, &decision.cluster_uid);

                    // Attempt to create a directory for this category of backdoor.
                    let backdoor_dir = config.backdoors_dir().join(fingerprint);
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
                    trace.save_test_input(&backdoor_dir.join(trace.uid()))?;
                }

                let timed_decision = TimedDecision {
                    decision,
                    seconds: start_time.elapsed().as_secs(),
                };

                timed_decision.save(&config.decisions_dir())
            })?;

        // Before exiting, update coverage & stats.
        let current_traces: Vec<Trace> = trace_db.traces().clone();
        let (edge_coverage, syscall_coverage) = trace::get_coverage(&current_traces);
        config.set_current_coverage(edge_coverage, syscall_coverage)?;
        config.log_stats(
            start_time.elapsed().as_secs(),
            current_traces.len() as u64,
            nb_unique_backdoors,
            nb_total_backdoors,
            edge_coverage,
            syscall_coverage,
        )?;
    }

    config.set_current_phase(RosaPhase::Stopped)?;

    Ok(())
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let cli = Cli::parse();

    match run(
        &cli.config_file,
        cli.force,
        cli.phase_one_corpus.as_deref(),
        cli.verbose,
        cli.no_tui,
        cli.wait_for_fuzzers,
        cli.hard_stop,
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
