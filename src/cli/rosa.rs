use std::{
    collections::HashMap,
    path::PathBuf,
    process::ExitCode,
    sync::mpsc::{self, TryRecvError},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread, time,
};

use clap::Parser;
use colored::Colorize;

use rosa::{
    clustering,
    config::Config,
    decision::{Decision, DecisionReason},
    error::RosaError,
    fuzzer::{self, FuzzerProcess},
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
        default_value = "config.json",
        value_name = "FILE"
    )]
    config_file: String,

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
    ( $action:expr, $fuzzer_process:tt ) => {{
        $action.or_else(|err| {
            $fuzzer_process.stop()?;
            Err(err)
        })
    }};
}

fn run(config_file: &str, force: bool, verbose: bool, no_tui: bool) -> Result<(), RosaError> {
    // Load the configuration and set up the output directories.
    let config_file_path = PathBuf::from(config_file);
    let config = Config::load(&config_file_path)?;
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

    // Set up both fuzzer processes.
    let mut fuzzer_seed_process = FuzzerProcess::create(
        config.fuzzer_seed_cmd.clone(),
        config.fuzzer_seed_env.clone(),
        config
            .logs_dir()
            .clone()
            .join("fuzzer_seed")
            .with_extension("log"),
    )?;
    let mut fuzzer_run_process = FuzzerProcess::create(
        config.fuzzer_run_cmd.clone(),
        config.fuzzer_run_env.clone(),
        config
            .logs_dir()
            .clone()
            .join("fuzzer_run")
            .with_extension("log"),
    )?;

    // Setup communication channel with TUI.
    let (tx, rx) = mpsc::channel::<()>();

    // Spawn the fuzzer seed process.
    println_info!("Collecting seed traces...");
    if verbose {
        println_verbose!("Fuzzer seed process:");
        println_verbose!("  Env: {}", fuzzer_seed_process.env_as_string());
        println_verbose!("  Cmd: {}", fuzzer_seed_process.cmd_as_string());
    }
    fuzzer_seed_process.spawn()?;

    // Wait for the fuzzer process (or for a Ctrl-C).
    while fuzzer_seed_process.is_running()? && !rosa_should_stop.load(Ordering::Acquire) {}

    // Check to see if we received a Ctrl-C while waiting.
    if fuzzer_seed_process.is_running()? && rosa_should_stop.load(Ordering::Acquire) {
        println_info!("Stopping fuzzer seed process.");
        fuzzer_seed_process.stop()?;
        return Ok(());
    }

    // Check the exit code of the fuzzer seed process.
    fuzzer_seed_process.check_success().map_err(|err| {
        rosa::error!(
            "fuzzer seed command failed: {}. See {}.",
            err,
            fuzzer_seed_process.log_file.display()
        )
    })?;

    // Check for crashes; if some of the inputs crash, the fuzzer will most likely get oriented
    // towards that family of inputs, which decreases the overall chance of finding backdoors.
    if fuzzer::fuzzer_found_crashes(&config.crashes_dir)? {
        println_warning!(
            "the fuzzer has detected one or more crashes in {}. This is probably hindering the \
            thorough exploration of the binary; it is recommended that you fix the crashes and \
            try again.",
            &config.crashes_dir.display()
        );
    }
    // Collect seed traces.
    let seed_traces = trace::load_traces(
        &config.test_input_dir,
        &config.trace_dump_dir,
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
            let decision = Decision {
                trace_uid: trace.uid.clone(),
                cluster_uid: cluster.uid.clone(),
                is_backdoor: false,
                reason: DecisionReason::Seed,
            };

            decision.save(&config.decisions_dir())
        })
    })?;

    // Spawn the fuzzer run process.
    println_info!("Starting backdoor detection...");
    if verbose {
        println_verbose!("Fuzzer run process:");
        println_verbose!("  Env: {}", fuzzer_run_process.env_as_string());
        println_verbose!("  Cmd: {}", fuzzer_run_process.cmd_as_string());
    }
    fuzzer_run_process.spawn()?;
    let mut nb_backdoors = 0;
    // Sleep for 3 seconds to give some time to the fuzzer to get started.
    thread::sleep(time::Duration::from_secs(3));

    // Start the TUI thread.
    let monitor_dir = config.output_dir.clone();
    let tui_thread_handle = match no_tui {
        true => None,
        false => Some(thread::spawn(move || -> Result<(), RosaError> {
            let mut tui = RosaTui::new(&monitor_dir);
            tui.start()?;

            loop {
                tui.render()?;

                // Give some time to the renderer to do its job.
                thread::sleep(time::Duration::from_millis(200));

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

    let mut already_warned_about_crashes = false;
    // Loop until Ctrl-C.
    while !rosa_should_stop.load(Ordering::SeqCst) {
        if !already_warned_about_crashes && no_tui {
            // Check for crashes; if some of the inputs crash, the fuzzer will most likely get
            // oriented towards that family of inputs, which decreases the overall chance of
            // finding backdoors.
            if fuzzer::fuzzer_found_crashes(&config.crashes_dir)? {
                println_warning!(
                    "the fuzzer has detected one or more crashes in {}. This is probably \
                    hindering the thorough exploration of the binary; it is recommended that you \
                    fix the crashes and try again.",
                    &config.crashes_dir.display()
                );
                already_warned_about_crashes = true;
            }
        }

        // Collect new traces.
        let new_traces = with_cleanup!(
            trace::load_traces(
                &config.test_input_dir,
                &config.trace_dump_dir,
                &mut known_traces,
                // Skip missing traces, because the fuzzer is continually producing new ones, and
                // we might miss some because of the timing of the writes; it's okay, we'll pick
                // them up on the next iteration.
                true,
            ),
            fuzzer_run_process
        )?;
        // Save traces to output dir for later inspection.
        with_cleanup!(
            trace::save_traces(&new_traces, &config.traces_dir()),
            fuzzer_run_process
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
                            println_verbose!("Trace {}:", trace.uid);
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
                        fuzzer_run_process
                    )?;
                }

                with_cleanup!(decision.save(&config.decisions_dir()), fuzzer_run_process)
            })?;
    }

    // Shut down TUI thread.
    let _ = tx.send(());
    if let Some(handle) = tui_thread_handle {
        let _ = handle.join();
    }
    println_info!("Stopping fuzzer run process.");
    fuzzer_run_process.stop()?;

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
        Cli::command().verbose_assert()
    }
}
