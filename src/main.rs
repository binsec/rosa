use colored::Colorize;

use std::{
    collections::HashMap,
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread, time,
};

use clap::Parser;

use crate::{config::Config, error::RosaError, fuzzer::FuzzerProcess};

#[macro_use]
mod logging;
#[macro_use]
mod error;

mod clustering;
mod config;
mod criterion;
mod decision;
mod distance_metric;
mod fuzzer;
mod oracle;
mod trace;

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
        default_value = "config.ini",
        value_name = "FILE"
    )]
    config_file: String,

    /// The output directory to use.
    #[arg(
        short = 'o',
        long = "output",
        default_value = "out",
        value_name = "DIR"
    )]
    output_dir: String,

    /// Force the creation of the output directory, potentially overwriting existing results.
    #[arg(short = 'f', long = "force")]
    force: bool,
}

macro_rules! with_cleanup {
    ( $action:expr, $fuzzer_process:tt ) => {{
        $action.or_else(|err| {
            $fuzzer_process.stop()?;
            Err(err)
        })
    }};
}

fn run(config_file: &str, output_dir: &str, force: bool) -> Result<(), RosaError> {
    // Load the configuration and set up the output directories.
    let config = Config::load(config_file, output_dir)?;
    config.setup_dirs(force)?;

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

    // Spawn the fuzzer seed process.
    println_info!("Collecting seed traces...");
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
    fuzzer_seed_process.check_success().or_else(|err| {
        fail!(
            "fuzzer seed command failed: {}. See {}.",
            err,
            fuzzer_seed_process.log_file.display()
        )
    })?;

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
        cluster
            .traces
            .iter()
            .map(|trace| {
                let decision = known_traces
                    .get(&trace.uid)
                    .expect("failed to get decision for seed trace.");

                decision.save(&trace.uid, &cluster.uid, &config, &config.decisions_dir())
            })
            .collect::<Result<(), RosaError>>()
    })?;

    // Spawn the fuzzer run process.
    println_info!("Starting backdoor detection...");
    fuzzer_run_process.spawn()?;
    // Sleep for 3 seconds to give some time to the fuzzer to get started.
    thread::sleep(time::Duration::from_secs(3));

    // Loop until Ctrl-C.
    while !rosa_should_stop.load(Ordering::SeqCst) {
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
                    &cluster,
                    config.oracle_criterion,
                    config.oracle_distance_metric,
                );
                (trace, cluster, decision)
            })
            .try_for_each(|(trace, cluster, decision)| {
                if decision.is_backdoor {
                    println_info!("!!!! BACKDOOR FOUND !!!!");
                    trace.print(false);
                    decision.print();

                    // Save backdoor.
                    with_cleanup!(
                        trace::save_trace_test_input(&trace, &config.backdoors_dir()),
                        fuzzer_run_process
                    )?;
                }

                with_cleanup!(
                    decision.save(&trace.uid, &cluster.uid, &config, &config.decisions_dir()),
                    fuzzer_run_process
                )
            })?;
    }

    println_info!("Stopping fuzzer run process.");
    fuzzer_run_process.stop()?;

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli.config_file, &cli.output_dir, cli.force) {
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
