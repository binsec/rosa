//! Show the distances between two traces
//!
//! Sometimes it is useful to be able to quickly know the distances (in terms of both edges &
//! syscalls) between two traces; this is what this tool is for.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};

use clap::Parser;
use colored::Colorize;

use rosa::{distance_metric::DistanceMetric, error::RosaError, trace::Trace};

mod common;
#[macro_use]
#[allow(unused_macros)]
mod logging;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Calculate distance between two traces.",
    long_about = None,
    propagate_version = true)]
struct Cli {
    /// The first trace.
    #[arg(long_help, value_name = "TRACE 1 UID", help = "UID of first trace")]
    trace_1_uid: String,

    /// The second trace.
    #[arg(long_help, value_name = "TRACE 2 UID", help = "UID of second trace")]
    trace_2_uid: String,

    /// The ROSA output directory to pull traces from.
    #[arg(long_help, value_name = "DIR", help = "The ROSA output directory")]
    output_dir: PathBuf,

    /// The distance metric to use.
    #[arg(
        long_help,
        short,
        long,
        default_value = "hamming",
        help = "The distance metric to use"
    )]
    distance_metric: String,

    /// Display all edges and system calls that differ.
    #[arg(long_help, short, long, help = "Be more verbose")]
    verbose: bool,
}

/// Run the distance calculation tool.
fn run(
    output_dir: &Path,
    trace_1_uid: &str,
    trace_2_uid: &str,
    distance_metric: &str,
    verbose: bool,
) -> Result<(), RosaError> {
    let trace_1_path = output_dir.join("traces").join(trace_1_uid);
    let trace_1 = Trace::load(
        "trace_1",
        &trace_1_path,
        &trace_1_path.with_extension("trace"),
    )?;

    let trace_2_path = output_dir.join("traces").join(trace_2_uid);
    let trace_2 = Trace::load(
        "trace_2",
        &trace_2_path,
        &trace_2_path.with_extension("trace"),
    )?;

    let distance_metric = DistanceMetric::from_str(distance_metric)?;

    let edge_wise_dist = distance_metric.dist(&trace_1.edges, &trace_2.edges);
    let syscall_wise_dist = distance_metric.dist(&trace_1.syscalls, &trace_2.syscalls);

    println_info!("Distances between '{}' and '{}':", trace_1_uid, trace_2_uid);
    println_info!("  Edge-wise: {}", edge_wise_dist);
    println_info!("  Syscall-wise: {}", syscall_wise_dist);

    if verbose {
        println_info!("");
        println_info!("Edges differing:");
        trace_1
            .edges
            .into_iter()
            .zip(trace_2.edges)
            .enumerate()
            .for_each(|(index, (edge1, edge2))| {
                if edge1 != edge2 {
                    println_info!("#{}: {} != {}", index, edge1, edge2);
                }
            });

        println_info!("");
        println_info!("Syscalls differing:");
        trace_1
            .syscalls
            .into_iter()
            .zip(trace_2.syscalls)
            .enumerate()
            .for_each(|(index, (edge1, edge2))| {
                if edge1 != edge2 {
                    println_info!("#{}: {} != {}", index, edge1, edge2);
                }
            });
    }

    Ok(())
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let cli = Cli::parse();

    match run(
        &cli.output_dir,
        &cli.trace_1_uid,
        &cli.trace_2_uid,
        &cli.distance_metric,
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
