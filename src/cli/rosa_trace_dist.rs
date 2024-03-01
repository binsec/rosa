use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};

use clap::Parser;
use colored::Colorize;

use rosa::{distance_metric::DistanceMetric, error::RosaError, trace::Trace};

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
    trace1_uid: String,

    /// The second trace.
    trace2_uid: String,

    /// The ROSA output directory to pull traces from.
    #[arg(
        short = 'o',
        long = "output-dir",
        default_value = "out/",
        value_name = "DIR"
    )]
    output_dir: PathBuf,

    #[arg(short = 'd', long = "distance-metric", default_value = "hamming")]
    distance_metric: String,
}

fn run(
    output_dir: &Path,
    trace1_uid: &str,
    trace2_uid: &str,
    distance_metric: &str,
) -> Result<(), RosaError> {
    let trace1_path = output_dir.join("traces").join(trace1_uid);
    let trace1 = Trace::load("trace1", &trace1_path, &trace1_path.with_extension("trace"))?;

    let trace2_path = output_dir.join("traces").join(trace2_uid);
    let trace2 = Trace::load("trace2", &trace2_path, &trace2_path.with_extension("trace"))?;

    let distance_metric = DistanceMetric::from_str(distance_metric)?;

    let edge_wise_dist = distance_metric.dist(&trace1.edges, &trace2.edges);
    let syscall_wise_dist = distance_metric.dist(&trace1.syscalls, &trace2.syscalls);

    println_info!("Distances between '{}' and '{}':", trace1_uid, trace2_uid);
    println_info!("  Edge-wise: {}", edge_wise_dist);
    println_info!("  Syscall-wise: {}", syscall_wise_dist);

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(
        &cli.output_dir,
        &cli.trace1_uid,
        &cli.trace2_uid,
        &cli.distance_metric,
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
