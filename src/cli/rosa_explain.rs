//! Explain a ROSA finding.
//!
//! Sometimes, it is useful to go beyond the _reason_ of a decision made by the metamorphic oracle;
//! this little program allows us to do so by printing all the remarkable differences between a
//! given trace and its cluster. That might shed some more light into why something was or wasn't
//! classified as a backdoor.

use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
use colored::Colorize;
use itertools::Itertools;

use rosa::error;
use rosa::{config::Config, decision::TimedDecision, error::RosaError, trace::Trace};

#[macro_use]
#[allow(unused_macros)]
mod logging;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Explain backdoor detection results.",
    long_about = None,
    propagate_version = true)]
struct Cli {
    /// The ROSA output directory to pull traces from.
    #[arg(
        short = 'o',
        long = "output-dir",
        default_value = "out/",
        value_name = "DIR"
    )]
    output_dir: PathBuf,

    /// The trace to explain.
    trace_uid: String,
}

/// Run the explanation tool.
///
/// # Arguments
/// * `output_dir` - Path to the output directory where ROSA's findings are stored.
/// * `trace_uid` - The unique ID of the trace we want to get explanations for.
fn run(output_dir: &Path, trace_uid: &str) -> Result<(), RosaError> {
    let config = Config::load(&output_dir.join("config").with_extension("toml"))?;
    let timed_decision = TimedDecision::load(
        &output_dir
            .join("decisions")
            .join(trace_uid)
            .with_extension("toml"),
    )?;
    let decision = timed_decision.decision;
    let trace = Trace::load(
        &decision.trace_uid,
        &output_dir.join("traces").join(trace_uid),
        &output_dir
            .join("traces")
            .join(trace_uid)
            .with_extension("trace"),
    )?;

    let cluster_file_content = fs::read_to_string(
        output_dir
            .join("clusters")
            .join(&decision.cluster_uid)
            .with_extension("txt"),
    )
    .map_err(|err| {
        error!(
            "could not read cluster '{}' in {}: {}.",
            &decision.cluster_uid,
            output_dir.display(),
            err
        )
    })?;
    let cluster_trace_uids: Vec<&str> = cluster_file_content
        .split('\n')
        .filter(|line| !line.trim().is_empty())
        .collect();
    let cluster: Vec<Trace> = cluster_trace_uids
        .iter()
        .map(|trace_uid| {
            Trace::load(
                trace_uid,
                &output_dir.join("traces").join(trace_uid),
                &output_dir
                    .join("traces")
                    .join(trace_uid)
                    .with_extension("trace"),
            )
        })
        .collect::<Result<Vec<Trace>, RosaError>>()?;

    let trace_unique_edges: Vec<usize> = trace
        .edges
        .iter()
        .enumerate()
        .filter_map(|(index, edge)| match edge {
            0u8 => None,
            _ => Some(index),
        })
        .filter(|index| {
            cluster
                .iter()
                .all(|cluster_trace| cluster_trace.edges[*index] == 0)
        })
        .collect();
    let trace_unique_syscalls: Vec<usize> = trace
        .syscalls
        .iter()
        .enumerate()
        .filter_map(|(index, syscall)| match syscall {
            0u8 => None,
            _ => Some(index),
        })
        .filter(|index| {
            cluster
                .iter()
                .all(|cluster_trace| cluster_trace.syscalls[*index] == 0)
        })
        .collect();

    let cluster_unique_edges: Vec<usize> = trace
        .edges
        .iter()
        .enumerate()
        .filter_map(|(index, edge)| match edge {
            0u8 => Some(index),
            _ => None,
        })
        .filter(|index| {
            cluster
                .iter()
                .any(|cluster_trace| cluster_trace.edges[*index] != 0)
        })
        .collect();
    let cluster_unique_syscalls: Vec<usize> = trace
        .syscalls
        .iter()
        .enumerate()
        .filter_map(|(index, syscall)| match syscall {
            0u8 => Some(index),
            _ => None,
        })
        .filter(|index| {
            cluster
                .iter()
                .any(|cluster_trace| cluster_trace.syscalls[*index] != 0)
        })
        .collect();

    let trace_edge_dists = cluster.iter().map(|cluster_trace| {
        config
            .oracle_distance_metric
            .dist(&trace.edges, &cluster_trace.edges)
    });
    let trace_syscall_dists = cluster.iter().map(|cluster_trace| {
        config
            .oracle_distance_metric
            .dist(&trace.syscalls, &cluster_trace.syscalls)
    });

    let cluster_edge_dists = cluster.iter().combinations(2).map(|trace_pair| {
        config.oracle_distance_metric.dist(
            &trace_pair
                .first()
                .expect("failed to get first trace of trace pair.")
                .edges,
            &trace_pair
                .last()
                .expect("failed to get second trace of trace pair.")
                .edges,
        )
    });
    let cluster_syscall_dists = cluster.iter().combinations(2).map(|trace_pair| {
        config.oracle_distance_metric.dist(
            &trace_pair
                .first()
                .expect("failed to get first trace of trace pair.")
                .syscalls,
            &trace_pair
                .last()
                .expect("failed to get second trace of trace pair.")
                .syscalls,
        )
    });

    println_info!("Explaining trace '{}' ('{}'):", &trace_uid, trace.name);
    println_info!("  Trace indicates a backdoor: {}", &decision.is_backdoor);
    println_info!("  Detection reason: {}", &decision.reason);
    println_info!("  Oracle criterion: {}", &config.oracle_criterion);
    println_info!("  Most similar cluster: {}", &decision.cluster_uid);

    println_info!("");

    println_info!("Found in the trace but not the cluster:");
    println_info!(
        "  Edges: {}",
        trace_unique_edges
            .iter()
            .map(|edge| edge.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    );
    println_info!(
        "  Syscalls: {}",
        trace_unique_syscalls
            .iter()
            .map(|syscall| syscall.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    );

    println_info!("");

    println_info!("Found in the cluster but not in the trace:");
    println_info!(
        "  Edges: {}",
        cluster_unique_edges
            .iter()
            .map(|edge| edge.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    );
    println_info!(
        "  Syscalls: {}",
        cluster_unique_syscalls
            .iter()
            .map(|syscall| syscall.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    );

    println_info!("");

    println_info!("Distances from trace to cluster:");
    println_info!("  Edges:");
    println_info!(
        "    Min: {}",
        trace_edge_dists
            .clone()
            .min()
            .expect("failed to get min edge distance for trace.")
    );
    println_info!(
        "    Max: {}",
        trace_edge_dists
            .clone()
            .max()
            .expect("failed to get max edge distance for trace.")
    );
    println_info!("  Syscalls:");
    println_info!(
        "    Min: {}",
        trace_syscall_dists
            .clone()
            .min()
            .expect("failed to get min syscall distance for trace.")
    );
    println_info!(
        "    Max: {}",
        trace_syscall_dists
            .clone()
            .max()
            .expect("failed to get max syscall distance for trace.")
    );

    println_info!("");

    println_info!("Distances from cluster to cluster:");
    println_info!("  Edges:");
    println_info!(
        "    Min: {}",
        cluster_edge_dists
            .clone()
            .min()
            .unwrap_or(config.cluster_formation_edge_tolerance)
    );
    println_info!(
        "    Max: {}",
        cluster_edge_dists
            .clone()
            .max()
            .unwrap_or(config.cluster_formation_edge_tolerance)
    );
    println_info!("  Syscalls:");
    println_info!(
        "    Min: {}",
        cluster_syscall_dists
            .clone()
            .min()
            .unwrap_or(config.cluster_formation_syscall_tolerance)
    );
    println_info!(
        "    Max: {}",
        cluster_syscall_dists
            .clone()
            .max()
            .unwrap_or(config.cluster_formation_syscall_tolerance)
    );

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli.output_dir, &cli.trace_uid) {
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
