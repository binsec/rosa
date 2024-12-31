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

use rosa::error;
use rosa::{config::Config, decision::TimedDecision, error::RosaError, trace::Trace};

mod common;
#[macro_use]
#[allow(unused_macros)]
mod logging;

use common::Component;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Explain backdoor detection results.",
    long_about = None,
    propagate_version = true)]
struct Cli {
    /// The ROSA output directory to pull traces from.
    #[arg(long_help, value_name = "DIR", help = "The ROSA output directory")]
    output_dir: PathBuf,

    /// The UID of the trace to explain.
    #[arg(long_help, value_name = "TRACE UID", help = "The UID of the trace")]
    trace_uid: String,

    /// The component of the trace to explain.
    #[arg(
        long_help,
        value_enum,
        short,
        long,
        default_value_t = Component::Syscalls,
        help = "The component to explain"
    )]
    component: Component,
}

/// Run the explanation tool.
///
/// Display the differences between the trace and its corresponding cluster.
fn run(output_dir: &Path, trace_uid: &str, component: Component) -> Result<(), RosaError> {
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

    println_info!("Explaining trace {}:", &trace_uid);
    println_info!("  Trace indicates a backdoor: {}", &decision.is_backdoor);
    println_info!("  Detection reason: {}", &decision.reason);
    println_info!("  Oracle criterion: {}", &config.oracle_criterion);
    println_info!("  Most similar cluster: {}", &decision.cluster_uid);

    println_info!("");

    println_info!("Found in the trace but not the cluster:");
    println!(
        "{}",
        match component {
            Component::Edges => trace_unique_edges,
            Component::Syscalls => trace_unique_syscalls,
        }
        .iter()
        .map(|item| item.to_string())
        .collect::<Vec<String>>()
        .join(", ")
    );

    println_info!("");

    println_info!("Found in the cluster but not the trace:");
    println!(
        "{}",
        match component {
            Component::Edges => cluster_unique_edges,
            Component::Syscalls => cluster_unique_syscalls,
        }
        .iter()
        .map(|item| item.to_string())
        .collect::<Vec<String>>()
        .join(", ")
    );

    Ok(())
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let cli = Cli::parse();

    match run(&cli.output_dir, &cli.trace_uid, cli.component) {
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
