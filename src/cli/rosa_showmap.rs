//! Print the edges/syscalls of a trace (like afl-showmap).

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
use colored::Colorize;

use rosa::{error::RosaError, trace::Trace};

mod common;
#[macro_use]
#[allow(unused_macros)]
mod logging;

use common::Component;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Show trace coverage.",
    long_about = None,
    propagate_version = true)]
struct Cli {
    /// The trace file to analyze.
    #[arg(long_help, value_name = "TRACE FILE", help = "Trace file")]
    trace_file: PathBuf,

    /// The component of the trace to show.
    #[arg(
        long_help,
        value_enum,
        short = 'c',
        long = "component",
        default_value_t = Component::Syscalls,
        value_name = "COMPONENT",
        help = "The component to show"
    )]
    component: Component,
}

fn run(file: &Path, component: Component) -> Result<(), RosaError> {
    Trace::load("_dummy", file, file).map(|trace| {
        let edges_output: Vec<String> = trace
            .edges
            .iter()
            .enumerate()
            .filter_map(|(index, edge)| match edge {
                0 => None,
                count => Some(format!("{:06}:{}", index, count)),
            })
            .collect();

        let syscalls_output: Vec<String> = trace
            .syscalls
            .iter()
            .enumerate()
            .filter_map(|(index, syscall)| match syscall {
                0 => None,
                count => Some(format!("{:06}:{}", index, count)),
            })
            .collect();

        println!(
            "{}",
            match component {
                Component::Edges => {
                    edges_output
                }
                Component::Syscalls => {
                    syscalls_output
                }
            }
            .join("\n")
        );
    })
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let cli = Cli::parse();

    match run(&cli.trace_file, cli.component) {
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
