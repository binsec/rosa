//! Print the edges/syscalls of a trace (like afl-showmap).

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, ValueEnum};
use colored::Colorize;

use rosa::{error::RosaError, trace::Trace};

#[macro_use]
#[allow(unused_macros)]
mod logging;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Show trace coverage.",
    long_about = None,
    propagate_version = true)]
struct Cli {
    /// The trace file to analyze.
    trace_file: PathBuf,

    /// The component of the trace to show.
    #[arg(
        value_enum,
        short = 'c',
        long = "component",
        default_value_t = Component::Edges,
        value_name = "COMPONENT"
    )]
    component: Component,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Component {
    Edges,
    Syscalls,
    EdgesAndSyscalls,
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

        match component {
            Component::Edges => {
                println!("{}", edges_output.join("\n"));
            }
            Component::Syscalls => {
                println!("{}", syscalls_output.join("\n"));
            }
            Component::EdgesAndSyscalls => {
                println!("EDGES");
                println!("{}", edges_output.join("\n"));
                println!("SYSCALLS");
                println!("{}", syscalls_output.join("\n"));
            }
        }
    })
}

// Reset SIGPIPE, so that the output of rosa-showmap may be piped to other stuff.
// See https://stackoverflow.com/q/65755853/.
fn reset_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

fn main() -> ExitCode {
    reset_sigpipe();
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
