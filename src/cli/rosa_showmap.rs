//! Print the edges/syscalls of a trace (like afl-showmap).

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
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
}

fn run(file: &Path) -> Result<(), RosaError> {
    Trace::load("_dummy", file, file).map(|trace| {
        trace
            .edges
            .iter()
            .enumerate()
            .for_each(|(index, edge)| match edge {
                0 => {}
                count => println!("{:06}:{}", index, count),
            })
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli.trace_file) {
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
