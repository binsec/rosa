//! Capture a runtime trace with a given input to a given program.

use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
use colored::Colorize;

use rosa::{config::Config, error, error::RosaError, fail, trace::TraceDatabase};

mod common;
#[macro_use]
#[allow(unused_macros)]
mod logging;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Capture a runtime trace.",
    long_about = None,
    propagate_version = true)]
struct Cli {
    /// The configuration file to use.
    #[arg(long_help, value_name = "CONFIG FILE", help = "Configuration file")]
    config_file: PathBuf,

    /// A file containing input to the target program specified in the configuration file.
    #[arg(long_help, value_name = "INPUT FILE", help = "Input file")]
    input_file: PathBuf,

    /// The output trace file.
    ///
    /// If a name is not provided, the trace's UID will be used.
    #[arg(long_help, short, long, help = "Output trace file")]
    output: Option<PathBuf>,
}

fn run(config_file: &Path, input_file: &Path, output_file: Option<&Path>) -> Result<(), RosaError> {
    let config = Config::load(config_file)?;

    // Check that the main fuzzer is AFL++ in standard mode, otherwise this won't work.
    // TODO maybe adapt it to QEMU too?
    let main_fuzzer = config.main_fuzzer()?;
    if main_fuzzer.backend.backend_id() != *"afl++-standard" {
        fail!(
            "unsupported main fuzzer backend: only AFL++ in standard mode is currently supported."
        )?;
    }

    if !input_file.is_file() {
        fail!("invalid input file '{}'.", input_file.display())?;
    }

    println_info!(
        "Running target program to collect the trace for input '{}'...",
        input_file.display()
    );
    // Copy the input file to a temporary directory to be able to load it with the built-in
    // trace collection mechanism.
    let trace_dir = tempfile::tempdir()
        .map_err(|err| error!("could not create temporary directory: {}.", err))?;
    let scratch_dir = tempfile::tempdir()
        .map_err(|err| error!("could not create temporary directory: {}.", err))?;
    let input_copy = trace_dir.path().join(
        input_file
            .file_name()
            .expect("failed to get file name for input file."),
    );
    fs::copy(input_file, input_copy).map_err(|err| {
        error!(
            "failed to copy input file '{}': {}.",
            input_file.display(),
            err
        )
    })?;

    let mut trace_db = TraceDatabase::new();
    main_fuzzer.backend.setup(scratch_dir.path())?;
    let trace = main_fuzzer
        .backend
        .collect_one_trace(
            &mut trace_db,
            false,
            scratch_dir.path(),
            Some(trace_dir.path()),
        )?
        .ok_or(error!("could not load any traces."))?;
    main_fuzzer.backend.teardown(scratch_dir.path())?;

    let default_file = PathBuf::from(".").join(trace.uid()).with_extension("trace");
    let output_file = output_file.unwrap_or(&default_file);
    trace.save_trace_dump(output_file)?;
    println_info!("Done! Trace saved in '{}'.", output_file.display());

    Ok(())
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let cli = Cli::parse();

    match run(&cli.config_file, &cli.input_file, cli.output.as_deref()) {
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
