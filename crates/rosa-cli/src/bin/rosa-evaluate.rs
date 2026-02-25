//! Evaluate ROSA's findings using "ground-truth" programs.
//!
//! In order to confidently evaluate the quality of ROSA's findings (e.g. how many "backdoors" in
//! its findings are actually backdoors?), we need a **ground-truth** version of the target
//! program. This version should print the string `***BACKDOOR TRIGGERED***` in `stderr` for every
//! triggered backdoor, so that this tool can confidently say if a backdoor has been reached.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::File,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use clap::{ArgAction, Parser};
use colored::Colorize;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

use rosa::{error, error::RosaError, oracle::TimedDecision};
use rosa_cli::{
    config::{self, Config},
    error_message,
    fuzzer::FuzzerBackend,
    info_message, println_error, println_info, rosa_message,
};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Evaluate a ROSA backdoor detection campaign.",
    long_about = None,
    propagate_version = true)]
struct Cli {
    /// The ROSA output directory to pull traces from.
    #[arg(long_help, value_name = "DIR", help = "The ROSA output directory")]
    output_dir: PathBuf,

    /// Show a short summary of the results.
    #[arg(long_help, short = 's', long = "summary", help = "Summarize results")]
    show_summary: bool,

    /// Show the output (stdout & stderr) of the selected traces.
    #[arg(
        long_help,
        short = 'O',
        long = "show-output",
        help = "Show execution output"
    )]
    show_output: bool,

    /// The target program to run inputs through (if empty, use the command from the main fuzzer
    /// instance in the configuration).
    #[arg(
        long_help,
        short = 'p',
        long = "target-program",
        value_name = "\"CMD ARG1 ARG2 ...\"",
        help = "The target program to use"
    )]
    target_program_cmd: Option<String>,

    /// The environment to use for the target program (if empty, use the environment from the main
    /// fuzzer instance in the configuration).
    #[arg(
        long_help,
        short = 'e',
        long = "environment",
        value_name = "\"KEY1=VALUE1 KEY2=VALUE2 ...\"",
        help = "The environment to use"
    )]
    target_program_env: Option<String>,

    /// The trace to evaluate (can be used multiple times).
    #[arg(
        long_help,
        short = 'u',
        long = "trace-id",
        value_name = "TRACE_ID",
        action = ArgAction::Append,
        help = "Selected trace ID"
    )]
    trace_ids: Vec<String>,

    /// Do not deduplicate findings. Every finding will be treated as unique.
    #[arg(
        long_help,
        value_enum,
        short = 'D',
        long = "no-deduplication",
        action = ArgAction::SetFalse,
        help = "Do not deduplicate findings"
    )]
    deduplicate: bool,

    /// Do not evaluate traces analyzed past a certain time limit (in seconds).
    #[arg(
        long_help,
        short = 't',
        long = "time-limit",
        value_name = "SECONDS",
        help = "Trace time limit (in seconds)"
    )]
    time_limit: Option<u64>,
}

/// A kind of sample/finding.
#[derive(Clone, Debug, PartialEq)]
enum SampleKind {
    /// The sample is _marked_ as a backdoor and actually _is_ a backdoor.
    TruePositive,
    /// The sample is _marked_ as a backdoor but actually _is not_ a backdoor.
    FalsePositive,
    /// The sample is _not marked_ as a backdoor and actually _is not_ a backdoor.
    TrueNegative,
    /// The sample is _not marked_ as a backdoor but actually _is_ a backdoor.
    FalseNegative,
}

impl fmt::Display for SampleKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::TruePositive => "true_positive",
                Self::FalsePositive => "false_positive",
                Self::TrueNegative => "true_negative",
                Self::FalseNegative => "false_negative",
            }
        )
    }
}

/// A sample from ROSA's findings.
#[derive(Clone, Debug)]
struct Sample {
    /// The ID of the sample.
    id: String,
    /// The amount of seconds passed since the beginning of the detection campaign.
    seconds: u64,
    /// The kind of the sample.
    kind: SampleKind,
    /// The ID of the discriminant.
    discriminant_id: String,
}

/// Check a ROSA decision.
///
/// The test input is run through the ground-truth version of the target program, and we check to
/// see if `"***BACKDOOR TRIGGERED***"` appears in the output (`stderr` or `stdout`). We then check
/// against the decision to find out if the finding is a true/false positive/negative.
fn check_decision(
    cmd: &[String],
    env: &HashMap<String, String>,
    test_input_path: &Path,
    timed_decision: &TimedDecision,
    discriminant_id: String,
    show_output: bool,
) -> Result<Sample, RosaError> {
    let test_input_file = File::open(test_input_path).map_err(|err| {
        error!(
            "failed to read test input from file {}: {}.",
            test_input_path.display(),
            err
        )
    })?;

    // If the target program implements the `LLVMFuzzerTestOneInput()` interface, or simply
    // receives input via a file, then the user can pass `@@` (just like in AFL++) to denote that.
    let mut target_cmd = Command::new(&cmd[0]);
    let output = if cmd.contains(&"@@".to_string()) {
        let args: Vec<String> = cmd[1..]
            .iter()
            .map(|arg| {
                if arg == "@@" {
                    test_input_path.display().to_string()
                } else {
                    arg.to_string()
                }
            })
            .collect();
        target_cmd.args(&args)
    } else {
        target_cmd.args(&cmd[1..]).stdin(test_input_file)
    }
    .envs(config::replace_env_var_placeholders(env))
    .output()
    .map_err(|err| error!("failed to run target program: {}", err))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let backdoor =
        stdout.contains("***BACKDOOR TRIGGERED***") || stderr.contains("***BACKDOOR TRIGGERED***");

    if show_output {
        println_info!("stdout:");
        println!("{}", stdout);
        println_info!("stderr:");
        println!("{}", stderr);
    }

    let kind = match (backdoor, timed_decision.decision.is_backdoor) {
        (true, true) => SampleKind::TruePositive,
        (true, false) => SampleKind::FalseNegative,
        (false, true) => SampleKind::FalsePositive,
        (false, false) => SampleKind::TrueNegative,
    };

    Ok(Sample {
        id: timed_decision.decision.trace_id.clone(),
        seconds: timed_decision.seconds,
        kind,
        discriminant_id,
    })
}

/// Run the evaluation of ROSA's findings.
#[allow(clippy::too_many_arguments)]
fn run(
    output_dir: &Path,
    target_program_cmd: Option<String>,
    target_program_env: Option<String>,
    trace_ids: &[String],
    show_summary: bool,
    show_output: bool,
    deduplicate: bool,
    time_limit: Option<u64>,
) -> Result<(), RosaError> {
    // Make sure the config is using the output directory passed to this function.
    let mut config = Config::load(&output_dir.join("config").with_extension("toml"))?;
    config.output_dir = output_dir.to_path_buf();

    let root_dir = output_dir.parent().ok_or(error!(
        "could not get parent directory of '{}'.",
        output_dir.display()
    ))?;

    println_info!("Loading traces...");
    let all_traces = rosa_cli::trace::load_traces_from_dir(&root_dir.join(config.traces_dir()))?;

    let selected_trace_ids: Vec<String> = match trace_ids.len() {
        0 => all_traces.iter().map(|trace| trace.id()).collect(),
        _ => Vec::from(trace_ids),
    };

    let selected_cmd: Vec<String> = match target_program_cmd {
        Some(cmd) => cmd.split(' ').map(|arg| arg.to_string()).collect(),
        None => config.main_fuzzer()?.backend.cmd().clone(),
    };
    let selected_env: HashMap<String, String> = match target_program_env {
        Some(env) => env
            .split(' ')
            .map(|pair| {
                let mut splitter = pair.split('=');
                let key = splitter.next().unwrap_or("").to_string();
                let value = splitter.next().unwrap_or("").to_string();

                (key, value)
            })
            .collect(),
        None => config.main_fuzzer()?.backend.env().clone(),
    };

    let timed_decisions: Vec<TimedDecision> = selected_trace_ids
        .iter()
        .map(|trace_id| {
            rosa_cli::oracle::load_decision_from_file(
                &output_dir
                    .join("decisions")
                    .join(trace_id)
                    .with_extension("toml"),
            )
        })
        .collect::<Result<Vec<TimedDecision>, RosaError>>()?;
    println_info!("Evaluating {} traces...", timed_decisions.len());

    // Filter based on the time limit.
    let timed_decisions: Vec<TimedDecision> = timed_decisions
        .into_iter()
        .filter_map(|timed_decision| match time_limit {
            Some(limit_seconds) => {
                (timed_decision.seconds <= limit_seconds).then_some(timed_decision)
            }
            None => Some(timed_decision),
        })
        .collect();

    if let Some(limit_seconds) = time_limit {
        println_info!(
            "  ({} traces remaining after time limit of {} seconds)",
            timed_decisions.len(),
            limit_seconds
        );
    }

    // We can run the evaluations in parallel, since they're all independent.
    let mut samples: Vec<Sample> = timed_decisions
        .par_iter()
        .map(|timed_decision| {
            check_decision(
                &selected_cmd,
                &selected_env,
                &output_dir
                    .join("traces")
                    .join(&timed_decision.decision.trace_id),
                timed_decision,
                timed_decision
                    .decision
                    .discriminants
                    .fingerprint(config.oracle_criterion, &timed_decision.decision.cluster_id),
                show_output,
            )
        })
        .collect::<Result<Vec<Sample>, RosaError>>()?;

    // Sort by decision time.
    samples.sort_by(|sample1, sample2| sample1.seconds.cmp(&sample2.seconds));

    let samples = if deduplicate {
        let mut known_traces = HashSet::new();
        let samples: Vec<Sample> = samples
            .clone()
            .into_iter()
            .filter_map(|sample| match sample.kind {
                // Only deduplicate (true/false) _positives_, as that is what ROSA does to
                // deduplicate while running.
                SampleKind::TruePositive | SampleKind::FalsePositive => known_traces
                    .insert(sample.clone().discriminant_id)
                    .then_some(sample),
                // All other kinds of inputs are left in the same state.
                _ => Some(sample),
            })
            .collect();
        println_info!("  ({} traces remaining after deduplication)", samples.len());

        samples
    } else {
        samples
    };

    let seconds_to_first_backdoor = samples
        .iter()
        .find(|sample| sample.kind == SampleKind::TruePositive)
        .map_or("N/A".to_string(), |sample| sample.seconds.to_string());

    let header = if show_summary {
        "true_positives,false_positives,true_negatives,false_negatives,seconds_to_first_backdoor"
    } else {
        "trace_id,result,seconds"
    };

    let body = if show_summary {
        format!(
            "{},{},{},{},{}",
            samples
                .iter()
                .filter(|sample| sample.kind == SampleKind::TruePositive)
                .count(),
            samples
                .iter()
                .filter(|sample| sample.kind == SampleKind::FalsePositive)
                .count(),
            samples
                .iter()
                .filter(|sample| sample.kind == SampleKind::TrueNegative)
                .count(),
            samples
                .iter()
                .filter(|sample| sample.kind == SampleKind::FalseNegative)
                .count(),
            seconds_to_first_backdoor
        )
    } else {
        samples
            .iter()
            .map(|sample| format!("{},{},{}", sample.id, sample.kind, sample.seconds))
            .collect::<Vec<String>>()
            .join("\n")
    };

    println!("{}\n{}", header, body);

    Ok(())
}

fn main() -> ExitCode {
    rosa_cli::reset_sigpipe();

    let cli = Cli::parse();

    match run(
        &cli.output_dir,
        cli.target_program_cmd,
        cli.target_program_env,
        &cli.trace_ids,
        cli.show_summary,
        cli.show_output,
        cli.deduplicate,
        cli.time_limit,
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
