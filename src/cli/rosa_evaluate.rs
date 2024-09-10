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
    process::{Command, ExitCode, Stdio},
};

use clap::{ArgAction, Parser};
use colored::Colorize;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

use rosa::error;
use rosa::{
    config::{self, Config},
    decision::TimedDecision,
    error::RosaError,
    trace,
};

#[macro_use]
#[allow(unused_macros)]
mod logging;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Evaluate backdoor detection.",
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

    /// Show a summary of the results.
    #[arg(short = 's', long = "summary")]
    show_summary: bool,

    /// Show the output (stdout & stderr) of the selected traces.
    #[arg(short = 'O', long = "show-output")]
    show_output: bool,

    /// The target program to run traces through (if empty, use the command from the first fuzzer
    /// in the configuration).
    #[arg(
        short = 'p',
        long = "target-program",
        value_name = "\"CMD ARG1 ARG2 ...\""
    )]
    target_program_cmd: Option<String>,

    /// The environment to use for the target program (if empty, use the environment from the first
    /// fuzzer in the configuration).
    #[arg(
        short = 'e',
        long = "environment",
        value_name = "\"KEY1=VALUE1 KEY2=VALUE2 ...\""
    )]
    target_program_env: Option<String>,

    /// The trace to evaluate (can be used multiple times).
    #[arg(short = 'u', long = "trace-uid", value_name = "TRACE_UID", action = ArgAction::Append)]
    trace_uids: Vec<String>,

    /// Disable deduplication for the results (more precise, but might result in more false
    /// positives).
    #[arg(short = 'D', long = "no-deduplication", action = ArgAction::SetFalse)]
    deduplicate: bool,
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
    /// The unique ID of the sample.
    uid: String,
    /// The amount of seconds passed since the beginning of the detection campaign.
    seconds: u64,
    /// The kind of the sample.
    kind: SampleKind,
    /// The unique ID of the discriminant.
    discriminant_uid: String,
}

/// The stats obtained from evaluating ROSA's findings.
struct Stats {
    /// The number of true positives.
    true_positives: u64,
    /// The number of false positives.
    false_positives: u64,
    /// The number of true negatives.
    true_negatives: u64,
    /// The number of false negatives.
    false_negatives: u64,
}

impl Stats {
    /// Create a new stats record.
    pub fn new() -> Self {
        Stats {
            true_positives: 0,
            false_positives: 0,
            true_negatives: 0,
            false_negatives: 0,
        }
    }

    /// Add a sample to the record.
    ///
    /// # Arguments
    /// * `sample` - The sample to add.
    pub fn add_sample(&mut self, sample: &Sample) {
        match sample.kind {
            SampleKind::TruePositive => {
                self.true_positives += 1;
            }
            SampleKind::FalsePositive => {
                self.false_positives += 1;
            }
            SampleKind::TrueNegative => {
                self.true_negatives += 1;
            }
            SampleKind::FalseNegative => {
                self.false_negatives += 1;
            }
        }
    }
}

/// Check a ROSA decision.
///
/// As explained in the module-level doc, the decision's test input will be fed to the
/// **ground-truth** program, and we'll check if the string `***BACKDOOR TRIGGERED***` appears in
/// `stderr`.
fn check_decision(
    cmd: &[String],
    env: &HashMap<String, String>,
    test_input_file: &Path,
    timed_decision: &TimedDecision,
    discriminant_uid: String,
    show_output: bool,
) -> Result<Sample, RosaError> {
    let test_input_file = File::open(test_input_file).map_err(|err| {
        error!(
            "failed to read test input from file {}: {}.",
            test_input_file.display(),
            err
        )
    })?;
    let output = Command::new(&cmd[0])
        .stdin(Stdio::from(test_input_file))
        .args(&cmd[1..])
        .envs(config::replace_env_var_placeholders(env))
        .output()
        .map_err(|err| error!("failed to run target program: {}", err))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let backdoor =
        stdout.contains("***BACKDOOR TRIGGERED***") || stderr.contains("***BACKDOOR TRIGGERED***");

    match show_output {
        true => {
            println_info!("stdout:");
            println!("{}", stdout);
            println_info!("stderr:");
            println!("{}", stderr);
        }
        false => (),
    }

    let kind = match (backdoor, timed_decision.decision.is_backdoor) {
        (true, true) => SampleKind::TruePositive,
        (true, false) => SampleKind::FalseNegative,
        (false, true) => SampleKind::FalsePositive,
        (false, false) => SampleKind::TrueNegative,
    };

    Ok(Sample {
        uid: timed_decision.decision.trace_uid.clone(),
        seconds: timed_decision.seconds,
        kind,
        discriminant_uid,
    })
}

/// Run the evaluation of ROSA's findings.
///
/// # Arguments
/// * `output_dir` - Path to the output directory where ROSA's findings are stored.
/// * `target_program_cmd` - The command to use to run the "ground-truth" program.
/// * `target_program_env` - The environment to pass to the "ground-truth" program.
/// * `trace_uids` - The unique IDs of the traces to evaluate (if empty, all traces are evaluated).
/// * `show_summary` - Show a summary of the results.
/// * `show_output` - Show the output (stderr & stdout) when executing the target program.
/// * `deduplicate` - Deduplicate findings based on the oracle criterion.
fn run(
    output_dir: &Path,
    target_program_cmd: Option<String>,
    target_program_env: Option<String>,
    trace_uids: &[String],
    show_summary: bool,
    show_output: bool,
    deduplicate: bool,
) -> Result<(), RosaError> {
    let config = Config::load(&output_dir.join("config").with_extension("toml"))?;

    println_info!("Loading traces...");
    let mut known_traces = HashMap::new();
    let all_traces = trace::load_traces(
        &output_dir.join("traces"),
        &output_dir.join("traces"),
        "rosa",
        &mut known_traces,
        true,
    )?;

    let selected_trace_uids: Vec<String> = match trace_uids.len() {
        0 => all_traces.iter().map(|trace| trace.uid()).collect(),
        _ => Vec::from(trace_uids),
    };

    let selected_cmd: Vec<String> = match target_program_cmd {
        Some(cmd) => cmd.split(' ').map(|arg| arg.to_string()).collect(),
        None => config.main_fuzzer()?.cmd.clone(),
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
        None => config.main_fuzzer()?.env.clone(),
    };

    println_info!("Evaluating {} traces...", selected_trace_uids.len());
    let timed_decisions: Vec<TimedDecision> = selected_trace_uids
        .iter()
        .map(|trace_uid| {
            TimedDecision::load(
                &output_dir
                    .join("decisions")
                    .join(trace_uid)
                    .with_extension("toml"),
            )
        })
        .collect::<Result<Vec<TimedDecision>, RosaError>>()?;

    // We can run the evaluations in parallel, since they're all independent.
    let mut samples: Vec<Sample> = timed_decisions
        .par_iter()
        .map(|timed_decision| {
            check_decision(
                &selected_cmd,
                &selected_env,
                &output_dir
                    .join("traces")
                    .join(&timed_decision.decision.trace_uid),
                timed_decision,
                timed_decision
                    .decision
                    .discriminants
                    .uid(config.oracle_criterion),
                show_output,
            )
        })
        .collect::<Result<Vec<Sample>, RosaError>>()?;

    // Sort by decision time.
    samples.sort_by(|sample1, sample2| sample1.seconds.partial_cmp(&sample2.seconds).unwrap());

    if deduplicate {
        // Remove backdoor duplicates based on the discriminant UID.
        let mut known_backdoors = HashSet::new();
        let samples: Vec<Sample> = samples
            .clone()
            .into_iter()
            .filter_map(|sample| match sample.kind {
                SampleKind::TruePositive | SampleKind::FalsePositive => known_backdoors
                    .insert(sample.clone().discriminant_uid)
                    .then_some(sample),
                _ => Some(sample),
            })
            .collect();
        println_info!("  ({} traces remaining after deduplication)", samples.len());
    }

    let stats = samples.iter().try_fold(Stats::new(), |mut stats, sample| {
        stats.add_sample(sample);

        Ok(stats)
    })?;

    let seconds_to_first_backdoor = samples
        .iter()
        .find(|sample| sample.kind == SampleKind::TruePositive)
        .map_or("N/A".to_string(), |sample| {
            timed_decisions
                .iter()
                .find(|timed_decision| timed_decision.decision.trace_uid == sample.uid)
                .map(|timed_decision| timed_decision.seconds.to_string())
                .expect("failed to get seconds for first backdoor.")
        });

    let header = match show_summary {
        true => {
            "true_positives,false_positives,true_negatives,false_negatives,\
                seconds_to_first_backdoor"
        }
        false => "trace_uid,result,seconds",
    };

    let body = match show_summary {
        true => format!(
            "{},{},{},{},{}",
            stats.true_positives,
            stats.false_positives,
            stats.true_negatives,
            stats.false_negatives,
            seconds_to_first_backdoor
        ),
        false => samples
            .iter()
            .map(|sample| format!("{},{},{}", sample.uid, sample.kind, sample.seconds))
            .collect::<Vec<String>>()
            .join("\n"),
    };

    println!("{}\n{}", header, body);

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(
        &cli.output_dir,
        cli.target_program_cmd,
        cli.target_program_env,
        &cli.trace_uids,
        cli.show_summary,
        cli.show_output,
        cli.deduplicate,
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
