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

use clap::{ArgAction, Parser, ValueEnum};
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

/// Describe the kinds of deduplication of results.
#[derive(Debug, Copy, Clone, ValueEnum)]
enum DeduplicationKind {
    /// Don't perform any deduplication.
    None,
    /// Perform native deduplication, based on the actual results of the evaluation.
    ///
    /// For this, the heuristics of the backdoor detector are used: we only deduplicate
    /// (true/false) _positive_ results.
    Native,
    /// Perform full post-process deduplication for all phase-2 inputs.
    ///
    /// Deduplication is applied to all of the results corresponding to phase-2 inputs (i.e.,
    /// ignoring de facto (true/false) _negatives_ from phase 1.
    PostProcess,
}

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

    /// The target program to run traces through (if empty, use the command from the main fuzzer
    /// in the configuration).
    #[arg(
        short = 'p',
        long = "target-program",
        value_name = "\"CMD ARG1 ARG2 ...\""
    )]
    target_program_cmd: Option<String>,

    /// The environment to use for the target program (if empty, use the environment from the main
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

    /// The kind of deduplication to use.
    #[arg(
        value_enum,
        short = 'd',
        long = "deduplication",
        default_value_t = DeduplicationKind::Native,
        value_name = "DEDUPLICATION_KIND"
    )]
    deduplication_kind: DeduplicationKind,

    /// The time limit to cut off at (if any).
    #[arg(short = 't', long = "time-limit", value_name = "SECONDS")]
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
/// * `deduplication_kind` - The kind of deduplication to use.
/// * `time_limit` - The time limit (if any) to cut off at.
#[allow(clippy::too_many_arguments)]
fn run(
    output_dir: &Path,
    target_program_cmd: Option<String>,
    target_program_env: Option<String>,
    trace_uids: &[String],
    show_summary: bool,
    show_output: bool,
    deduplication_kind: DeduplicationKind,
    time_limit: Option<u64>,
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
                    .join(&timed_decision.decision.trace_uid),
                timed_decision,
                timed_decision.decision.discriminants.uid(
                    config.oracle_criterion,
                    &timed_decision.decision.cluster_uid,
                ),
                show_output,
            )
        })
        .collect::<Result<Vec<Sample>, RosaError>>()?;

    // Sort by decision time.
    samples.sort_by(|sample1, sample2| sample1.seconds.partial_cmp(&sample2.seconds).unwrap());

    let samples = match deduplication_kind {
        DeduplicationKind::None => samples,
        DeduplicationKind::Native => {
            let mut known_traces = HashSet::new();
            let samples: Vec<Sample> = samples
                .clone()
                .into_iter()
                .filter_map(|sample| match sample.kind {
                    // Only deduplicate (true/false) _positives_, as that is what ROSA does to
                    // deduplicate while running.
                    SampleKind::TruePositive | SampleKind::FalsePositive => known_traces
                        .insert(sample.clone().discriminant_uid)
                        .then_some(sample),
                    // All other kinds of inputs are left in the same state.
                    _ => Some(sample),
                })
                .collect();
            println_info!("  ({} traces remaining after deduplication)", samples.len());

            samples
        }
        DeduplicationKind::PostProcess => {
            // Remove duplicate traces based on the discriminant UID.
            // For the traces which arrived in phase 2 (when the oracle is active), we can simply
            // deduplicate all of them based on a single hash set. It does not make sense to count
            // two traces with the same discriminant UID as two unique entities, as the
            // discriminant UID should ensure that the behavior and related input family are
            // unique.
            //
            // This can have the following effects (as far as I know):
            // * TP removed because of existing TP - neutral effect (we can't miss a backdoor this
            //   way).
            // * TP removed because of existing FP - unfortunate, as we lose a TP, but also
            //   probably a sign that the TP was not different enough. Maybe there is backdoor
            //   contamination at play, or the backdoor is very well hidden, mimicking similar
            //   benign behaviors. We might miss a backdoor this way.
            // * FP removed because of existing TP - this, again, is probably the result of
            //   backdoor contamination or a well hidden backdoor, but in this case it works in our
            //   favor. Positive effect.
            // * FP removed because of existing FP - positive effect (less FPs overall).
            // * TN removed because of TN - neutral effect (we don't care about TNs).
            // * TN removed because of FN - we have probably discovered an "inoffensive trigger"
            //   (in terms of behavior) before its TN equivalent. This can mean that backdoor
            //   contamination happened, or that the ground-truth marker can be triggered without
            //   divergent behavior (can be the case for some targets). So, negative or neutral
            //   effect.
            // * FN removed because of TN - positive effect (it's the ground-truth marker scenario
            //   from the previous case).
            // * FN removed because of FN - positive effect (less FNs overall).
            let mut known_traces = HashSet::new();
            let samples: Vec<Sample> = samples
                .clone()
                .into_iter()
                .filter_map(|sample| {
                    match sample.seconds
                        > config.seed_conditions.seconds.expect(
                            "failed to get seconds (duration) of phase 1, needed for \
                                    deduplication.",
                        ) {
                        true => known_traces
                            .insert(sample.clone().discriminant_uid)
                            .then_some(sample),
                        // Phase 1 samples move right along, no deduplication (because the oracle
                        // wasn't active in phase 1).
                        false => Some(sample),
                    }
                })
                .collect();
            println_info!("  ({} traces remaining after deduplication)", samples.len());

            samples
        }
    };

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
        cli.deduplication_kind,
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
