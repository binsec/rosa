use std::{
    collections::HashMap,
    fs::File,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use clap::{ArgAction, Parser};
use colored::Colorize;

use rosa::error;
use rosa::{config::Config, decision::Decision, error::RosaError, trace};

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

    /// The target program to run traces through (if empty, `fuzzer_run_cmd` from ROSA's
    /// configuration is used).
    #[arg(
        short = 'p',
        long = "target-program",
        value_name = "\"CMD ARG1 ARG2 ...\""
    )]
    target_program_cmd: Option<String>,

    /// The environment to use for the target program (if empty, `fuzzer_run_env` from ROSA's
    /// configuration is used).
    #[arg(
        short = 'e',
        long = "environment",
        value_name = "\"KEY1=VALUE1 KEY2=VALUE2 ...\""
    )]
    target_program_env: Option<String>,

    /// The trace to evaluate (can be used multiple times).
    #[arg(short = 't', long = "trace-uid", value_name = "TRACE_UID", action = ArgAction::Append)]
    trace_uids: Vec<String>,
}

enum Sample {
    TruePositive,
    FalsePositive,
    TrueNegative,
    FalseNegative,
}

struct Stats {
    true_positives: u64,
    false_positives: u64,
    true_negatives: u64,
    false_negatives: u64,
}

impl Stats {
    pub fn new() -> Self {
        Stats {
            true_positives: 0,
            false_positives: 0,
            true_negatives: 0,
            false_negatives: 0,
        }
    }

    pub fn add_sample(&mut self, sample: Sample) {
        match sample {
            Sample::TruePositive => {
                self.true_positives += 1;
            }
            Sample::FalsePositive => {
                self.false_positives += 1;
            }
            Sample::TrueNegative => {
                self.true_negatives += 1;
            }
            Sample::FalseNegative => {
                self.false_negatives += 1;
            }
        }
    }

    pub fn total_samples(&self) -> u64 {
        self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
    }

    pub fn precision(&self) -> Option<f64> {
        match self.true_positives + self.false_positives {
            0 => None,
            sum => Some((self.true_positives as f64) / (sum as f64)),
        }
    }

    pub fn recall(&self) -> Option<f64> {
        match self.true_positives + self.false_negatives {
            0 => None,
            sum => Some((self.true_positives as f64) / (sum as f64)),
        }
    }
}

fn check_decision(
    cmd: &[String],
    env: &HashMap<String, String>,
    test_input_file: &Path,
    decision: &Decision,
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
        .envs(env)
        .output()
        .map_err(|err| error!("failed to run target program: {}", err))?;

    let backdoor = String::from_utf8(output.stderr)
        .map_or(false, |stderr| stderr.contains("***BACKDOOR TRIGGERED***"));

    Ok(match (backdoor, decision.is_backdoor) {
        (true, true) => Sample::TruePositive,
        (true, false) => Sample::FalseNegative,
        (false, true) => Sample::FalsePositive,
        (false, false) => Sample::TrueNegative,
    })
}

fn run(
    output_dir: &Path,
    target_program_cmd: Option<String>,
    target_program_env: Option<String>,
    trace_uids: &[String],
) -> Result<(), RosaError> {
    let config = Config::load(&output_dir.join("config").with_extension("json"))?;

    let mut known_traces = HashMap::new();
    let all_traces = trace::load_traces(
        &output_dir.join("traces"),
        &output_dir.join("traces"),
        &mut known_traces,
        true,
    )?;

    let selected_trace_uids: Vec<String> = match trace_uids.len() {
        0 => all_traces.iter().map(|trace| trace.uid.clone()).collect(),
        _ => Vec::from(trace_uids),
    };

    let selected_cmd: Vec<String> = match target_program_cmd {
        Some(cmd) => cmd.split(' ').map(|arg| arg.to_string()).collect(),
        None => config.fuzzer_run_cmd.clone(),
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
        None => config.fuzzer_run_env.clone(),
    };

    println_info!("Evaluating {} traces...", selected_trace_uids.len());
    let decisions: Vec<Decision> = selected_trace_uids
        .iter()
        .map(|trace_uid| {
            Decision::load(
                &output_dir
                    .join("decisions")
                    .join(trace_uid)
                    .with_extension("json"),
            )
        })
        .collect::<Result<Vec<Decision>, RosaError>>()?;

    let stats = decisions
        .iter()
        .try_fold(Stats::new(), |mut stats, decision| {
            stats.add_sample(check_decision(
                &selected_cmd,
                &selected_env,
                &output_dir.join("traces").join(&decision.trace_uid),
                decision,
            )?);

            Ok(stats)
        })?;

    println_info!("{} traces evaluated:", stats.total_samples());
    println_info!(
        "  True positives: {} ({:.2}%)",
        stats.true_positives,
        (stats.true_positives as f64) / (stats.total_samples() as f64) * 100.0
    );
    println_info!(
        "  False positives: {} ({:.2}%)",
        stats.false_positives,
        (stats.false_positives as f64) / (stats.total_samples() as f64) * 100.0
    );
    println_info!(
        "  True negatives: {} ({:.2}%)",
        stats.true_negatives,
        (stats.true_negatives as f64) / (stats.total_samples() as f64) * 100.0
    );
    println_info!(
        "  False negatives: {} ({:.2}%)",
        stats.false_negatives,
        (stats.false_negatives as f64) / (stats.total_samples() as f64) * 100.0
    );

    println_info!(
        "  Precision: {}",
        match stats.precision() {
            Some(precision) => format!("{:.2}%", precision * 100.0),
            None => "N/A".to_string(),
        }
    );
    println_info!(
        "  Recall: {}",
        match stats.recall() {
            Some(recall) => format!("{:.2}%", recall * 100.0),
            None => "N/A".to_string(),
        }
    );

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(
        &cli.output_dir,
        cli.target_program_cmd,
        cli.target_program_env,
        &cli.trace_uids,
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
