//! ROSA configuration definition & utilities.
//!
//! This module handles ROSA's configuration file (mostly its parsing), as well as IO-related
//! functionality needed by the configuration.

use std::{
    collections::HashMap,
    env, fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    str::{self, FromStr},
};

use serde::{Deserialize, Serialize};

use crate::{
    criterion::Criterion,
    distance_metric::{hamming::Hamming, DistanceMetric},
    error::RosaError,
    fuzzer::FuzzerConfig,
    oracle::{comp_min_max::CompMinMax, Oracle},
};

/// The conditions that describe when to stop collecting seed traces.
#[derive(Serialize, Deserialize, Debug)]
pub struct SeedConditions {
    /// Stop after a given amount of seconds.
    #[serde(default = "SeedConditions::default_seconds")]
    pub seconds: Option<u64>,
    /// Stop once a given edge coverage has been reached (percentage between 0.0 and 1.0).
    #[serde(default = "SeedConditions::default_edge_coverage")]
    pub edge_coverage: Option<f64>,
    /// Stop once a given syscall coverage has been reached (percentage between 0.0 and 1.0).
    #[serde(default = "SeedConditions::default_syscall_coverage")]
    pub syscall_coverage: Option<f64>,
}

impl SeedConditions {
    const fn default_seconds() -> Option<u64> {
        None
    }

    const fn default_edge_coverage() -> Option<f64> {
        None
    }

    const fn default_syscall_coverage() -> Option<f64> {
        None
    }

    /// Check if a set of seed conditions is valid.
    ///
    /// # Examples
    /// ```
    /// use rosa::config::SeedConditions;
    ///
    /// let conditions = SeedConditions {
    ///     seconds: None,
    ///     edge_coverage: None,
    ///     syscall_coverage: None,
    /// };
    /// assert_eq!(conditions.valid(), false);
    ///
    /// let conditions = SeedConditions {
    ///     seconds: None,
    ///     edge_coverage: Some(100.00),
    ///     syscall_coverage: None,
    /// };
    /// assert_eq!(conditions.valid(), true);
    ///
    /// let conditions = SeedConditions {
    ///     seconds: Some(300),
    ///     edge_coverage: Some(32.34),
    ///     syscall_coverage: Some(1.2),
    /// };
    /// assert_eq!(conditions.valid(), true);
    /// ```
    pub fn valid(&self) -> bool {
        self.seconds.is_some() || self.edge_coverage.is_some() || self.syscall_coverage.is_some()
    }

    /// Check if the seed conditions have been met.
    ///
    /// # Parameters
    /// * `seconds` - The current seconds.
    /// * `edge_coverage` - The current edge coverage.
    /// * `syscall_coverage` - The current syscall coverage.
    ///
    /// # Examples
    /// ```
    /// use rosa::config::SeedConditions;
    ///
    /// let conditions = SeedConditions {
    ///     seconds: Some(32),
    ///     edge_coverage: None,
    ///     syscall_coverage: None,
    /// };
    /// assert_eq!(conditions.check(10, 0.9999, 0.9999), false);
    /// assert_eq!(conditions.check(32, 0.0, 0.0), true);
    /// ```
    pub fn check(&self, seconds: u64, edge_coverage: f64, syscall_coverage: f64) -> bool {
        let seconds_check = self
            .seconds
            .map(|seconds_limit| seconds >= seconds_limit)
            .unwrap_or(false);
        let edge_coverage_check = self
            .edge_coverage
            .map(|edge_coverage_limit| edge_coverage >= edge_coverage_limit)
            .unwrap_or(false);
        let syscall_coverage_check = self
            .syscall_coverage
            .map(|syscall_coverage_limit| syscall_coverage >= syscall_coverage_limit)
            .unwrap_or(false);

        seconds_check || edge_coverage_check || syscall_coverage_check
    }
}

/// The possible phases of ROSA.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RosaPhase {
    /// Starting up.
    Starting,
    /// Collection of family-representative inputs.
    CollectingInputs,
    /// Clustering of family-represenative inputs (into families).
    ClusteringInputs,
    /// Backdoor detection.
    DetectingBackdoors,
    /// Stopped.
    Stopped,
}

impl fmt::Display for RosaPhase {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Starting => "starting",
                Self::CollectingInputs => "collecting-inputs",
                Self::ClusteringInputs => "clustering-inputs",
                Self::DetectingBackdoors => "detecting-backdoors",
                Self::Stopped => "stopped",
            }
        )
    }
}

impl str::FromStr for RosaPhase {
    type Err = RosaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "starting" => Ok(Self::Starting),
            "collecting-inputs" => Ok(Self::CollectingInputs),
            "clustering-inputs" => Ok(Self::ClusteringInputs),
            "detecting-backdoors" => Ok(Self::DetectingBackdoors),
            "stopped" => Ok(Self::Stopped),
            unknown => fail!("invalid phase '{}'.", unknown),
        }
    }
}

/// A configuration for ROSA.
///
/// This configuration will be loaded from a configuration file (one per target program).
#[derive(Serialize, Deserialize)]
pub struct Config {
    /// The directory in which ROSA's output will be stored.
    pub output_dir: PathBuf,

    /// The collection of fuzzers to run during both the seed & detection phases.
    pub fuzzers: Vec<FuzzerConfig>,

    /// The conditions that describe when to stop collecting seed traces.
    /// If multiple, the seed collection will stop once the first is met; at least one condition
    /// must be supplied.
    pub seed_conditions: SeedConditions,

    /// The criterion to use during cluster formation.
    /// See [cluster_traces](crate::clustering::cluster_traces).
    #[serde(default = "Config::default_cluster_formation_criterion")]
    pub cluster_formation_criterion: Criterion,
    /// The distance metric to use during cluster formation.
    /// See [cluster_traces](crate::clustering::cluster_traces).
    #[serde(default = "Config::default_cluster_formation_distance_metric")]
    pub cluster_formation_distance_metric: Box<dyn DistanceMetric>,
    /// The edge tolerance to use during cluster formation.
    /// See [cluster_traces](crate::clustering::cluster_traces).
    #[serde(default = "Config::default_cluster_formation_edge_tolerance")]
    pub cluster_formation_edge_tolerance: u64,
    /// The syscall tolerance to use during cluster formation.
    /// See [cluster_traces](crate::clustering::cluster_traces).
    #[serde(default = "Config::default_cluster_formation_syscall_tolerance")]
    pub cluster_formation_syscall_tolerance: u64,
    /// The criterion to use during cluster selection.
    /// See [get_most_similar_cluster](crate::clustering::get_most_similar_cluster).
    #[serde(default = "Config::default_cluster_selection_criterion")]
    pub cluster_selection_criterion: Criterion,
    /// The distance metric to use during cluster selection.
    /// See [get_most_similar_cluster](crate::clustering::get_most_similar_cluster).
    #[serde(default = "Config::default_cluster_selection_distance_metric")]
    pub cluster_selection_distance_metric: Box<dyn DistanceMetric>,
    /// The oracle to use.
    #[serde(default = "Config::default_oracle")]
    pub oracle: Box<dyn Oracle>,
    /// The criterion to use in the oracle algorithm.
    #[serde(default = "Config::default_oracle_criterion")]
    pub oracle_criterion: Criterion,
    /// The distance metric to use in the oracle algorithm.
    #[serde(default = "Config::default_oracle_distance_metric")]
    pub oracle_distance_metric: Box<dyn DistanceMetric>,
}

impl Config {
    /// The default cluster formation criterion.
    pub fn default_cluster_formation_criterion() -> Criterion {
        // By default, we separate clusters by CFG edges only. This is because of how we define
        // input families in the original paper. Additionally, this criterion implicitly takes
        // system calls into account, as passing by the same CFG edges implies producing the same
        // types of system calls.
        Criterion::EdgesOnly
    }
    /// The default cluster formation distance metric.
    pub fn default_cluster_formation_distance_metric() -> Box<dyn DistanceMetric> {
        Box::new(Hamming)
    }
    /// The default cluster formation edge tolerance.
    pub fn default_cluster_formation_edge_tolerance() -> u64 {
        0
    }
    /// The default cluster formation syscall tolerance.
    pub fn default_cluster_formation_syscall_tolerance() -> u64 {
        0
    }
    /// The default cluster selection criterion.
    pub fn default_cluster_selection_criterion() -> Criterion {
        // By default, we select clusters by CFG edges and system calls. This is because of how we
        // define input families in the original paper. The system calls are used here as a tie
        // breaker, in case the CFG edge vectors are identical.
        Criterion::EdgesAndSyscalls
    }
    /// The default cluster selection distance metric.
    pub fn default_cluster_selection_distance_metric() -> Box<dyn DistanceMetric> {
        Box::new(Hamming)
    }
    /// The default oracle algorithm.
    pub fn default_oracle() -> Box<dyn Oracle> {
        Box::new(CompMinMax)
    }
    /// The default criterion to use in the oracle algorithm.
    pub fn default_oracle_criterion() -> Criterion {
        // By default, we only use system calls in the oracle. This is because of how the
        // metamorphic oracle is defined in the original paper. Backdoors are expected to exhibit
        // differences in denotational semantics, which here are modeled via system call types.
        Criterion::SyscallsOnly
    }
    /// The default distance metric to use in the oracle algorithm.
    pub fn default_oracle_distance_metric() -> Box<dyn DistanceMetric> {
        Box::new(Hamming)
    }

    /// The README to put in the root of ROSA's output directory.
    const OUTPUT_DIR_README: [&'static str; 13] = [
        "This is an output directory created by ROSA, the backdoor detection tool.",
        "It contains the following subdirectories:",
        "",
        "- backdoors: contains all detected backdoor-triggering inputs",
        "- clusters: contains the different clusters that were formed prior to detection",
        "- decisions: contains the decisions of the oracle, as well as the parameters used by it",
        "- logs: contains the logs generated by the fuzzer",
        "- traces: contains all the test inputs and trace dumps corresponding to the traces",
        "  that have been evaluated so far",
        "",
        "It also contains the `config.toml` file, which describes the configuration parameters",
        "used in order to produce these results.",
        "",
    ];
    /// The README to put in the `backdoors` directory in the output directory.
    const BACKDOORS_DIR_README: [&'static str; 14] = [
        "This directory contains inputs that trigger a backdoor in the target program. In order",
        "to reproduce the backdoor(s), you'll need to run the program under the same conditions",
        "as those used by the fuzzer that discovered it. You can find the parameters used by the",
        "fuzzer in the following files:",
        "",
        "    ../config.toml",
        "    ../decisions/<BACKDOOR_INPUT>.toml",
        "",
        "The suspicious inputs are found in the subdirectories present in this directory. They",
        "are in fact grouped by *discriminants*, meaning the characteristics that discriminate",
        "them and make them suspicious. This facilitates manual analysis, as we would only need",
        "to analyze one input of every class (i.e., subdirectory) to realize if the entire class",
        "contains backdoor-triggering inputs or not.",
        "",
    ];
    /// The README to put in the `clusters` directory in the output directory.
    const CLUSTERS_DIR_README: [&'static str; 7] = [
        "This directory contains the clusters created by ROSA. Each cluster file is named after",
        "the ID of the cluster, and contains the IDs of the traces that form the cluster.",
        "The test inputs and actual trace dumps (edge/syscall vectors) of those traces can be",
        "found in:",
        "",
        "    ../traces/",
        "",
    ];
    /// The README to put in the `decisions` directory in the output directory.
    const DECISIONS_DIR_README: [&'static str; 3] = [
        "This directory contains the decisions made by the oracle for every trace it has analyzed",
        "so far. See the documentation for details on the format of the decision files.",
        "",
    ];
    /// The README to put in the `logs` directory in the output directory.
    const LOGS_DIR_README: [&'static str; 6] = [
        "This directory contains the logs created by the fuzzer processes (both stdout and",
        "stderr).",
        "",
        "The file `fuzzer_seed.log` corresponds to the seed collection run of the fuzzer,",
        "while the file `fuzzer_detection.log` corresponds to the detection run of the fuzzer.",
        "",
    ];
    /// The README to put in the `traces` directory in the output directory.
    const TRACES_DIR_README: [&'static str; 10] = [
        "This directory contains the test inputs and trace dumps associated with each trace that",
        "has been evaluated so far.",
        "Test inputs can be found in the files named:",
        "",
        "    <TRACE ID>",
        "",
        "Trace dumps can be found in the files named:",
        "",
        "    <TRACE ID>.trace",
        "",
    ];

    /// Save a configuration to a file.
    pub fn save(&self, file: &Path) -> Result<(), RosaError> {
        let config_toml = toml::to_string_pretty(&self).expect("failed to serialize config TOML.");

        fs::write(file, config_toml)
            .map_err(|err| error!("could not save config to file {}: {}.", file.display(), err))
    }

    /// Load a configuration from file.
    pub fn load(file: &Path) -> Result<Self, RosaError> {
        let config_toml = fs::read_to_string(file).map_err(|err| {
            error!(
                "failed to read configuration from {}: {}.",
                file.display(),
                err
            )
        })?;

        let config: Self = toml::from_str(&config_toml)
            .map_err(|err| error!("failed to deserialize config TOML: {}.", err))?;

        config
            .seed_conditions
            .valid()
            .then_some(config)
            .ok_or(error!(
                "at least one seed condition must be specified to know when to stop collecting \
                    seeds."
            ))
    }

    /// Set up ROSA's output directories.
    ///
    /// This function sets up the output directories for ROSA, which will contain any findings
    /// produced during the backdoor detection campaign.
    pub fn setup_dirs(&self, force: bool) -> Result<(), RosaError> {
        if self.output_dir.is_dir() {
            if !force {
                fail!(
                    "output directory '{}' already exists, so it would be overwritten. If that's \
                    intentional, use the `-f/--force` option.",
                    &self.output_dir.display()
                )?;
            }

            fs::remove_dir_all(&self.output_dir).map_err(|err| {
                error!(
                    "could not remove '{}': {}.",
                    &self.output_dir.display(),
                    err
                )
            })?;
        }

        // Create all directories from scratch.
        for (dir, readme) in [
            (&self.output_dir, Self::OUTPUT_DIR_README.join("\n")),
            (&self.backdoors_dir(), Self::BACKDOORS_DIR_README.join("\n")),
            (&self.clusters_dir(), Self::CLUSTERS_DIR_README.join("\n")),
            (&self.decisions_dir(), Self::DECISIONS_DIR_README.join("\n")),
            (&self.logs_dir(), Self::LOGS_DIR_README.join("\n")),
            (&self.traces_dir(), Self::TRACES_DIR_README.join("\n")),
        ] {
            fs::create_dir(dir)
                .map_err(|err| error!("could not create '{}': {}", &dir.display(), err))?;
            fs::write(dir.join("README").with_extension("txt"), readme).map_err(|err| {
                error!("could not create README for '{}': {}", &dir.display(), err)
            })?;
        }

        Ok(())
    }

    /// Get the current phase of ROSA's detection.
    pub fn get_current_phase(&self) -> Result<RosaPhase, RosaError> {
        let phase = fs::read_to_string(self.current_phase_file()).map_err(|err| {
            error!(
                "failed to get current phase from {}: {}.",
                self.current_phase_file().display(),
                err
            )
        })?;

        RosaPhase::from_str(&phase)
    }

    /// Set the current phase of ROSA's detection.
    pub fn set_current_phase(&self, phase: RosaPhase) -> Result<(), RosaError> {
        fs::write(self.current_phase_file(), phase.to_string()).map_err(|err| {
            error!(
                "failed to set current phase in {}: {}.",
                self.current_phase_file().display(),
                err
            )
        })
    }

    /// Get the current coverage.
    pub fn get_current_coverage(&self) -> Result<(f64, f64), RosaError> {
        let coverage_string = fs::read_to_string(self.current_coverage_file()).map_err(|err| {
            error!(
                "failed to get current coverage from {}: {}.",
                self.current_coverage_file().display(),
                err
            )
        })?;
        let coverage_parts: Vec<&str> = coverage_string.split('/').collect();

        let edge_coverage_str = coverage_parts.first().ok_or(error!(
            "missing edge coverage in {}.",
            self.current_coverage_file().display()
        ))?;
        let syscall_coverage_str = coverage_parts.last().ok_or(error!(
            "missing syscall coverage in {}.",
            self.current_coverage_file().display()
        ))?;

        let edge_coverage = edge_coverage_str
            .parse::<f64>()
            .map_err(|err| error!("failed to parse edge coverage: {err}."))?;
        let syscall_coverage = syscall_coverage_str
            .parse::<f64>()
            .map_err(|err| error!("failed to parse syscall coverage: {err}."))?;

        Ok((edge_coverage, syscall_coverage))
    }

    /// Set the current coverage.
    pub fn set_current_coverage(
        &self,
        edge_coverage: f64,
        syscall_coverage: f64,
    ) -> Result<(), RosaError> {
        fs::write(
            self.current_coverage_file(),
            format!("{}/{}", edge_coverage, syscall_coverage),
        )
        .map_err(|err| {
            error!(
                "failed to set current coverage in {}: {}.",
                self.current_coverage_file().display(),
                err
            )
        })
    }

    /// Initialize the stats file.
    ///
    /// This file tracks various statistics about the detection campaign and can be used to plot
    /// its progress.
    pub fn init_stats_file(&self) -> Result<(), RosaError> {
        fs::write(
            self.current_stats_file(),
            "seconds,traces,unique_backdoors,total_backdoors,edge_coverage,syscall_coverage\n",
        )
        .map_err(|err| {
            error!(
                "failed to initialize stats file '{}': {}.",
                self.current_stats_file().display(),
                err
            )
        })
    }

    /// Log a new line in the stats file.
    pub fn log_stats(
        &self,
        seconds: u64,
        traces: u64,
        unique_backdoors: u64,
        total_backdoors: u64,
        edge_coverage: f64,
        syscall_coverage: f64,
    ) -> Result<(), RosaError> {
        let mut stats_file = OpenOptions::new()
            .append(true)
            .open(self.current_stats_file())
            .map_err(|err| {
                error!(
                    "failed to open stats file '{}': {}.",
                    self.current_stats_file().display(),
                    err
                )
            })?;

        writeln!(
            stats_file,
            "{},{},{},{},{},{}",
            seconds, traces, unique_backdoors, total_backdoors, edge_coverage, syscall_coverage
        )
        .map_err(|err| {
            error!(
                "failed to log stats in {}: {}.",
                self.current_stats_file().display(),
                err
            )
        })
    }

    /// Get the path to the current stats file.
    fn current_stats_file(&self) -> PathBuf {
        self.output_dir.join("stats.csv")
    }

    /// Get the path to the current coverage file.
    fn current_coverage_file(&self) -> PathBuf {
        self.output_dir.join(".current_coverage")
    }

    /// Get the path to the current phase file.
    fn current_phase_file(&self) -> PathBuf {
        self.output_dir.join(".current_phase")
    }

    /// Get the path to the `backdoors` output directory.
    pub fn backdoors_dir(&self) -> PathBuf {
        self.output_dir.join("backdoors")
    }

    /// Get the path to the `clusters` output directory.
    pub fn clusters_dir(&self) -> PathBuf {
        self.output_dir.join("clusters")
    }

    /// Get the path to the `decisions` output directory.
    pub fn decisions_dir(&self) -> PathBuf {
        self.output_dir.join("decisions")
    }

    /// Get the path to the `logs` output directory.
    pub fn logs_dir(&self) -> PathBuf {
        self.output_dir.join("logs")
    }

    /// Get the path to the `traces` output directory.
    pub fn traces_dir(&self) -> PathBuf {
        self.output_dir.join("traces")
    }

    /// Get the main fuzzer.
    pub fn main_fuzzer(&self) -> Result<&FuzzerConfig, RosaError> {
        self.fuzzers
            .iter()
            .find(|fuzzer_config| fuzzer_config.backend.name() == "main")
            .ok_or(error!("No 'main' fuzzer found in the configuration."))
    }
}

/// Replace environment variable representations in strings with their actual values.
pub fn replace_env_var_placeholders(env: &HashMap<String, String>) -> HashMap<String, String> {
    env.iter()
        .map(|(key, value)| {
            // TODO maybe we should actually scan through every occurrence and replace them all,
            // instead of the usual suspects...
            (
                key.clone(),
                value
                    .replace(
                        "$LD_PRELOAD",
                        &env::var("LD_PRELOAD").unwrap_or("".to_string()),
                    )
                    .replace("$PWD", &env::var("PWD").unwrap_or("".to_string()))
                    .replace("$HOME", &env::var("HOME").unwrap_or("".to_string())),
            )
        })
        .collect()
}
