//! ROSA configuration definition & utilities.
//!
//! This module handles ROSA's configuration file (mostly its parsing), as well as IO-related
//! functionality needed by the configuration.

use std::{
    collections::HashMap,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    str::{self, FromStr},
};

use serde::{Deserialize, Serialize};

use crate::{
    criterion::Criterion, distance_metric::DistanceMetric, error::RosaError, oracle::Oracle,
};

/// A fuzzer configuration.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FuzzerConfig {
    /// The name of the fuzzer instance. This is useful when performing parallel fuzzing; for
    /// example, in AFL++, the main instance will be named with the `-M` option (e.g. `-M main`),
    /// while the secondary instances will be named with the `-S` option (e.g. `-S secondary`).
    /// These are the names that should be used here, to namespace the fuzzers and the traces that
    /// they generate.
    pub name: String,
    /// Any environment variables that need to be passed to the fuzzer.
    pub env: HashMap<String, String>,
    /// The full command to invoke the fuzzer.
    pub cmd: Vec<String>,
    /// The directory where the fuzzer will place new test inputs.
    pub test_input_dir: PathBuf,
    /// The directory where the fuzzer will place new trace dumps.
    pub trace_dump_dir: PathBuf,
    /// The directory where the fuzzer will place found crashes. This is only useful because
    /// crashes will hinder backdoor detection, so we'll want to keep an eye on any findings.
    pub crashes_dir: PathBuf,
}

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
    /// Collection of seed traces.
    CollectingSeeds,
    /// Clustering of seed traces.
    ClusteringSeeds,
    /// Backdoor detection.
    DetectingBackdoors,
    /// Finding deduplication.
    DeduplicatingFindings,
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
                Self::CollectingSeeds => "collecting-seeds",
                Self::ClusteringSeeds => "clustering-seeds",
                Self::DetectingBackdoors => "detecting-backdoors",
                Self::DeduplicatingFindings => "deduplicating-findings",
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
            "collecting-seeds" => Ok(Self::CollectingSeeds),
            "clustering-seeds" => Ok(Self::ClusteringSeeds),
            "detecting-backdoors" => Ok(Self::DetectingBackdoors),
            "stopped" => Ok(Self::Stopped),
            unknown => fail!("invalid phase '{}'.", unknown),
        }
    }
}

/// A configuration for a deduplicator.
///
/// A deduplicator can be an external program that deduplicates traces based on some criteria.
/// This is sometimes useful to apply to counteract the non-deterministic nature of the fuzzer.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeduplicatorConfig {
    /// The deduplicator command.
    ///
    /// The command should contain `"{{INPUT}}"` and `"{{OUTPUT}}"` strings where the input and
    /// output directories of the deduplicator go.
    pub cmd: Vec<String>,
    /// The deduplicator environment variables (if any).
    pub env: HashMap<String, String>,
}

/// A configuration for ROSA.
///
/// This configuration will be loaded from a configuration file (one per target program).
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    /// The directory in which ROSA's output will be stored.
    pub output_dir: PathBuf,

    /// The collection of fuzzers to run during both the seed & detection phases.
    pub fuzzers: Vec<FuzzerConfig>,

    /// The conditions that describe when to stop collecting seed traces.
    /// If multiple, the seed collection will stop once the first is met; at least one condition
    /// must be supplied.
    pub seed_conditions: SeedConditions,

    /// The deduplicator (if any).
    /// This can be helpful to deduplicate traces in the cases where non-determinism creeps into
    /// the results.
    /// The deduplicator is post-processing, meaning it is applied at the very end of a detection
    /// campaign.
    pub deduplicator: Option<DeduplicatorConfig>,

    /// The criterion to use during cluster formation.
    /// See [cluster_traces](crate::clustering::cluster_traces).
    #[serde(default = "Config::default_cluster_formation_criterion")]
    pub cluster_formation_criterion: Criterion,
    /// The distance metric to use during cluster formation.
    /// See [cluster_traces](crate::clustering::cluster_traces).
    #[serde(default = "Config::default_cluster_formation_distance_metric")]
    pub cluster_formation_distance_metric: DistanceMetric,
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
    pub cluster_selection_distance_metric: DistanceMetric,
    /// The oracle to use.
    #[serde(default = "Config::default_oracle")]
    pub oracle: Oracle,
    /// The criterion to use in the oracle algorithm.
    #[serde(default = "Config::default_oracle_criterion")]
    pub oracle_criterion: Criterion,
    /// The distance metric to use in the oracle algorithm.
    #[serde(default = "Config::default_oracle_distance_metric")]
    pub oracle_distance_metric: DistanceMetric,
}

impl Config {
    /// The default cluster formation criterion.
    const fn default_cluster_formation_criterion() -> Criterion {
        // See https://git.frama-c.com/kokkonis/rosa/-/issues/2.
        Criterion::EdgesOnly
    }
    /// The default cluster formation distance metric.
    const fn default_cluster_formation_distance_metric() -> DistanceMetric {
        DistanceMetric::Hamming
    }
    /// The default cluster formation edge tolerance.
    const fn default_cluster_formation_edge_tolerance() -> u64 {
        0
    }
    /// The default cluster formation syscall tolerance.
    const fn default_cluster_formation_syscall_tolerance() -> u64 {
        0
    }
    /// The default cluster selection criterion.
    const fn default_cluster_selection_criterion() -> Criterion {
        // See https://git.frama-c.com/kokkonis/rosa/-/issues/2.
        Criterion::EdgesAndSyscalls
    }
    /// The default cluster selection distance metric.
    const fn default_cluster_selection_distance_metric() -> DistanceMetric {
        DistanceMetric::Hamming
    }
    /// The default oracle algorithm.
    const fn default_oracle() -> Oracle {
        Oracle::CompMinMax
    }
    /// The default criterion to use in the oracle algorithm.
    const fn default_oracle_criterion() -> Criterion {
        // See https://git.frama-c.com/kokkonis/rosa/-/issues/2.
        Criterion::SyscallsOnly
    }
    /// The default distance metric to use in the oracle algorithm.
    const fn default_oracle_distance_metric() -> DistanceMetric {
        DistanceMetric::Hamming
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
    const BACKDOORS_DIR_README: [&'static str; 8] = [
        "This directory contains inputs that trigger a backdoor in the target program. In order",
        "to reproduce the backdoor(s), you'll need to run the program under the same conditions",
        "as those used by the fuzzer that discovered it. You can find the parameters used by the",
        "fuzzer in the following files:",
        "",
        "    ../config.toml",
        "    ../decisions/<BACKDOOR_INPUT>.toml",
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
    ///
    /// # Arguments
    /// * `output_dir` - The directory in which to save the configuration file. The file will be
    ///   titled `config.toml`.
    pub fn save(&self, output_dir: &Path) -> Result<(), RosaError> {
        let config_toml = toml::to_string(&self).expect("failed to serialize config TOML.");
        let config_file = output_dir.join("config").with_extension("toml");

        fs::write(&config_file, config_toml).map_err(|err| {
            error!(
                "could not save config to file {}: {}.",
                config_file.display(),
                err
            )
        })
    }

    /// Load a configuration from file.
    ///
    /// # Arguments
    /// * `file` - The file to load the configuration from.
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
            "at least one seed condition must be specified to know when to stop collecting seeds."
        ))
    }

    /// Set up ROSA's output directories.
    ///
    /// This function sets up the output directories for ROSA, which will contain any findings
    /// produced during the backdoor detection campaign.
    ///
    /// # Arguments
    /// * `force` - If [true], force the creation of the output directory even if it already
    ///   exists.
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
            "seconds, traces, backdoors, edge_coverage, syscall_coverage\n",
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
    ///
    /// # Arguments
    /// * `seconds` - The number of seconds that have passed since the beginning of the detection
    ///   campaign.
    /// * `traces` - The current number of traces.
    /// * `backdoors` - The current number of backdoors.
    /// * `edge_coverage` - The current edge coverage.
    /// * `syscall_coverage` - The current syscall coverage.
    pub fn log_stats(
        &self,
        seconds: u64,
        traces: u64,
        backdoors: u64,
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
            "{}, {}, {}, {}, {}",
            seconds, traces, backdoors, edge_coverage, syscall_coverage
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
            .find(|fuzzer_config| fuzzer_config.name == "main")
            .ok_or(error!("No 'main' fuzzer found in the configuration."))
    }
}
