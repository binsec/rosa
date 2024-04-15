//! ROSA configuration definition & utilities.
//!
//! This module handles ROSA's configuration file (mostly its parsing), as well as IO-related
//! functionality needed by the configuration.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
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

/// A configuration for ROSA.
///
/// This configuration will be loaded from a configuration file (one per target program).
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    /// The directory in which ROSA's output will be stored.
    pub output_dir: PathBuf,

    /// The collection of fuzzers to run during the seed phase.
    pub seed_phase_fuzzers: Vec<FuzzerConfig>,
    /// The collection of fuzzers to run during the detection phase.
    pub detection_phase_fuzzers: Vec<FuzzerConfig>,

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
        Criterion::EdgesAndSyscalls
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
        Criterion::EdgesAndSyscalls
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

        toml::from_str(&config_toml)
            .map_err(|err| error!("failed to deserialize config TOML: {}.", err))
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

    /// Get the main fuzzer from the seed phase.
    pub fn main_seed_phase_fuzzer(&self) -> Result<&FuzzerConfig, RosaError> {
        self.seed_phase_fuzzers
            .iter()
            .find(|fuzzer_config| fuzzer_config.name == "main")
            .ok_or(error!("No 'main' fuzzer found in the seed phase fuzzers."))
    }

    /// Get the main fuzzer from the detection phase.
    pub fn main_detection_phase_fuzzer(&self) -> Result<&FuzzerConfig, RosaError> {
        self.detection_phase_fuzzers
            .iter()
            .find(|fuzzer_config| fuzzer_config.name == "main")
            .ok_or(error!(
                "No 'main' fuzzer found in the detection phase fuzzers."
            ))
    }
}
