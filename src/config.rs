use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::{
    criterion::Criterion, distance_metric::DistanceMetric, error::RosaError, oracle::Oracle,
};

#[derive(Builder, Serialize, Deserialize, Debug)]
pub struct Config {
    pub output_dir: PathBuf,
    pub fuzzer_seed_cmd: Vec<String>,
    pub fuzzer_seed_env: HashMap<String, String>,
    pub fuzzer_run_cmd: Vec<String>,
    pub fuzzer_run_env: HashMap<String, String>,
    pub test_input_dir: PathBuf,
    pub trace_dump_dir: PathBuf,
    pub crashes_dir: PathBuf,

    #[serde(default = "Config::default_cluster_formation_criterion")]
    pub cluster_formation_criterion: Criterion,
    #[serde(default = "Config::default_cluster_formation_distance_metric")]
    pub cluster_formation_distance_metric: DistanceMetric,
    #[serde(default = "Config::default_cluster_formation_edge_tolerance")]
    pub cluster_formation_edge_tolerance: u64,
    #[serde(default = "Config::default_cluster_formation_syscall_tolerance")]
    pub cluster_formation_syscall_tolerance: u64,
    #[serde(default = "Config::default_cluster_selection_criterion")]
    pub cluster_selection_criterion: Criterion,
    #[serde(default = "Config::default_cluster_selection_distance_metric")]
    pub cluster_selection_distance_metric: DistanceMetric,
    #[serde(default = "Config::default_oracle")]
    pub oracle: Oracle,
    #[serde(default = "Config::default_oracle_criterion")]
    pub oracle_criterion: Criterion,
    #[serde(default = "Config::default_oracle_distance_metric")]
    pub oracle_distance_metric: DistanceMetric,
}

impl Config {
    const fn default_cluster_formation_criterion() -> Criterion {
        Criterion::EdgesAndSyscalls
    }
    const fn default_cluster_formation_distance_metric() -> DistanceMetric {
        DistanceMetric::Hamming
    }
    const fn default_cluster_formation_edge_tolerance() -> u64 {
        0
    }
    const fn default_cluster_formation_syscall_tolerance() -> u64 {
        0
    }
    const fn default_cluster_selection_criterion() -> Criterion {
        Criterion::EdgesAndSyscalls
    }
    const fn default_cluster_selection_distance_metric() -> DistanceMetric {
        DistanceMetric::Hamming
    }
    const fn default_oracle() -> Oracle {
        Oracle::CompMinMax
    }
    const fn default_oracle_criterion() -> Criterion {
        Criterion::EdgesAndSyscalls
    }
    const fn default_oracle_distance_metric() -> DistanceMetric {
        DistanceMetric::Hamming
    }

    const OUTPUT_DIR_README: &'static str = "\
        This is an output directory created by ROSA, the backdoor detection tool.\n\
        It contains the following subdirectories:\n\n\
        - backdoors: contains all detected backdoor-triggering inputs\n\
        - clusters: contains the different clusters that were formed prior to detection\n\
        - decisions: contains the decisions of the oracle, as well as the parameters used by it\n\
        - logs: contains the logs generated by the fuzzer\n\
        - traces: contains all the test inputs and trace dumps corresponding to the traces \n  \
          that have been evaluated so far\n\n\
        It also contains the `config.json` file, which describes the configuration parameters\n\
        used in order to produce these results.\n";
    const BACKDOORS_DIR_README: &'static str = "\
        This directory contains inputs that trigger a backdoor in the target program. In order\n\
        to reproduce the backdoor(s), you'll need to run the program under the same conditions\n\
        as those used by the fuzzer that discovered it. You can find the parameters used by the\n\
        fuzzer in the following files:\n\n    \
            ../config.json\n    \
            ../decisions/<BACKDOOR_INPUT>.json\n";
    const CLUSTERS_DIR_README: &'static str = "\
        This directory contains the clusters created by ROSA. Each cluster file is named after\n\
        the ID of the cluster, and contains the IDs of the traces that form the cluster.\n\
        The test inputs and actual trace dumps (edge/syscall vectors) of those traces can be\n\
        found in:\n\n    \
            ../traces/\n";
    const DECISIONS_DIR_README: &'static str = "\
        This directory contains the decisions made by the oracle for every trace it has analyzed\n\
        so far. See the documentation for details on the format of the decision files.\n";
    const LOGS_DIR_README: &'static str = "\
        This directory contains the logs created by the fuzzer processes (both stdout and\n\
        stderr).\n\
        The file `fuzzer_seed.log` corresponds to the seed collection run of the fuzzer,\n\
        while the file `fuzzer_run.log` corresponds to the exploration/detection run of the\n\
        fuzzer.\n";
    const TRACES_DIR_README: &'static str = "\
        This directory contains the test inputs and trace dumps associated with each trace that\n\
        has been evaluated so far.\n\
        Test inputs can be found in the files named:\n\n    \
            <TRACE ID>\n\n\
        Trace dumps can be found in the files named:\n\n    \
            <TRACE ID>.trace\n";

    pub fn save(&self, output_dir: &Path) -> Result<(), RosaError> {
        let config_json =
            serde_json::to_string_pretty(&self).expect("failed to serialize config JSON.");
        let config_file = output_dir.join("config").with_extension("json");

        fs::write(&config_file, config_json).map_err(|err| {
            error!(
                "could not save config to file {}: {}.",
                config_file.display(),
                err
            )
        })
    }

    pub fn load(file: &Path) -> Result<Self, RosaError> {
        let config_json = fs::read_to_string(file)
            .map_err(|err| error!("failed to read configuration from file: {}.", err))?;

        serde_json::from_str(&config_json)
            .map_err(|err| error!("failed to deserialize config JSON: {}.", err))
    }

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
            (&self.output_dir, Self::OUTPUT_DIR_README),
            (&self.backdoors_dir(), Self::BACKDOORS_DIR_README),
            (&self.clusters_dir(), Self::CLUSTERS_DIR_README),
            (&self.decisions_dir(), Self::DECISIONS_DIR_README),
            (&self.logs_dir(), Self::LOGS_DIR_README),
            (&self.traces_dir(), Self::TRACES_DIR_README),
        ] {
            fs::create_dir(dir)
                .map_err(|err| error!("could not create '{}': {}", &dir.display(), err))?;
            fs::write(dir.join("README").with_extension("txt"), readme).map_err(|err| {
                error!("could not create README for '{}': {}", &dir.display(), err)
            })?;
        }

        Ok(())
    }

    pub fn backdoors_dir(&self) -> PathBuf {
        self.output_dir.join("backdoors")
    }

    pub fn clusters_dir(&self) -> PathBuf {
        self.output_dir.join("clusters")
    }

    pub fn decisions_dir(&self) -> PathBuf {
        self.output_dir.join("decisions")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.output_dir.join("logs")
    }

    pub fn traces_dir(&self) -> PathBuf {
        self.output_dir.join("traces")
    }
}
