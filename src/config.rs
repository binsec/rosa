use std::{collections::HashMap, fs, path::PathBuf};

use derive_builder::Builder;

use crate::{
    criterion::Criterion, distance_metric::DistanceMetric, error::RosaError, oracle::Oracle,
};

#[derive(Builder)]
pub struct Config {
    output_dir: PathBuf,
    pub fuzzer_seed_cmd: Vec<String>,
    pub fuzzer_seed_env: HashMap<String, String>,
    pub fuzzer_run_cmd: Vec<String>,
    pub fuzzer_run_env: HashMap<String, String>,
    pub test_input_dir: PathBuf,
    pub trace_dump_dir: PathBuf,

    pub cluster_formation_criterion: Criterion,
    pub cluster_formation_distance_metric: DistanceMetric,
    pub cluster_formation_edge_tolerance: u64,
    pub cluster_formation_syscall_tolerance: u64,
    pub cluster_selection_criterion: Criterion,
    pub cluster_selection_distance_metric: DistanceMetric,
    pub oracle: Oracle,
    pub oracle_criterion: Criterion,
    pub oracle_distance_metric: DistanceMetric,
}

impl Config {
    const DEFAULT_CLUSTER_FORMATION_CRITERION: Criterion = Criterion::EdgesAndSyscalls;
    const DEFAULT_CLUSTER_FORMATION_DISTANCE_METRIC: DistanceMetric = DistanceMetric::Hamming;
    const DEFAULT_CLUSTER_FORMATION_EDGE_TOLERANCE: u64 = 0;
    const DEFAULT_CLUSTER_FORMATION_SYSCALL_TOLERANCE: u64 = 0;
    const DEFAULT_CLUSTER_SELECTION_CRITERION: Criterion = Criterion::EdgesAndSyscalls;
    const DEFAULT_CLUSTER_SELECTION_DISTANCE_METRIC: DistanceMetric = DistanceMetric::Hamming;
    const DEFAULT_ORACLE: Oracle = Oracle::CompMinMax;
    const DEFAULT_ORACLE_CRITERION: Criterion = Criterion::EdgesAndSyscalls;
    const DEFAULT_ORACLE_DISTANCE_METRIC: DistanceMetric = DistanceMetric::Hamming;

    pub fn load(file: &str, output_dir: &str) -> Result<Self, RosaError> {
        let source = fs::read_to_string(file)
            .or_else(|err| fail!("invalid config file '{}': {}.", file, err))?;

        // Set the defaults for the config.
        // This builder will be passed around, parsing different options of the config as it goes
        // through the iterator.
        let mut builder = ConfigBuilder::default();
        let default_config_builder = builder
            .output_dir(PathBuf::from(output_dir))
            .cluster_formation_criterion(Self::DEFAULT_CLUSTER_FORMATION_CRITERION)
            .cluster_formation_distance_metric(Self::DEFAULT_CLUSTER_FORMATION_DISTANCE_METRIC)
            .cluster_formation_edge_tolerance(Self::DEFAULT_CLUSTER_FORMATION_EDGE_TOLERANCE)
            .cluster_formation_syscall_tolerance(Self::DEFAULT_CLUSTER_FORMATION_SYSCALL_TOLERANCE)
            .cluster_selection_criterion(Self::DEFAULT_CLUSTER_SELECTION_CRITERION)
            .cluster_selection_distance_metric(Self::DEFAULT_CLUSTER_SELECTION_DISTANCE_METRIC)
            .oracle(Self::DEFAULT_ORACLE)
            .oracle_criterion(Self::DEFAULT_ORACLE_CRITERION)
            .oracle_distance_metric(Self::DEFAULT_ORACLE_DISTANCE_METRIC);

        // Parse the `.ini` file.
        source
            // Each line is its own option, and spaces on either side of the line are ignored.
            .split("\n")
            .map(|line| line.trim())
            // Enumerate, to get the line number (for error reporting).
            .enumerate()
            // Filter out empty lines and comments (lines that start with `#`).
            .filter(|(_, line)| {
                !line.is_empty()
                    && !line
                        .chars()
                        .nth(0)
                        .is_some_and(|first_char| first_char == '#')
            })
            // Every line is expected to be of the form `a = b`, so split at the first `=` and keep
            // the two resulting substrings.
            .map(|(index, line)| {
                let mut splitter = line.splitn(2, '=');
                (index, (splitter.next(), splitter.next()))
            })
            // Aggregate all of the key-value pairs to build the final configuration. We start with
            // the default configuration, and tack on the parsed option on every iteration.
            .fold(
                Ok(default_config_builder),
                |builder, (index, (key, value))| {
                    Self::build_option_from_key_value_pair(builder, key, value, file, index + 1)
                },
            )?
            // Build the final configuration (if possible), or report a missing element.
            .build()
            .or_else(|err| fail!("{}: incomplete configuration: {}", file, err))
    }

    fn build_option_from_key_value_pair<'a>(
        builder: Result<&'a mut ConfigBuilder, RosaError>,
        key: Option<&'a str>,
        value: Option<&'a str>,
        file: &'a str,
        lineno: usize,
    ) -> Result<&'a mut ConfigBuilder, RosaError> {
        // Propagate the error if it exists.
        let builder = builder?;
        // Create a string to reuse when reporting the position of an error in the config file.
        let config_file_position = format!("{}:{}", file, lineno);
        // Make sure we have both a key and a value.
        let key = key
            .ok_or(error!(
                "{}: missing key from key-value pair.",
                config_file_position
            ))?
            .trim();
        let value = value
            .ok_or(error!(
                "{}: missing value from key-value pair.",
                config_file_position
            ))?
            .trim();

        // Parse the key-value pair.
        // If the key-value pair is valid (i.e. the key is a recognized option and the value is
        // well-formatted), we will set the corresponding option on the config builder and return
        // it; otherwise, we'll return an error.
        match key {
            // The command for the "seed" phase of the fuzzer should be a simple string, with one
            // space (` `) serving as an argument separator. We need to produce a vector of strings
            // as the final result.
            "fuzzer_seed_cmd" => Ok(builder.fuzzer_seed_cmd(
                value
                    .trim_matches('"')
                    .split(" ")
                    .map(|arg| arg.to_string())
                    .collect(),
            )),
            // Collect the `KEY=VALUE` pairs from the value string and turn them into a HashMap for
            // the final env.
            "fuzzer_seed_env" => Ok(builder.fuzzer_seed_env(
                value
                    .trim_matches('"')
                    .split(" ")
                    .map(|arg| arg.to_string())
                    .filter_map(|arg| {
                        let mut splitter = arg.splitn(2, '=');
                        let key = splitter.next().map(|key| key.to_string());
                        let value = splitter.next().map(|value| value.to_string());

                        match (key, value) {
                            (Some(key), Some(value)) => Some((key, value)),
                            _ => None,
                        }
                    })
                    .collect(),
            )),
            // Same as `fuzzer_seed_cmd`.
            "fuzzer_run_cmd" => Ok(builder.fuzzer_run_cmd(
                value
                    .trim_matches('"')
                    .split(" ")
                    .map(|arg| arg.to_string())
                    .collect(),
            )),
            // Same as `fuzzer_seed_env`.
            "fuzzer_run_env" => Ok(builder.fuzzer_run_env(
                value
                    .trim_matches('"')
                    .split(" ")
                    .map(|arg| arg.to_string())
                    .filter_map(|arg| {
                        let mut splitter = arg.splitn(2, '=');
                        let key = splitter.next().map(|key| key.to_string());
                        let value = splitter.next().map(|value| value.to_string());

                        match (key, value) {
                            (Some(key), Some(value)) => Some((key, value)),
                            _ => None,
                        }
                    })
                    .collect(),
            )),
            // The test input directory is a simple string.
            "test_input_dir" => {
                Ok(builder.test_input_dir(PathBuf::from(value.trim_matches('"').to_string())))
            }
            // Same as `test_input_dir`.
            "trace_dump_dir" => {
                Ok(builder.trace_dump_dir(PathBuf::from(value.trim_matches('"').to_string())))
            }
            // The criterion is a string, but it has to be one of the recognized criteria.
            "cluster_formation_criterion" => {
                let value = value.trim_matches('"');

                Criterion::from_str(value)
                    .map(|criterion| builder.cluster_formation_criterion(criterion))
                    .ok_or(error!(
                        "{}: invalid criterion '{}'.",
                        config_file_position, value
                    ))
            }
            // The distance metric is a string, but it has to be one of the recognized distance
            // metric functions.
            "cluster_formation_distance_metric" => {
                let value = value.trim_matches('"');

                DistanceMetric::from_str(value)
                    .map(|distance_metric| {
                        builder.cluster_formation_distance_metric(distance_metric)
                    })
                    .ok_or(error!(
                        "{}: invalid criterion '{}'.",
                        config_file_position, value
                    ))
            }
            // The edge tolerance should be a positive (or zero) integer.
            "cluster_formation_edge_tolerance" => value
                .parse::<u64>()
                .map(|edge_tolerance| builder.cluster_formation_edge_tolerance(edge_tolerance))
                .or_else(|_| {
                    fail!(
                        "{}: invalid edge tolerance '{}'.",
                        config_file_position,
                        value
                    )
                }),
            // Same as `cluster_formation_edge_tolerance`.
            "cluster_formation_syscall_tolerance" => value
                .parse::<u64>()
                .map(|syscall_tolerance| {
                    builder.cluster_formation_syscall_tolerance(syscall_tolerance)
                })
                .or_else(|_| {
                    fail!(
                        "{}: invalid syscall tolerance '{}'.",
                        config_file_position,
                        value
                    )
                }),
            // Same as `cluster_formation_criterion`.
            "cluster_selection_criterion" => {
                let value = value.trim_matches('"');

                Criterion::from_str(value)
                    .map(|criterion| builder.cluster_selection_criterion(criterion))
                    .ok_or(error!(
                        "{}: invalid criterion '{}'.",
                        config_file_position, value
                    ))
            }
            // Same as `cluster_formation_distance_metric`.
            "cluster_selection_distance_metric" => {
                let value = value.trim_matches('"');

                DistanceMetric::from_str(value)
                    .map(|distance_metric| {
                        builder.cluster_selection_distance_metric(distance_metric)
                    })
                    .ok_or(error!(
                        "{}: invalid criterion '{}'.",
                        config_file_position, value
                    ))
            }
            // The oracle is a string, but it has to be one of the recognized oracle functions.
            "oracle" => {
                let value = value.trim_matches('"');

                Oracle::from_str(value)
                    .map(|oracle| builder.oracle(oracle))
                    .ok_or(error!(
                        "{}: invalid oracle '{}'.",
                        config_file_position, value
                    ))
            }
            // Same as `cluster_formation_criterion`.
            "oracle_criterion" => {
                let value = value.trim_matches('"');

                Criterion::from_str(value)
                    .map(|criterion| builder.oracle_criterion(criterion))
                    .ok_or(error!(
                        "{}: invalid criterion '{}'.",
                        config_file_position, value
                    ))
            }
            // Same as `cluster_formation_distance_metric`.
            "oracle_distance_metric" => {
                let value = value.trim_matches('"');

                DistanceMetric::from_str(value)
                    .map(|distance_metric| builder.oracle_distance_metric(distance_metric))
                    .ok_or(error!(
                        "{}: invalid criterion '{}'.",
                        config_file_position, value
                    ))
            }
            // Everything else is invalid.
            _ => fail!("{}: unknown option '{}'.", config_file_position, key),
        }
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

            fs::remove_dir_all(&self.output_dir).or_else(|err| {
                fail!(
                    "could not remove '{}': {}.",
                    &self.output_dir.display(),
                    err
                )
            })?;
        }

        // Create all directories from scratch.
        for dir in [
            &self.output_dir,
            &self.backdoors_dir(),
            &self.clusters_dir(),
            &self.decisions_dir(),
            &self.logs_dir(),
            &self.traces_dir(),
        ] {
            fs::create_dir(&dir)
                .or_else(|err| fail!("could not create '{}': {}", &dir.display(), err))?;
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
