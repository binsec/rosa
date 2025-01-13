//! Interface to the AFL++ fuzzer.
//!
//! Note that this is a patched version specifically crafted to work with ROSA. It can be found in
//! the same repository, under `fuzzers/aflpp`.

use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    error::RosaError,
    fuzzer::{FuzzerBackend, FuzzerStatus},
};

/// The AFL++ fuzzer.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AFLPlusPlus {
    /// The name of the fuzzer.
    pub name: String,
    /// Whether or not this is a main instance.
    pub is_main: bool,
    /// The path to the `afl-fuzz` binary.
    pub afl_fuzz: PathBuf,
    /// The path to the seed corpus directory to use.
    pub input_dir: PathBuf,
    /// The path to the findings (output) directory to use.
    pub output_dir: PathBuf,
    /// The full command to invoke the target program (with arguments if needed).
    pub target: Vec<String>,
    /// Any extra arguments to pass to the fuzzer
    pub extra_args: Vec<String>,
}

impl AFLPlusPlus {
    /// Get the PID of the fuzzer.
    ///
    /// The PID of the fuzzer can be found in the `fuzzer_stats` file, if it exists.
    fn pid(&self) -> Result<String, RosaError> {
        let fuzzer_stats_file = self.output_dir.join("fuzzer_stats");
        fs::read_to_string(&fuzzer_stats_file).map_or_else(
            |err| {
                fail!(
                    "could not read fuzzer stats file ('{}') to get PID: {}.",
                    fuzzer_stats_file.display(),
                    err
                )
            },
            |raw_stats| {
                let fuzzer_pid_index = raw_stats
                    .match_indices("fuzzer_pid")
                    .next()
                    .ok_or(error!(
                        "could not find \"fuzzer_pid\" in '{}'.",
                        fuzzer_stats_file.display()
                    ))?
                    .0;
                let pid_start_index = fuzzer_pid_index
                + raw_stats[fuzzer_pid_index..]
                    .match_indices(':')
                    .next()
                    .ok_or(error!(
                        "could not find PID value start index in '{}'.",
                        fuzzer_stats_file.display()
                    ))?
                    .0
                // +1 to move past the colon.
                + 1;
                let pid_stop_index = pid_start_index
                    + raw_stats[pid_start_index..]
                        .match_indices('\n')
                        .next()
                        // Just in case we hit the end of the string.
                        .unwrap_or((raw_stats.len(), ""))
                        .0;

                Ok(raw_stats[pid_start_index..pid_stop_index]
                    .trim()
                    .to_string())
            },
        )
    }
}

#[typetag::serde(name = "afl++")]
impl FuzzerBackend for AFLPlusPlus {
    fn name(&self) -> &str {
        &self.name
    }

    fn cmd(&self) -> Vec<String> {
        [
            vec![
                self.afl_fuzz.display().to_string(),
                "-i".to_string(),
                self.input_dir.display().to_string(),
                "-o".to_string(),
                self.output_dir.display().to_string(),
                if self.is_main {
                    "-M".to_string()
                } else {
                    "-S".to_string()
                },
                self.name.clone(),
            ],
            self.extra_args.clone(),
            vec!["--".to_string()],
            self.target.clone(),
        ]
        .concat()
    }

    fn test_input_dir(&self) -> PathBuf {
        self.output_dir.join(&self.name).join("queue")
    }

    fn runtime_trace_dir(&self) -> PathBuf {
        self.output_dir.join(&self.name).join("trace_dumps")
    }

    fn found_crashes(&self) -> Result<bool, RosaError> {
        let crashes_dir = &self.output_dir.join(&self.name).join("crashes");
        fs::read_dir(crashes_dir).map_or_else(
            |err| {
                fail!(
                    "invalid crashes directory '{}': {}.",
                    crashes_dir.display(),
                    err
                )
            },
            // If any files are present in the crashes directory, that means that crashes were
            // found.
            |res| Ok(res.filter_map(|item| item.ok()).next().is_some()),
        )
    }

    fn status(&self) -> FuzzerStatus {
        let fuzzer_setup_file = self.output_dir.join("fuzzer_setup");
        let fuzzer_stats_file = self.output_dir.join("fuzzer_stats");

        let fuzzer_setup_metadata = fuzzer_setup_file.metadata();
        let fuzzer_stats_metadata = fuzzer_stats_file.metadata();

        match (fuzzer_setup_metadata, fuzzer_stats_metadata) {
            (Ok(setup_metadata), Ok(stats_metadata)) => {
                // From `afl-whatsup`: if `fuzzer_setup` is newer than `fuzzer_stats`, then the
                // fuzzer is still starting up.
                if setup_metadata.modified().unwrap() > stats_metadata.modified().unwrap() {
                    FuzzerStatus::Starting
                } else {
                    // Since we have access to `fuzzer_stats`, we can simply check the PID
                    // contained within to see if the process is running.
                    let pid = self.pid().expect("failed to get fuzzer PID.");
                    let proc_dir = PathBuf::from("/proc").join(pid);

                    if proc_dir.exists() {
                        FuzzerStatus::Running
                    } else {
                        FuzzerStatus::Stopped
                    }
                }
            }
            // If we have `fuzzer_setup` but not `fuzzer_stats`, the fuzzer probably hasn't
            // created it yet because it's starting up.
            (Ok(_), Err(_)) => FuzzerStatus::Starting,
            // In any other case, it's safe to assume that the fuzzer is not going to start.
            (_, _) => FuzzerStatus::Stopped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the command to invoke AFL++ is correctly computed from its configuration.
    #[test]
    fn verify_aflpp_cmd() {
        let name = "main".to_string();
        let afl_fuzz = PathBuf::from("afl-fuzz");
        let input_dir = PathBuf::from("corpus");
        let output_dir = PathBuf::from("findings");
        let target: Vec<String> = vec!["sudo", "--stdin", "--reset-timestamp", "--", "id"]
            .iter()
            .map(|arg| arg.to_string())
            .collect();
        let extra_args: Vec<String> = vec!["-Q", "-c", "0"]
            .iter()
            .map(|arg| arg.to_string())
            .collect();
        let config = AFLPlusPlus {
            name: name.clone(),
            is_main: true,
            afl_fuzz: afl_fuzz.clone(),
            input_dir: input_dir.clone(),
            output_dir: output_dir.clone(),
            target: target.clone(),
            extra_args: extra_args.clone(),
        };
        assert_eq!(
            config.cmd(),
            [
                vec![
                    afl_fuzz.display().to_string(),
                    "-i".to_string(),
                    input_dir.display().to_string(),
                    "-o".to_string(),
                    output_dir.display().to_string(),
                    "-M".to_string(),
                    name
                ],
                extra_args,
                vec!["--".to_string()],
                target
            ]
            .concat()
        );

        let name = "secondary".to_string();
        let afl_fuzz = PathBuf::from("./afl-fuzz");
        let input_dir = PathBuf::from("in");
        let output_dir = PathBuf::from("out");
        let target: Vec<String> = vec!["./target"].iter().map(|arg| arg.to_string()).collect();
        let config = AFLPlusPlus {
            name: name.clone(),
            is_main: false,
            afl_fuzz: afl_fuzz.clone(),
            input_dir: input_dir.clone(),
            output_dir: output_dir.clone(),
            target: target.clone(),
            extra_args: Vec::new(),
        };
        assert_eq!(
            config.cmd(),
            [
                vec![
                    afl_fuzz.display().to_string(),
                    "-i".to_string(),
                    input_dir.display().to_string(),
                    "-o".to_string(),
                    output_dir.display().to_string(),
                    "-S".to_string(),
                    name,
                    "--".to_string()
                ],
                target
            ]
            .concat()
        );
    }
}
