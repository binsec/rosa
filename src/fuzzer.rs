//! Fuzzer-handling utilities.
//!
//! This module contains utilities to create, spawn and stop fuzzer processes, as well as some
//! fuzzer-monitoring utilities.

use std::{
    collections::HashMap,
    fs::{self, File},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use serde::{Deserialize, Serialize};

use crate::{config, error::RosaError};

/// The fuzzer backends supported by ROSA.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum FuzzerBackend {
    /// The AFL++ fuzzer.
    #[serde(rename = "afl++")]
    AFLPlusPlus,
}

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
    /// crashes may hinder backdoor detection, so we'll want to keep an eye on any findings.
    pub crashes_dir: PathBuf,
    /// The fuzzer backend used.
    pub backend: FuzzerBackend,
}

/// A fuzzer instance.
pub struct FuzzerInstance {
    /// The configuration of the instance.
    pub config: FuzzerConfig,
    /// The log file that holds the fuzzer's output (`stdout` & `stderr`).
    pub log_file: PathBuf,
    /// The [Command] of the fuzzer instance.
    command: Command,
    /// The instance process.
    process: Option<Child>,
}

/// Possible states a fuzzer can be in.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FuzzerStatus {
    /// The fuzzer is running nominally.
    Running,
    /// The fuzzer is **not** running.
    Stopped,
    /// The fuzzer is starting up, but is not yet running nominally.
    Starting,
}

impl FuzzerConfig {
    /// Check if the fuzzer has found any crashes.
    ///
    /// Most fuzzers are optimized to find crashes. If a crash is found, it might alter the
    /// fuzzer's exploration or conceal a backdoor. Thus, it is useful to know if any crashes have
    /// been found.
    pub fn found_crashes(&self) -> Result<bool, RosaError> {
        match self.backend {
            FuzzerBackend::AFLPlusPlus => aflpp_found_crashes(&self.crashes_dir),
        }
    }

    /// Get the PID of a fuzzer from its output dir.
    ///
    pub fn pid(&self) -> Result<String, RosaError> {
        match self.backend {
            FuzzerBackend::AFLPlusPlus => aflpp_pid(
                self.test_input_dir
                    .parent()
                    .expect("failed to get parent directory of test inputs directory."),
            ),
        }
    }

    /// Get the status of a fuzzer.
    pub fn status(&self) -> Result<FuzzerStatus, RosaError> {
        match self.backend {
            FuzzerBackend::AFLPlusPlus => aflpp_status(
                self.test_input_dir
                    .parent()
                    .expect("failed to get parent directory of test inputs directory."),
            ),
        }
    }
}

impl FuzzerInstance {
    /// Create a new fuzzer instance (without spawning it).
    ///
    /// # Examples
    /// ```
    /// use std::{path::PathBuf, collections::HashMap};
    /// use rosa::fuzzer::{FuzzerBackend, FuzzerConfig, FuzzerInstance};
    ///
    /// let _fuzzer_instance = FuzzerInstance::create(
    ///     FuzzerConfig {
    ///         name: "my_fuzzer".to_string(),
    ///         env: HashMap::from([("AFL_DEBUG".to_string(), "1".to_string())]),
    ///         cmd: vec![
    ///             "afl-fuzz".to_string(),
    ///             "-i".to_string(),
    ///             "in".to_string(),
    ///             "-o".to_string(),
    ///             "out".to_string(),
    ///             "--".to_string(),
    ///             "./target".to_string(),
    ///         ],
    ///         test_input_dir: PathBuf::from("/path/to/test_input_dir"),
    ///         trace_dump_dir: PathBuf::from("/path/to/trace_dump_dir"),
    ///         crashes_dir: PathBuf::from("/path/to/crashes_dir"),
    ///         backend: FuzzerBackend::AFLPlusPlus
    ///     },
    ///     PathBuf::from("/path/to/log_file.log"),
    /// );
    /// ```
    pub fn create(config: FuzzerConfig, log_file: PathBuf) -> Result<Self, RosaError> {
        let log_stdout = File::create(&log_file).map_err(|err| {
            error!(
                "could not create log file '{}': {}.",
                &log_file.display(),
                err
            )
        })?;
        let log_stderr = log_stdout
            .try_clone()
            .expect("could not clone fuzzer seed log file.");

        let mut command = Command::new(&config.cmd[0]);
        command
            .args(&config.cmd[1..])
            .envs(config::replace_env_var_placeholders(&config.env))
            .stdout(Stdio::from(log_stdout))
            .stderr(Stdio::from(log_stderr));

        Ok(FuzzerInstance {
            config,
            log_file,
            command,
            process: None,
        })
    }

    /// Spawn (start) the fuzzer process.
    pub fn spawn(&mut self) -> Result<(), RosaError> {
        match &self.process {
            Some(_) => fail!("could not start fuzzer process; process is already running."),
            None => Ok(()),
        }?;

        let process = self.command.spawn().or(fail!(
            "could not run fuzzer seed command. See {}.",
            &self.log_file.display()
        ))?;
        self.process = Some(process);

        Ok(())
    }

    /// Check if the fuzzer process is running.
    pub fn is_running(&mut self) -> Result<bool, RosaError> {
        self.process
            .as_mut()
            .map(|process| {
                process
                    .try_wait()
                    .expect("could not get status of fuzzer process.")
                    .is_none()
            })
            .ok_or(error!(
                "could not get fuzzer process status; process is not spawned."
            ))
    }

    /// Stop the fuzzer process (via `SIGINT`).
    pub fn stop(&mut self) -> Result<(), RosaError> {
        self.process.as_mut().map_or_else(
            || fail!("could not stop process; process is not spawned."),
            |process| unsafe {
                libc::kill(process.id() as i32, libc::SIGINT);
                Ok(())
            },
        )?;

        self.process = None;

        Ok(())
    }

    /// Check the success of the fuzzer process.
    ///
    /// If the fuzzer process returned anything other than `0`, it's considered unsuccessful.
    pub fn check_success(&mut self) -> Result<(), RosaError> {
        self.process.as_mut().map_or_else(
            || fail!("could not check for success of fuzzer process; process is not spawned."),
            |process| {
                let exit_status = process.wait().expect("failed to wait for process to stop.");

                exit_status.success().then_some(()).ok_or(error!(
                    "process exited with code {}",
                    exit_status
                        .code()
                        .map(|code| format!("{}", code))
                        .unwrap_or("<signal>".to_string())
                ))
            },
        )
    }

    /// Get the environment passed to the fuzzer in string form.
    pub fn env_as_string(&self) -> String {
        self.config
            .env
            .iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<String>>()
            .join(" ")
    }

    /// Get the command used to run the fuzzer in string form.
    pub fn cmd_as_string(&self) -> String {
        self.config.cmd.join(" ")
    }
}

/// Check if the fuzzer has found any crashes.
fn aflpp_found_crashes(crashes_dir: &Path) -> Result<bool, RosaError> {
    fs::read_dir(crashes_dir).map_or_else(
        |err| {
            fail!(
                "invalid crashes directory '{}': {}.",
                crashes_dir.display(),
                err
            )
        },
        |res| Ok(res.filter_map(|item| item.ok()).next().is_some()),
    )
}

/// Get the PID of a fuzzer from its output dir.
fn aflpp_pid(fuzzer_dir: &Path) -> Result<String, RosaError> {
    let fuzzer_stats_file = fuzzer_dir.join("fuzzer_stats");
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

/// Get the status of a fuzzer.
fn aflpp_status(fuzzer_dir: &Path) -> Result<FuzzerStatus, RosaError> {
    fuzzer_dir
        .is_dir()
        .then(|| {
            let fuzzer_setup_file = fuzzer_dir.join("fuzzer_setup");
            let fuzzer_stats_file = fuzzer_dir.join("fuzzer_stats");

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
                        let pid = aflpp_pid(fuzzer_dir).expect("failed to get fuzzer PID.");
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
        })
        .ok_or(error!(
            "could not check fuzzer directory '{}'.",
            fuzzer_dir.display()
        ))
}
