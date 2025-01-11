//! Fuzzer-handling utilities.
//!
//! This module contains utilities to create, spawn and stop fuzzer processes, as well as some
//! fuzzer-monitoring utilities.

use std::{
    collections::HashMap,
    fs::File,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use dyn_clone::{clone_trait_object, DynClone};
use serde::{Deserialize, Serialize};

use crate::{config, error::RosaError};

pub mod aflpp;

/// The interface to a fuzzer backend.
///
/// This backend is expected to generate (test input, runtime trace) pairs that can then be
/// collected by ROSA.
#[typetag::serde(tag = "kind")]
pub trait FuzzerBackend: DynClone {
    /// Get the name of the fuzzer instance.
    fn name(&self) -> &str;
    /// Get the full command used to invoke the fuzzer.
    fn cmd(&self) -> Vec<String>;
    /// Get the path to the directory where the fuzzer places new test inputs.
    fn test_input_dir(&self) -> PathBuf;
    /// Get the path to the directory where the fuzzer places runtime traces, corresponding to test
    /// inputs.
    fn runtime_trace_dir(&self) -> PathBuf;
    /// Check if the fuzzer has found any crashes.
    fn found_crashes(&self) -> Result<bool, RosaError>;
    /// Get the status of the fuzzer.
    fn status(&self) -> FuzzerStatus;
}
clone_trait_object!(FuzzerBackend);

/// A fuzzer configuration.
#[derive(Serialize, Deserialize, Clone)]
pub struct FuzzerConfig {
    /// Any environment variables that need to be passed to the fuzzer.
    pub env: HashMap<String, String>,
    /// The fuzzer backend to use.
    pub backend: Box<dyn FuzzerBackend>,
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

impl FuzzerInstance {
    /// Create a new fuzzer instance (without spawning it).
    ///
    /// # Examples
    /// ```
    /// use std::{path::PathBuf, collections::HashMap};
    /// use rosa::fuzzer::{aflpp::AFLPlusPlus, FuzzerConfig, FuzzerInstance};
    ///
    /// let _fuzzer_instance = FuzzerInstance::create(
    ///     FuzzerConfig {
    ///         env: HashMap::from([("AFL_DEBUG".to_string(), "1".to_string())]),
    ///         backend: Box::new(AFLPlusPlus {
    ///             name: "main".to_string(),
    ///             is_main: true,
    ///             afl_fuzz: PathBuf::from("afl-fuzz"),
    ///             input_dir: PathBuf::from("seeds"),
    ///             output_dir: PathBuf::from("findings"),
    ///             target: vec!["./target".to_string()],
    ///             extra_args: vec!["-Q".to_string()],
    ///         }),
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

        let fuzzer_cmd = config.backend.cmd();
        let mut command = Command::new(&fuzzer_cmd[0]);
        command
            .args(&fuzzer_cmd[1..])
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
        self.config.backend.cmd().join(" ")
    }
}
