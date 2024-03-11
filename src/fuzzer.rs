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

use crate::error::RosaError;

/// A fuzzer process.
pub struct FuzzerProcess {
    /// The name of the fuzzer process.
    pub name: String,
    /// The command used to run the fuzzer.
    fuzzer_cmd: Vec<String>,
    /// The environment passed to the fuzzer process.
    fuzzer_env: HashMap<String, String>,
    /// The log file that holds the fuzzer's output (`stdout` & `stderr`).
    pub log_file: PathBuf,
    /// The [Command] of the fuzzer process.
    command: Command,
    /// The fuzzer process.
    process: Option<Child>,
}

impl FuzzerProcess {
    /// Create a new fuzzer process (without spawning it).
    ///
    /// # Arguments
    /// * `fuzzer_cmd` - The command used to run the fuzzer.
    /// * `fuzzer_env` - Any environment variables to be passed to the fuzzer process.
    /// * `log_file` - The log file to use to store the fuzzer's output (`stdout` & `stderr`).
    ///
    /// # Examples
    /// ```
    /// use std::{path::PathBuf, collections::HashMap};
    /// use rosa::fuzzer::FuzzerProcess;
    ///
    /// let _fuzzer_process = FuzzerProcess::create(
    ///     "my_fuzzer".to_string(),
    ///     vec![
    ///         "afl-fuzz".to_string(),
    ///         "-i".to_string(),
    ///         "in".to_string(),
    ///         "-o".to_string(),
    ///         "out".to_string(),
    ///         "--".to_string(),
    ///         "./target".to_string(),
    ///     ],
    ///     HashMap::from([("AFL_DEBUG".to_string(), "1".to_string())]),
    ///     PathBuf::from("/path/to/log_file.log"),
    /// );
    /// ```
    pub fn create(
        name: String,
        fuzzer_cmd: Vec<String>,
        fuzzer_env: HashMap<String, String>,
        log_file: PathBuf,
    ) -> Result<Self, RosaError> {
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

        let mut command = Command::new(&fuzzer_cmd[0]);
        command
            .args(&fuzzer_cmd[1..])
            .envs(&fuzzer_env)
            .stdout(Stdio::from(log_stdout))
            .stderr(Stdio::from(log_stderr));

        Ok(FuzzerProcess {
            name,
            fuzzer_cmd,
            fuzzer_env,
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
                    exit_status.code().expect("failed to get exit code.")
                ))
            },
        )
    }

    /// Get the environment passed to the fuzzer in string form.
    pub fn env_as_string(&self) -> String {
        self.fuzzer_env
            .iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<String>>()
            .join(" ")
    }

    /// Get the command used to run the fuzzer in string form.
    pub fn cmd_as_string(&self) -> String {
        self.fuzzer_cmd.join(" ")
    }
}

/// Check if the fuzzer has found any crashes.
///
/// Most fuzzers are optimized to find crashes; if a crash is found, the fuzzer will generate more
/// test inputs that explore that crash. This might bias the exploration of the target program, so
/// it is useful to know if it has happened.
///
/// # Arguments
/// * `crashes_dir` - The directory where the fuzzer would store any discovered crashes.
pub fn fuzzer_found_crashes(crashes_dir: &Path) -> Result<bool, RosaError> {
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
///
/// **NOTE: this only works for AFL++.**
///
/// AFL++ fuzzers leave a `fuzzer_stats` file in their output directory, that contains the PID of
/// the fuzzer instance.
///
/// # Arguments
/// * `fuzzer_dir` - The output directory of the fuzzer instance.
fn get_fuzzer_pid(fuzzer_dir: &Path) -> Result<String, RosaError> {
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

/// Check if a fuzzer is alive (running).
///
/// **NOTE: this only works for AFL++.**
///
/// # Arguments
/// * `fuzzer_dir` - The output directory of the fuzzer instance.
///
/// # Examples
/// ```
/// use std::path::PathBuf;
/// use rosa::fuzzer;
///
/// let fuzzer_dir = PathBuf::from("/path/to/fuzzer_out/main");
/// let _ = fuzzer::is_fuzzer_alive(&fuzzer_dir);
/// ```
pub fn is_fuzzer_alive(fuzzer_dir: &Path) -> Result<bool, RosaError> {
    let pid = get_fuzzer_pid(fuzzer_dir)?;
    let proc_dir = PathBuf::from("/proc").join(pid);

    proc_dir.try_exists().map_err(|err| {
        error!(
            "could not check process directory '{}': {}.",
            proc_dir.display(),
            err
        )
    })
}
