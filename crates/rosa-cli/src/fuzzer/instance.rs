//! Fuzzer instance spawning and management.
//!
//! Allows to create, spawn, (gracefully) stop, and inspect fuzzer processes.

use std::{
    fs::File,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use rosa_core::{error, error::RosaError, fail};

use crate::{
    config,
    fuzzer::{FuzzerBackend, config::FuzzerConfig},
};

/// A fuzzer instance.
pub struct FuzzerInstance {
    /// The configuration of the instance.
    pub config: FuzzerConfig,
    /// The scratch directory dedicated to the instance.
    pub scratch_dir: PathBuf,
    /// The log file that holds the fuzzer's output (`stdout` & `stderr`).
    pub log_file: PathBuf,
    /// The [Command] of the fuzzer instance.
    command: Command,
    /// The instance process.
    process: Option<Child>,
}

impl FuzzerInstance {
    /// Create a new fuzzer instance (without spawning it).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::{path::PathBuf, collections::HashMap};
    /// use rosa_cli::fuzzer::{
    ///     aflpp::{AFLPlusPlus, AFLPlusPlusMode, AFLPlusPlusInput},
    ///     config::{FuzzerConfig, FuzzerBackendKind},
    ///     instance::FuzzerInstance,
    /// };
    ///
    /// let _fuzzer_instance = FuzzerInstance::create(
    ///     FuzzerConfig {
    ///         backend: FuzzerBackendKind::AFLPlusPlus(AFLPlusPlus {
    ///             name: "main".to_string(),
    ///             mode: AFLPlusPlusMode::QEMU,
    ///             input: AFLPlusPlusInput::Stdin,
    ///             is_main: true,
    ///             afl_fuzz: PathBuf::from("afl-fuzz"),
    ///             input_dir: PathBuf::from("seeds"),
    ///             output_dir: PathBuf::from("findings"),
    ///             target: vec!["./target".to_string()],
    ///             extra_args: vec!["-Q".to_string()],
    ///             env: HashMap::from([("AFL_DEBUG".to_string(), "1".to_string())]),
    ///             max_syscall_id: AFLPlusPlus::default_max_syscall_id(),
    ///             strace_timeout_seconds: AFLPlusPlus::default_strace_timeout_seconds(),
    ///         }),
    ///     },
    ///     PathBuf::from("/path/to/scratch_dir"),
    ///     PathBuf::from("/path/to/log_file.log"),
    /// );
    /// ```
    pub fn create(
        config: FuzzerConfig,
        scratch_dir: PathBuf,
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
            .expect("could not clone fuzzer log file.");

        let fuzzer_cmd = config.backend.cmd();
        let mut command = Command::new(&fuzzer_cmd[0]);
        command
            .args(&fuzzer_cmd[1..])
            .envs(config::replace_env_var_placeholders(&config.backend.env()))
            .stdout(Stdio::from(log_stdout))
            .stderr(Stdio::from(log_stderr));

        Ok(FuzzerInstance {
            config,
            scratch_dir,
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
            "could not run fuzzer command. See {}.",
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
            .backend
            .env()
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
