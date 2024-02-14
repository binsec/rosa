use std::{
    collections::HashMap,
    fs::{self, File},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use crate::error::RosaError;

pub struct FuzzerProcess {
    fuzzer_cmd: Vec<String>,
    fuzzer_env: HashMap<String, String>,
    pub log_file: PathBuf,
    command: Command,
    process: Option<Child>,
}

impl FuzzerProcess {
    pub fn create(
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
            fuzzer_cmd,
            fuzzer_env,
            log_file,
            command,
            process: None,
        })
    }

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

    pub fn stop(&mut self) -> Result<(), RosaError> {
        self.process.as_mut().map_or_else(
            || fail!("could not stop process; process is not spawned."),
            |process| unsafe {
                libc::kill(process.id() as i32, libc::SIGINT);
                Ok(())
            },
        )
    }

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

    pub fn env_as_string(&self) -> String {
        self.fuzzer_env
            .iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<String>>()
            .join(" ")
    }

    pub fn cmd_as_string(&self) -> String {
        self.fuzzer_cmd.join(" ")
    }
}

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
