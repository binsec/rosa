//! Interface to the AFL++ fuzzer.
//!
//! Note that this is a patched version specifically crafted to work with ROSA. It can be found in
//! the same repository, under `fuzzers/aflpp`.

use std::{
    collections::HashMap,
    fmt,
    fs::{self, File},
    io::Seek,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use regex::Regex;
use serde::{Deserialize, Serialize};
use tempfile::{self, NamedTempFile};

use crate::{
    config,
    error::RosaError,
    fuzzer::{FuzzerBackend, FuzzerStatus},
    trace::{self, Trace, TraceDatabase},
};

/// The maximum system call ID supported in the source version.
///
/// This value is chosen somewhat arbitrarily, and it is based on x86_64 Linux system calls. It
/// might have to be modified for other platforms.
// TODO maybe this should be an optional parameter in the config?
const MAX_SYSCALLS: usize = 600;

/// The AFL++ fuzzer.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AFLPlusPlus {
    /// The name of the fuzzer.
    pub name: String,
    /// The mode of the fuzzer.
    pub mode: AFLPlusPlusMode,
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
    /// The way the input is provided to the target.
    ///
    /// This is used to collect traces in standard mode.
    pub input: AFLPlusPlusInput,
    /// Any extra arguments to pass to the fuzzer.
    pub extra_args: Vec<String>,
    /// Any environment variables to set for the fuzzer.
    pub env: HashMap<String, String>,
}

/// The supported modes for AFL++.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq)]
pub enum AFLPlusPlusMode {
    /// Standard source instrumentation.
    ///
    /// The target program is expected to be compiled with an instrumentation-injecting compiler
    /// prior to fuzzing.
    #[serde(rename = "standard")]
    Standard,
    /// Binary-only fuzzing with QEMU.
    #[serde(rename = "qemu")]
    QEMU,
}

impl fmt::Display for AFLPlusPlusMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Standard => "standard",
                Self::QEMU => "qemu",
            }
        )
    }
}

/// The way the input is fed to the target program.
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub enum AFLPlusPlusInput {
    /// Input is provided through standard input.
    #[serde(rename = "stdin")]
    Stdin,
    /// Input is provided through a file.
    #[serde(rename = "file")]
    File,
    /// Input is provided through a libfuzzer-style harness.
    #[serde(rename = "libfuzzer")]
    LibFuzzer,
}

impl AFLPlusPlus {
    /// Get the PID of the fuzzer.
    ///
    /// The PID of the fuzzer can be found in the `fuzzer_stats` file, if it exists.
    fn pid(&self) -> Result<String, RosaError> {
        let fuzzer_stats_file = self.output_dir.join(&self.name).join("fuzzer_stats");
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
    fn backend_id(&self) -> String {
        format!("afl++-{}", self.mode)
    }

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
            if self.mode == AFLPlusPlusMode::QEMU {
                vec!["-Q".to_string()]
            } else {
                Vec::new()
            },
            self.extra_args.clone(),
            vec!["--".to_string()],
            self.target.clone(),
        ]
        .concat()
    }

    fn env(&self) -> HashMap<String, String> {
        self.env.clone()
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
        let fuzzer_setup_file = self.output_dir.join(&self.name).join("fuzzer_setup");
        let fuzzer_stats_file = self.output_dir.join(&self.name).join("fuzzer_stats");

        let fuzzer_setup_metadata = fuzzer_setup_file.metadata();
        let fuzzer_stats_metadata = fuzzer_stats_file.metadata();

        match (fuzzer_setup_metadata, fuzzer_stats_metadata) {
            (Ok(setup_metadata), Ok(stats_metadata)) => {
                // From `afl-whatsup`: if `fuzzer_setup` is newer than `fuzzer_stats`, then the
                // fuzzer is still starting up.
                if setup_metadata
                    .modified()
                    .expect("failed to get metadata for fuzzer_setup.")
                    > stats_metadata
                        .modified()
                        .expect("failed to get metadata for fuzzer_stats.")
                {
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

    fn setup(&self, output_dir: &Path) -> Result<(), RosaError> {
        if self.name() == "main" && self.backend_id() == *"afl++-standard" {
            let output_dir = output_dir.join("aflpp");
            fs::create_dir(&output_dir)
                .map_err(|err| error!("could not create '{}': {}.", &output_dir.display(), err))?;

            // Write the maximum number of edges to a file.
            let max_edges_file = File::create(output_dir.join(".max-edges"))
                .map_err(|err| error!("could not create .max-edges file: {}.", err))?;

            let target_cmd = self.target.clone();
            Command::new(&target_cmd[0])
                .args(&target_cmd[1..])
                .env("AFL_DUMP_MAP_SIZE", "1")
                .stdout(max_edges_file)
                .stderr(Stdio::null())
                .status()
                .map_err(|err| {
                    error!(
                        "could not run target program to obtain max edges: {}: {}.",
                        target_cmd.join(" "),
                        err
                    )
                })?;
        }

        Ok(())
    }

    fn teardown(&self, output_dir: &Path) -> Result<(), RosaError> {
        if self.name() == "main" && self.backend_id() == *"afl++-standard" {
            let output_dir = output_dir.join("aflpp");
            fs::remove_dir_all(&output_dir)
                .map_err(|err| error!("could not remove '{}': {}.", &output_dir.display(), err))?;
        }

        Ok(())
    }

    fn collect_traces(
        &self,
        trace_db: &mut TraceDatabase,
        skip_missing_traces: bool,
        input_dir: &Path,
        output_dir: &Path,
    ) -> Result<Vec<Trace>, RosaError> {
        // Unfortunately, we can't just call the default implementation, so we'll have to duplicate
        // it here.
        match self.mode {
            AFLPlusPlusMode::Standard => {
                let mut test_inputs: Vec<PathBuf> = trace::get_test_input_files(input_dir)?
                    .into_iter()
                    // Only keep new inputs.
                    .filter(|input| !trace_db.is_known_input(input))
                    .collect();
                // Make sure the test input names are sorted so that we have consistency when loading.
                test_inputs.sort();

                let traces_and_inputs: Vec<(Trace, PathBuf)> = test_inputs
                    .into_iter()
                    .map(|test_input_path| {
                        // In "standard" mode, we need to call `afl-showmap` and `strace` to get the
                        // edges and syscalls respectively.
                        let mut test_input_file = File::open(&test_input_path).map_err(|err| {
                            error!(
                                "could not open test input file '{}': {}.",
                                test_input_path.display(),
                                err
                            )
                        })?;

                        // For `afl-showmap`, we need to do:
                        // ```
                        // $ afl-showmap -o /tmp/trace.txt -q -e -- <program + arguments> \
                        //       && cat /tmp/trace.txt \
                        //       | sed -nE 's/^0*([[:digit:]]+):1$/\1/p'
                        // ```
                        // Maybe it's worth it to modify afl-showmap to add an option to print to
                        // stdout?
                        let showmap_output_file = NamedTempFile::new()
                            .map_err(|err| error!("could not create temporary file: {}.", err))?;
                        let showmap_output_path = showmap_output_file.into_temp_path();

                        let afl_showmap = self
                            .afl_fuzz
                            .parent()
                            .expect("failed to get parent directory of afl-fuzz.")
                            .join("afl-showmap");
                        let afl_showmap_args = vec![
                            "-o".to_string(),
                            showmap_output_path.to_string_lossy().to_string(),
                            "-q".to_string(),
                            "-e".to_string(),
                            "--".to_string(),
                        ];

                        let mut afl_showmap_cmd = Command::new(afl_showmap);
                        match self.input {
                            // If the input is read from `stdin`, then simply pass the file to the
                            // `stdin` of the process.
                            AFLPlusPlusInput::Stdin => afl_showmap_cmd
                                .args([afl_showmap_args, self.target.clone()].concat())
                                .stdin(
                                    test_input_file
                                        .try_clone()
                                        .expect("failed to clone test input file."),
                                ),
                            // If the input is read from a file, there is no need to pass anything
                            // to the `stdin` of the process. However, we should replace all
                            // occurrences of `@@` in the target command by the path to the file.
                            AFLPlusPlusInput::File => afl_showmap_cmd.args(
                                [
                                    afl_showmap_args,
                                    self.target
                                        .clone()
                                        .into_iter()
                                        .map(|arg| {
                                            if arg == "@@" {
                                                test_input_path.display().to_string()
                                            } else {
                                                arg
                                            }
                                        })
                                        .collect(),
                                ]
                                .concat(),
                            ),
                            AFLPlusPlusInput::LibFuzzer => afl_showmap_cmd.args(
                                [
                                    afl_showmap_args,
                                    self.target.clone(),
                                    vec![test_input_path.display().to_string()],
                                ]
                                .concat(),
                            ),
                        }
                        .envs(config::replace_env_var_placeholders(&self.env()))
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .map_err(|err| error!("afl-showmap failed: {}.", err))?;

                        let showmap_output = fs::read_to_string(showmap_output_path)
                            .map_err(|err| error!("could not read afl-showmap output: {}.", err))?;
                        let showmap_regex = Regex::new(r"(?m)^0*([[:digit:]]+):1$")
                            .expect("failed to compile showmap regex.");
                        let edges: Vec<usize> = showmap_regex
                            .captures_iter(&showmap_output)
                            .map(|capture| {
                                capture
                                    .get(1)
                                    .expect("failed to get showmap regex match.")
                                    .as_str()
                                    .parse::<usize>()
                                    .expect("failed to convert showmap regex match to `usize`.")
                            })
                            .collect();

                        // Make sure to rewind the input file before running `strace`.
                        test_input_file.rewind().map_err(|err| {
                            error!(
                                "could not rewind test input file '{}': {}.",
                                test_input_path.display(),
                                err
                            )
                        })?;
                        // For `strace`, we need to do:
                        // ```
                        // $ strace -e abbrev=all \
                        //       -e quiet=attach,exit,path-resolution,personality,thread-execve \
                        //       -ff -n -- \
                        //       <program + arguments> \
                        //       | sed -nE 's/^\[[[:space:]]*([[:digit:]]+)\].+$/\1/p' \
                        //       | sort \
                        //       | uniq
                        // ```

                        let strace_args = [
                            vec![
                                "-e".to_string(),
                                "abbrev=all".to_string(),
                                "-e".to_string(),
                                "quiet=attach,exit,path-resolution,\
                                                personality,thread-execve"
                                    .to_string(),
                                "-ff".to_string(),
                                "-n".to_string(),
                                "--".to_string(),
                            ],
                            // We want to take `AFL_PRELOAD` into account (if it's declared). The
                            // trouble is, `AFL_PRELOAD` does not mean anything to `strace`.
                            // So, we replace it by `LD_PRELOAD`, which will actually change
                            // things for `strace`.
                            config::replace_env_var_placeholders(&self.env())
                                .into_iter()
                                .map(|(key, value)| {
                                    if key == "AFL_PRELOAD" {
                                        format!("--env=LD_PRELOAD={}", value)
                                    } else {
                                        format!("--env={}={}", key, value)
                                    }
                                })
                                .collect::<Vec<String>>(),
                        ]
                        .concat();

                        let mut strace_cmd = Command::new("strace");
                        let strace_output = match self.input {
                            // If the input is read from `stdin`, then simply pass the file to the
                            // `stdin` of the process.
                            AFLPlusPlusInput::Stdin => strace_cmd
                                .args([strace_args, self.target.clone()].concat())
                                .stdin(test_input_file),
                            // If the input is read from a file, there is no need to pass anything
                            // to the `stdin` of the process. However, we should replace all
                            // occurrences of `@@` in the target command by the path to the file.
                            AFLPlusPlusInput::File => strace_cmd.args(
                                [
                                    strace_args,
                                    self.target
                                        .clone()
                                        .into_iter()
                                        .map(|arg| {
                                            if arg == "@@" {
                                                test_input_path.display().to_string()
                                            } else {
                                                arg
                                            }
                                        })
                                        .collect(),
                                ]
                                .concat(),
                            ),
                            AFLPlusPlusInput::LibFuzzer => strace_cmd.args(
                                [
                                    strace_args,
                                    self.target.clone(),
                                    vec![test_input_path.display().to_string()],
                                ]
                                .concat(),
                            ),
                        }
                        .output()
                        .map_err(|err| error!("`strace` failed: {}.", err))?;
                        let strace_output = String::from_utf8_lossy(&strace_output.stderr);
                        let start_index = strace_output.find("__ROSAS_CANTINA__").ok_or(error!(
                            "could not find ROSA's trace marker, maybe a missing \
                                `__ROSA_TRACE_START()`?"
                        ))?;
                        let strace_regex = Regex::new(concat!(
                            r"(?m)^",
                            r"(\[pid[[:space:]]*[[:digit:]]+\][[:space:]]+)?",
                            r"\[[[:space:]]*([[:digit:]]+)\].+$"
                        ))
                        .expect("failed to compile strace regex.");
                        let syscalls: Vec<usize> = strace_regex
                            .captures_iter(&strace_output[start_index..])
                            .map(|capture| {
                                capture
                                    .get(2)
                                    .expect("failed to get strace regex match.")
                                    .as_str()
                                    .parse::<usize>()
                                    .expect("failed to convert strace regex match to `usize`.")
                            })
                            .collect();

                        // Get the map size produced during setup.
                        let max_edges =
                            fs::read_to_string(output_dir.join("aflpp").join(".max-edges"))
                                .expect("failed to read max edge count from file (setup issue?).");
                        let max_edges = max_edges
                            .trim_end()
                            .parse::<usize>()
                            .expect("failed to parse max edge count.");

                        Ok((
                            Trace::from(
                                &format!(
                                    "{}__{}",
                                    self.name(),
                                    test_input_path
                                        .file_name()
                                        .expect("failed to get filename for test input.")
                                        .to_string_lossy()
                                ),
                                &fs::read(&test_input_path).map_err(|err| {
                                    error!(
                                        "could not read test input file '{}': {}.",
                                        test_input_path.display(),
                                        err
                                    )
                                })?,
                                &edges,
                                max_edges,
                                &syscalls,
                                MAX_SYSCALLS,
                            ),
                            test_input_path,
                        ))
                    })
                    .collect::<Result<Vec<(Trace, PathBuf)>, RosaError>>()?;

                let new_traces =
                    traces_and_inputs
                        .into_iter()
                        .fold(Vec::new(), |new_traces, (trace, input)| {
                            trace_db.register_input(&input);
                            if !trace_db.has_trace(&trace.uid()) {
                                trace_db.insert_trace(trace.clone());

                                [vec![trace], new_traces].concat()
                            } else {
                                new_traces
                            }
                        });

                Ok(new_traces)
            }
            AFLPlusPlusMode::QEMU => trace::load_traces(
                &self.test_input_dir(),
                &self.runtime_trace_dir(),
                self.name(),
                trace_db,
                skip_missing_traces,
            ),
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
        let extra_args: Vec<String> = vec!["-c", "0"].iter().map(|arg| arg.to_string()).collect();
        let env: HashMap<String, String> = [
            ("AFL_INST_LIBS", "1"),
            ("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1"),
        ]
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
        let config = AFLPlusPlus {
            name: name.clone(),
            mode: AFLPlusPlusMode::QEMU,
            input: AFLPlusPlusInput::Stdin,
            is_main: true,
            afl_fuzz: afl_fuzz.clone(),
            input_dir: input_dir.clone(),
            output_dir: output_dir.clone(),
            target: target.clone(),
            extra_args: extra_args.clone(),
            env: env.clone(),
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
                    name,
                    "-Q".to_string(),
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
            mode: AFLPlusPlusMode::Standard,
            input: AFLPlusPlusInput::LibFuzzer,
            afl_fuzz: afl_fuzz.clone(),
            input_dir: input_dir.clone(),
            output_dir: output_dir.clone(),
            target: target.clone(),
            extra_args: Vec::new(),
            env: HashMap::new(),
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
