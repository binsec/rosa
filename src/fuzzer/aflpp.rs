//! Interface to the AFL++ fuzzer.
//!
//! Note that this is a patched version specifically crafted to work with ROSA. It can be found in
//! the same repository, under `fuzzers/aflpp`.

use std::{
    collections::HashMap,
    env, fmt,
    fs::{self, File},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tempfile::{self, NamedTempFile};

use crate::{
    config,
    error::RosaError,
    fuzzer::{FuzzerBackend, FuzzerStatus},
    trace::{Trace, TraceDatabase},
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

    fn get_test_input_files(&self, input_dir: Option<&Path>) -> Result<Vec<PathBuf>, RosaError> {
        let default_input_dir = self.test_input_dir();
        let input_dir = input_dir.unwrap_or(&default_input_dir);
        fs::read_dir(input_dir)
            .map(|res| {
                res
                    // Ignore files/dirs we cannot read.
                    .filter_map(|item| item.ok())
                    .map(|item| item.path())
                    .filter(|path| path.is_file())
                    .collect()
            })
            .map_err(|err| {
                error!(
                    "invalid test input directory '{}': {}.",
                    input_dir.display(),
                    err
                )
            })
    }

    /// Collect one trace in AFL++ standard mode (source instrumentation).
    ///
    /// This function calls `afl-showmap` to get the CFG edges and `strace` to get the system calls
    /// associated with the test input. Naturally, `afl-showmap` is expected to be found in the
    /// same directory as `afl-fuzz` ([afl_fuzz](crate::fuzzer::aflpp::AFLPlusPlus::afl_fuzz)).
    fn collect_one_trace_standard(
        &self,
        skip_missing_traces: bool,
        original_test_input_path: &Path,
        test_input_path: &Path,
        test_input: &[u8],
        scratch_dir: &Path,
    ) -> Result<Option<Trace>, RosaError> {
        // For `afl-showmap`, we need to do:
        // ```
        // $ afl-showmap -o /tmp/trace.txt -q -e -- <program + arguments> \
        //       && cat /tmp/trace.txt \
        //       | sed -nE 's/^0*([[:digit:]]+):1$/\1/p'
        // ```
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
        let afl_showmap_status = match self.input {
            // If the input is read from `stdin`, then simply pass the file to the
            // `stdin` of the process.
            AFLPlusPlusInput::Stdin => afl_showmap_cmd
                .args([afl_showmap_args, self.target.clone()].concat())
                .stdin(File::open(test_input_path).expect("failed to open test input file.")),
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
        .map_err(|err| error!("could not get `afl-showmap`'s status: {}.", err))?;

        // `afl-showmap` can fail spuriously for certain target programs. That's
        // okay, we can just skip the trace for now and hope to collect it later,
        // if we're allowed to skip.
        //
        // If it keeps crashing then it will become apparent when no traces are
        // collected at all, so this still (indirectly) lets the user know there is
        // a problem.
        if !afl_showmap_status.success() {
            // `afl-showmap` exits with code `2` on timeout. We don't really care about the timeout
            // itself (we will still gladly take the captured edges), so we will just not consider
            // this to be an error. However, there is no real guarantee that exit code `2` does not
            // mean that something *else* went wrong, but this is blocking too many things to not
            // skip.
            //
            // You can set `ROSA_DO_NOT_IGNORE_AFL_SHOWMAP=1` to exit on any `afl-showmap` error.
            if skip_missing_traces {
                return Ok(None);
            } else if afl_showmap_status.code().unwrap_or(0) != 2
                || env::var("ROSA_DO_NOT_IGNORE_AFL_SHOWMAP").unwrap_or("0".to_string()) == "1"
            {
                let input_dump = scratch_dir.join("afl-showmap-crashing-test-input");
                fs::write(&input_dump, test_input)
                    .expect("failed to write input to emergency file.");
                fail!(
                    "`afl-showmap` failed while processing '{}' ({:?}). Input dumped to {}.",
                    original_test_input_path.display(),
                    afl_showmap_status,
                    input_dump.display()
                )?;
            }
        }

        let showmap_output = fs::read_to_string(showmap_output_path)
            .map_err(|err| error!("could not read afl-showmap output: {}.", err))?;
        let showmap_regex =
            Regex::new(r"(?m)^0*([[:digit:]]+):1$").expect("failed to compile showmap regex.");
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
        let strace_output_file = NamedTempFile::new()
            .map_err(|err| error!("could not create temporary file: {}.", err))?;
        let strace_output_path = strace_output_file.into_temp_path();

        let strace_args = [
            vec![
                // TODO make this value a parameter of the configuration?
                "5s".to_string(),
                "strace".to_string(),
                "-e".to_string(),
                "abbrev=all".to_string(),
                "-e".to_string(),
                "quiet=attach,exit,path-resolution,\
                                                personality,thread-execve"
                    .to_string(),
                "--follow-forks".to_string(),
                "--syscall-number".to_string(),
                format!("--output={}", strace_output_path.display()),
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
            vec!["--".to_string()],
        ]
        .concat();

        // Run `strace` under `timeout`, to ensure that we do not block even if the input results
        // in a timeout.
        let mut strace_cmd = Command::new("timeout");
        match self.input {
            // If the input is read from `stdin`, then simply pass the file to the
            // `stdin` of the process.
            AFLPlusPlusInput::Stdin => strace_cmd
                .args([strace_args, self.target.clone()].concat())
                .stdin(File::open(test_input_path).expect("failed to open test input file.")),
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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Note that we do not check if the `strace` command returned a non-0 exit
        // code. This is because that `strace` will transparently return the
        // target program's exit code, which means that we can't rely on it to
        // judge whether or not `strace` succeeded. In fact, we do not need to
        // check for this at all, because we're already checking for the presence
        // of the ROSA marker; if the marker is there, it's highly unlikely that
        // `strace` failed.
        .status()
        .map_err(|err| error!("could not get `strace`'s status: {}.", err))?;

        let strace_output = fs::read_to_string(strace_output_path)
            .map_err(|err| error!("could not read strace output: {}.", err))?;

        // `strace` can fail spuriously for certain target programs. That's
        // okay, we can just skip the trace for now and hope to collect it later,
        // if we're allowed to skip.
        //
        // If it keeps crashing then it will become apparent when no traces are
        // collected at all, so this still (indirectly) lets the user know there is
        // a problem.
        let find_result = strace_output.find("__ROSAS_CANTINA__");
        if find_result.is_none() {
            if skip_missing_traces {
                return Ok(None);
            } else {
                fail!(
                    "could not find ROSA's trace marker, maybe a missing `__ROSA_TRACE_START()`?"
                )?;
            }
        }
        let start_index =
            find_result.expect("find_result should be `Some(...)` after `is_none()` check.");

        let strace_regex = Regex::new(concat!(
            r"(?m)^",
            r"[[:digit:]]+[[:space:]]*",
            r"\[[[:space:]]*([[:digit:]]+)\].+$"
        ))
        .expect("failed to compile strace regex.");
        let syscalls: Vec<usize> = strace_regex
            .captures_iter(&strace_output[start_index..])
            .map(|capture| {
                capture
                    .get(1)
                    .expect("failed to get strace regex match.")
                    .as_str()
                    .parse::<usize>()
                    .expect("failed to convert strace regex match to `usize`.")
            })
            .collect();

        // Get the map size produced during setup.
        let max_edges = fs::read_to_string(scratch_dir.join(".max-edges"))
            .expect("failed to read max edge count from file (setup issue?).");
        let max_edges = max_edges
            .trim_end()
            .parse::<usize>()
            .expect("failed to parse max edge count.");

        Ok(Some(Trace::from(
            &format!(
                "{}__{}",
                self.name(),
                original_test_input_path
                    .file_name()
                    .expect("failed to get file name for test input.")
                    .to_string_lossy()
            ),
            test_input,
            &edges,
            max_edges,
            &syscalls,
            MAX_SYSCALLS,
        )))
    }

    /// Collect one trace in AFL++ QEMU mode (binary on-the-fly instrumentation).
    ///
    /// In this mode, AFL++ should be dumping the `.trace` files, so this function will simply
    /// pick them up.
    fn collect_one_trace_qemu(
        &self,
        skip_missing_traces: bool,
        original_test_input_path: &Path,
        test_input_path: &Path,
    ) -> Result<Option<Trace>, RosaError> {
        let test_input_file_name = original_test_input_path
            .file_name()
            .expect("failed to get file name for test input.")
            .to_string_lossy();

        // Make sure to preserve any existing extension(s).
        let test_input_extension = original_test_input_path.extension().map(|ext| {
            ext.to_str()
                .expect("should be able to convert extension to str")
                .to_string()
        });
        let trace_dump_extension = test_input_extension
            .map(|ext| format!("{}.trace", ext))
            .unwrap_or("trace".to_string());

        let trace_dump_path = self
            .output_dir
            .join(self.name())
            .join("trace_dumps")
            .join(test_input_file_name.to_string())
            .with_extension(&trace_dump_extension);

        if trace_dump_path.exists() {
            let new_trace = Trace::load(
                &format!("{}_{}", self.name(), test_input_file_name),
                test_input_path,
                &trace_dump_path,
            )?;

            Ok(Some(new_trace))
        } else if skip_missing_traces {
            Ok(None)
        } else {
            fail!(
                "missing trace dump file for test input '{}'.",
                test_input_file_name
            )
        }
    }

    /// A wrapper to handle collecting a single trace regardless of AFL++ mode.
    ///
    /// If a trace database is provided, then it will be used for trace deduplication during
    /// collection. If not, then the returned trace may be a duplicate of some existing trace, and
    /// it is the responsibility of the caller to deduplicate the result.
    fn collect_one_trace_from_one_input(
        &self,
        trace_db: Option<&mut TraceDatabase>,
        skip_missing_traces: bool,
        scratch_dir: &Path,
        test_input_path: &Path,
    ) -> Result<Option<Trace>, RosaError> {
        // First, check that the test input file still exists.
        if test_input_path.exists() {
            // If the test input exists, save it to a temporary file. This way, even if
            // AFL++ renames or deletes it, we still have it.
            let original_test_input_path = test_input_path;
            let test_input: Vec<u8> = fs::read(test_input_path).map_err(|err| {
                error!(
                    "could not read test input file '{}': {}.",
                    test_input_path.display(),
                    err
                )
            })?;
            let test_input_path = NamedTempFile::new()
                .map_err(|err| error!("could not create temporary file: {}.", err))?
                .into_temp_path();
            fs::write(&test_input_path, &test_input)
                .map_err(|err| error!("could not write test input to temporary file: {}.", err))?;

            let new_trace = match self.mode {
                AFLPlusPlusMode::Standard => self.collect_one_trace_standard(
                    skip_missing_traces,
                    original_test_input_path,
                    &test_input_path,
                    &test_input,
                    scratch_dir,
                ),
                AFLPlusPlusMode::QEMU => self.collect_one_trace_qemu(
                    skip_missing_traces,
                    original_test_input_path,
                    &test_input_path,
                ),
            }?;

            // Register input & trace (if needed).
            Ok(new_trace.and_then(|trace| match trace_db {
                Some(db) => {
                    db.register_input(original_test_input_path);

                    if !db.has_trace(&trace.uid()) {
                        db.insert_trace(trace.clone());

                        Some(trace)
                    } else {
                        None
                    }
                }
                None => Some(trace),
            }))
        } else if skip_missing_traces {
            Ok(None)
        } else {
            fail!(
                "could not open test input file '{}': file does not exist.",
                test_input_path.display()
            )
        }
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

    /// WARNING: this function is technically _unsafe_, as it sets an environment variable.
    ///
    /// See <https://doc.rust-lang.org/std/env/fn.set_var.html#safety>.
    ///
    /// This is because some targets fail to run if `AFL_MAP_SIZE` is not set to the actual map
    /// size, obtained by running `AFL_DUMP_MAP_SIZE=1 /path/to/target`.
    fn setup(&self, scratch_dir: &Path) -> Result<(), RosaError> {
        if self.backend_id() == *"afl++-standard" {
            if !scratch_dir.exists() {
                fs::create_dir(scratch_dir).map_err(|err| {
                    error!("could not create '{}': {}.", &scratch_dir.display(), err)
                })?;
            }

            // Write the maximum number of edges to a file.
            let max_edges_file = File::create(scratch_dir.join(".max-edges"))
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

            let map_size = fs::read_to_string(scratch_dir.join(".max-edges"))
                .map_err(|err| error!("could not read map size from .max-edges file: {}.", err))?;

            unsafe {
                env::set_var("AFL_MAP_SIZE", map_size);
            }
        }

        Ok(())
    }

    fn collect_one_trace(
        &self,
        trace_db: &mut TraceDatabase,
        skip_missing_traces: bool,
        scratch_dir: &Path,
        input_dir: Option<&Path>,
    ) -> Result<Option<Trace>, RosaError> {
        let mut test_inputs: Vec<PathBuf> = self
            .get_test_input_files(input_dir)?
            .into_iter()
            // Only keep new inputs.
            .filter(|input| !trace_db.is_known_input(input))
            .collect();

        // Get the first available input.
        test_inputs.sort();
        test_inputs
            .first()
            .map(|test_input_path| {
                self.collect_one_trace_from_one_input(
                    Some(trace_db),
                    skip_missing_traces,
                    scratch_dir,
                    test_input_path,
                )
            })
            .unwrap_or(Ok(None))
    }

    fn collect_all_traces(
        &self,
        trace_db: &mut TraceDatabase,
        skip_missing_traces: bool,
        scratch_dir: &Path,
        input_dir: Option<&Path>,
    ) -> Result<Vec<Trace>, RosaError> {
        let mut test_inputs: Vec<PathBuf> = self
            .get_test_input_files(input_dir)?
            .into_iter()
            // Only keep new inputs.
            .filter(|input| !trace_db.is_known_input(input))
            .collect();

        test_inputs.sort();
        let new_traces: Vec<Trace> = test_inputs
            .par_iter()
            // Filter out `None` traces, usually corresponding to failures.
            .filter_map(|test_input_path| {
                self.collect_one_trace_from_one_input(
                    None,
                    skip_missing_traces,
                    scratch_dir,
                    test_input_path,
                )
                .transpose()
            })
            .collect::<Result<Vec<Trace>, RosaError>>()?;

        let unique_traces: Vec<Trace> = new_traces
            .into_iter()
            .filter_map(|new_trace| {
                if !trace_db.has_trace(&new_trace.uid()) {
                    trace_db.insert_trace(new_trace.clone());
                    Some(new_trace)
                } else {
                    None
                }
            })
            .collect();

        Ok(unique_traces)
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
        let target: Vec<String> = ["sudo", "--stdin", "--reset-timestamp", "--", "id"]
            .iter()
            .map(|arg| arg.to_string())
            .collect();
        let extra_args: Vec<String> = ["-c", "0"].iter().map(|arg| arg.to_string()).collect();
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
        let target: Vec<String> = ["./target"].iter().map(|arg| arg.to_string()).collect();
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
