//! Runtime trace definition & utilities.
//!
//! This module describes runtime traces and provides different utilities, such as IO.

use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use crate::error::RosaError;

/// Runtime trace definition.
///
/// A runtime trace is produced by a _test input_ fed to a _target program_. Its full description
/// thus contains both the test input that produced it, as well as the runtime components (edges &
/// syscalls) of the trace.
#[derive(Debug, Clone)]
pub struct Trace {
    /// The unique ID of the trace.
    pub uid: String,
    /// The test input associated with the trace.
    pub test_input: Vec<u8>,
    /// The edges found in the trace.
    ///
    /// The edges are in the form of an _existential vector_; this means that the vector simply
    /// records the presence (`1`) or absence (`0`) of an edge in the trace. Multiple occurrences
    /// of an edge will still result in the same vector: `1` marks the presence, not the number of
    /// occurrences.
    pub edges: Vec<u8>,
    /// The syscalls found in the trace.
    ///
    /// The syscalls are in the form of an _existential vector_; this means that the vector simply
    /// records the presence (`1`) or absence (`0`) of a syscall in the trace. Multiple occurrences
    /// of a syscall will still result in the same vector: `1` marks the presence, not the number
    /// of occurrences.
    pub syscalls: Vec<u8>,
}

impl Trace {
    /// Loads a runtime trace from file.
    ///
    /// A runtime trace is composed of an associated test input (the test input that produced it)
    /// and a trace dump, containing the components of the runtime trace (edges and syscalls). In
    /// order to make dealing with traces easier, we assign a unique ID to each of them.
    ///
    /// # Arguments
    /// * `uid` - The unique ID associated with the trace. This is mostly used to distinguish
    ///   between traces.
    /// * `test_input_file` - The path to the (binary) file containing the raw test input that
    ///   generated the trace.
    /// * `trace_dump_file` - The path to the (binary) file containing the trace dump associated
    ///   with the trace. We expect the trace dump file to have the following format:
    ///   ```text
    ///   <nb_edges: u64><nb_syscalls: u64><edges: [u8]><syscalls: [u8]>
    ///   ```
    ///
    /// # Examples
    /// ```
    /// use std::path::Path;
    /// use rosa::trace::Trace;
    ///
    /// let trace = Trace::load(
    ///     "my_trace",
    ///     &Path::new("/path/to/test_input_file"),
    ///     &Path::new("/path/to/trace_file.trace"),
    /// );
    ///
    /// // With AFL/AFL++, traces would usually be in these dirs:
    /// let afl_trace = Trace::load(
    ///     "afl_trace",
    ///     &Path::new("fuzzer_out/queue/id_000000"),
    ///     &Path::new("fuzzer_out/trace_dumps/id_000000.trace"),
    /// );
    /// ```
    pub fn load(
        uid: &str,
        test_input_file: &Path,
        trace_dump_file: &Path,
    ) -> Result<Self, RosaError> {
        let test_input = fs::read(test_input_file).map_err(|err| {
            error!(
                "could not read test input file '{}': {}.",
                test_input_file.display(),
                err
            )
        })?;

        let mut file = File::open(trace_dump_file).map_err(|err| {
            error!(
                "could not open trace dump file '{}': {}.",
                trace_dump_file.display(),
                err
            )
        })?;
        // Read the length of the edges (64 bytes, so 8 * u8).
        let mut length_buffer = [0u8; 8];
        file.read_exact(&mut length_buffer).map_err(|err| {
            error!(
                "could not read length of edge trace from {}: {}.",
                trace_dump_file.display(),
                err
            )
        })?;
        // Convert the 8 bytes to the final number of edges.
        let edges_length = u64::from_le_bytes(length_buffer);
        // Read the length of the syscalls (64 bytes, so 8 * u8).
        let mut length_buffer = [0u8; 8];
        file.read_exact(&mut length_buffer).map_err(|err| {
            error!(
                "could not read length of edge trace from {}: {}.",
                trace_dump_file.display(),
                err
            )
        })?;
        // Convert the 8 bytes to the final number of syscalls.
        let syscalls_length = u64::from_le_bytes(length_buffer);

        // Read the edges from the file.
        let mut edges = vec![
            0;
            edges_length
                .try_into()
                .expect("failed to convert length of edge trace into usize.")
        ];
        file.read_exact(&mut edges).map_err(|err| {
            error!(
                "could not read edge trace from {}: {}.",
                trace_dump_file.display(),
                err
            )
        })?;

        // Read the syscalls from the file.
        let mut syscalls = vec![
            0;
            syscalls_length
                .try_into()
                .expect("failed to convert length of edge trace into usize.")
        ];
        file.read_exact(&mut syscalls).map_err(|err| {
            error!(
                "could not read edge trace from {}: {}.",
                trace_dump_file.display(),
                err
            )
        })?;

        Ok(Trace {
            uid: uid.to_string(),
            test_input,
            edges,
            syscalls,
        })
    }

    /// Get a printable version of the test input.
    ///
    /// In order to be able to see every byte of the test input without having any junk
    /// non-printable characters, the non-printable ones are converted to `\xYY` hexadecimal form,
    /// to be easier to read.
    ///
    /// # Examples
    /// ```
    /// use rosa::trace::Trace;
    ///
    /// // Dummy trace to test with.
    /// let trace = Trace {
    ///     uid: "my_trace".to_string(),
    ///     test_input: vec![0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0xde, 0xad, 0xbe, 0xef],
    ///     edges: vec![],
    ///     syscalls: vec![],
    /// };
    ///
    /// // Should get "hello \xde\xad\xbe\xef".
    /// assert_eq!(trace.printable_test_input(), "hello \\xde\\xad\\xbe\\xef".to_string());
    /// ```
    pub fn printable_test_input(&self) -> String {
        self.test_input
            .clone()
            .into_iter()
            .map(
                |byte| match (byte as char) >= ' ' && (byte as char) <= '~' {
                    true => (byte as char).to_string(),
                    false => format!("\\x{:0>2x}", byte),
                },
            )
            .collect::<Vec<String>>()
            .join("")
    }

    /// Convert the edges vector to a printable string.
    ///
    /// This is mostly for stats/debugging; since in most cases the full vector is too big to
    /// show on screen, we simply return the number of edges and the percentage of coverage they
    /// correspond to (i.e. how many `1`s compared to the vector's length).
    ///
    /// # Examples
    /// ```
    /// use rosa::trace::Trace;
    ///
    /// // Dummy trace to test with.
    /// let trace = Trace {
    ///     uid: "my_trace".to_string(),
    ///     test_input: vec![],
    ///     edges: vec![0, 1, 1, 0],
    ///     syscalls: vec![],
    /// };
    ///
    /// assert_eq!(trace.edges_as_string(), "2 edges (50.00%)".to_string());
    /// ```
    pub fn edges_as_string(&self) -> String {
        let nb_edges = self
            .edges
            .clone()
            .into_iter()
            .fold(0u64, |acc, edge| acc + (edge as u64));

        format!(
            "{} edges ({:.2}%)",
            nb_edges,
            (nb_edges as f64) / (self.edges.len() as f64) * 100.0
        )
    }

    /// Convert the syscalls vector to a printable string.
    ///
    /// This is mostly for stats/debugging; since in most cases the full vector is too big to
    /// show on screen, we simply return the number of syscalls and the percentage of coverage they
    /// correspond to (i.e. how many `1`s compared to the vector's length).
    ///
    /// # Examples
    /// ```
    /// use rosa::trace::Trace;
    ///
    /// // Dummy trace to test with.
    /// let trace = Trace {
    ///     uid: "my_trace".to_string(),
    ///     test_input: vec![],
    ///     edges: vec![],
    ///     syscalls: vec![0, 0, 1, 0],
    /// };
    ///
    /// assert_eq!(trace.syscalls_as_string(), "1 syscalls (25.00%)".to_string());
    /// ```
    pub fn syscalls_as_string(&self) -> String {
        let nb_syscalls = self
            .syscalls
            .clone()
            .into_iter()
            .fold(0u64, |acc, syscall| acc + (syscall as u64));

        format!(
            "{} syscalls ({:.2}%)",
            nb_syscalls,
            (nb_syscalls as f64) / (self.syscalls.len() as f64) * 100.0
        )
    }
}

/// Load multiple traces from file.
///
/// This function is used to load a lot of traces in bulk, while filtering some of them out
/// depending on different criteria. It's the function to use when "hot"-loading, i.e. loading
/// while the fuzzer is actively producing new traces.
///
/// For each test input file `X` discovered in `test_input_dir`, exactly one trace dump file
/// `X.trace` is expected to be found in `trace_dump_dir`. Whether this will provoke an error or
/// not is determined by the `skip_missing_traces` argument (see below).
///
/// # Arguments
/// * `test_input_dir` - The directory containing the test inputs to be loaded.
/// * `trace_dump_dir` - The directory containing the trace dumps to be loaded.
/// * `fuzzer_instance_name` - If [Some], this is the name that's going to be used to namespace the
///   trace. This is useful when performing parallel fuzzing, as each fuzzer's unique name is used
///   as a prefix/namespace to the trace UID, to ensure that no collisions are possible.
/// * `known_traces` - A [HashMap] of known traces. This is used as a filter, to avoid loading
///   already seen traces; any trace UIDs contained in the [HashMap] will **not** be loaded.
/// * `skip_missing_traces` - If [true], missing or incomplete traces will be skipped, otherwise an
///   error will be returned. This is used when "hot"-loading, as we may come across incomplete or
///   missing trace dump files; we can ignore them and let some future invocation pick them up.
///
/// # Examples
/// ```
/// use std::{path::Path, collections::HashMap};
/// use rosa::trace;
///
/// let mut known_traces = HashMap::new();
/// let traces = trace::load_traces(
///     &Path::new("/path/to/test_input_dir/"),
///     &Path::new("/path/to/trace_dump_dir/"),
///     Some("main"),
///     &mut known_traces,
///     // Will skip any incomplete/missing trace dumps.
///     false,
/// );
///
/// // The previous call populated the `known_traces` hash map, which means that this call will
/// // only pick up traces that the previous one did not.
/// let new_traces = trace::load_traces(
///     &Path::new("/path/to/test_input_dir/"),
///     &Path::new("/path/to/trace_dump_dir/"),
///     Some("main"),
///     &mut known_traces,
///     // Will expect every trace dump to be present & complete.
///     true,
/// );
/// ```
pub fn load_traces(
    test_input_dir: &Path,
    trace_dump_dir: &Path,
    fuzzer_instance_name: Option<&str>,
    known_traces: &mut HashMap<String, Trace>,
    skip_missing_traces: bool,
) -> Result<Vec<Trace>, RosaError> {
    let mut test_inputs: Vec<PathBuf> = fs::read_dir(test_input_dir)
        .map_or_else(
            |err| {
                fail!(
                    "invalid test input directory '{}': {}.",
                    test_input_dir.display(),
                    err
                )
            },
            |res| {
                Ok(res
                    // Ignore files/dirs we cannot read.
                    .filter_map(|item| item.ok())
                    .map(|item| item.path())
                    // Only keep files that do not end in `.trace`.
                    .filter(|path| path.is_file() && path.extension().is_none())
                    // Only keep new traces.
                    .filter(|path| {
                        let trace_uid = path
                            .file_name()
                            .expect("failed to get basename for path.")
                            .to_str()
                            .expect("failed to convert basename to str.");
                        // Namespace trace UID with the fuzzer instance's name.
                        let trace_uid = match fuzzer_instance_name {
                            Some(fuzzer_instance_name) => {
                                format!("{}__{}", fuzzer_instance_name, trace_uid)
                            }
                            None => trace_uid.to_string(),
                        };
                        !known_traces.contains_key(&trace_uid.to_string())
                    }))
            },
        )?
        .collect();

    // Make sure the test input names are sorted so that we have consistency when loading.
    test_inputs.sort();

    let trace_info: Vec<(String, PathBuf, PathBuf)> = test_inputs
        .into_iter()
        // Get the UID of the trace from the name of the test input file.
        .map(|test_input_file| {
            (
                test_input_file
                    .file_name()
                    .expect("failed to get basename for test input file.")
                    .to_os_string()
                    .into_string()
                    .expect("failed to convert basename to string."),
                test_input_file,
            )
        })
        // Get the name of the trace dump file, potentially skipping if it doesn't exist.
        .filter_map(|(trace_uid, test_input_file)| {
            let trace_dump_file = trace_dump_dir.join(&trace_uid).with_extension("trace");

            // If the trace dump file does not exist and we're skipping incomplete traces, we'll
            // simply let the map filter it out. Otherwise, we will put it in; if it doesn't exist,
            // the error will get detected when we try to read the file.
            match !trace_dump_file.is_file() && skip_missing_traces {
                true => None,
                false => Some((trace_uid, test_input_file, trace_dump_file)),
            }
        })
        .collect();

    trace_info
        .into_iter()
        // Attempt to load the trace.
        .map(|(trace_uid, test_input_file, trace_dump_file)| {
            // Namespace trace UID with the fuzzer instance's name.
            let trace_uid = match fuzzer_instance_name {
                Some(fuzzer_instance_name) => format!("{}__{}", fuzzer_instance_name, trace_uid),
                None => trace_uid.to_string(),
            };
            match trace_dump_file.is_file() {
                true => {
                    // Sometimes a trace load might fail because the trace file is still being
                    // written. In that case, if we're skipping traces anyway, might as well skip
                    // it here too.
                    let trace = Trace::load(&trace_uid, &test_input_file, &trace_dump_file);

                    match (trace, skip_missing_traces) {
                        (Ok(trace), _) => {
                            // If load was successful, log the trace as a known trace.
                            known_traces.insert(trace_uid.to_string(), trace.clone());

                            Ok(Some(trace))
                        }
                        // Load was unsuccessful, but we're skipping traces so it's fine.
                        (Err(_), true) => Ok(None),
                        // Load was unsuccessful, and we're not skipping traces: not fine.
                        (Err(err), false) => Err(err),
                    }
                }
                false => {
                    fail!("missing trace dump file for trace '{}'.", trace_uid)
                }
            }
        })
        // Filter out the skipped traces.
        .filter_map(|trace| trace.transpose())
        .collect()
}

/// Save a collection of traces to an output directory.
///
/// Specifically, create two files per trace:
/// - A file containing the **test input** of the trace;
/// - A file containing the **trace dump** of the trace.
///
/// # Arguments
/// * `traces` - The collection of traces to save.
/// * `output_dir` - The output directory where we should save the traces.
///
/// # Examples
/// ```
/// use std::path::Path;
/// use rosa::trace::{self, Trace};
///
/// let my_traces = vec![
///     Trace {
///         uid: "trace1".to_string(), test_input: vec![0x01], edges: vec![], syscalls: vec![]
///     },
///     Trace {
///         uid: "trace2".to_string(), test_input: vec![0x02], edges: vec![], syscalls: vec![]
///     },
/// ];
///
/// trace::save_traces(&my_traces, &Path::new("/path/to/traces_dir/"));
/// ```
pub fn save_traces(traces: &[Trace], output_dir: &Path) -> Result<(), RosaError> {
    traces.iter().try_for_each(|trace| {
        save_trace_test_input(trace, output_dir).and_then(|()| save_trace_dump(trace, output_dir))
    })
}

/// Save the test input of a trace to a file.
///
/// # Arguments
/// * `trace` - The trace whose test input we should save.
/// * `output_dir` - The output directory where we should save the trace input.
///
/// # Examples
/// ```
/// use std::path::Path;
/// use rosa::trace::{self, Trace};
///
/// let my_trace = Trace {
///     uid: "my_trace".to_string(),
///     test_input: vec![0x01, 0x02, 0x03, 0x04],
///     edges: vec![],
///     syscalls: vec![],
/// };
///
/// trace::save_trace_test_input(&my_trace, &Path::new("/path/to/my_trace"));
/// ```
pub fn save_trace_test_input(trace: &Trace, output_dir: &Path) -> Result<(), RosaError> {
    let trace_test_input_file = output_dir.join(&trace.uid);
    fs::write(&trace_test_input_file, &trace.test_input).map_err(|err| {
        error!(
            "could not write trace test input to {}: {}.",
            trace_test_input_file.display(),
            err
        )
    })?;
    Ok(())
}

/// Save the runtime representation (trace dump) of a trace to a file.
///
/// Just like in [Trace::load], we will maintain the expected format of a binary trace dump:
///   ```text
///   <nb_edges: u64><nb_syscalls: u64><edges: [u8]><syscalls: [u8]>
///   ```
///
/// # Arguments
/// * `trace` - The trace whose runtime representation we should save
/// * `output_dir` - The output directory where we should save the trace dump.
///
/// # Examples
/// ```
/// use std::path::Path;
/// use rosa::trace::{self, Trace};
///
/// let my_trace = Trace {
///     uid: "my_trace".to_string(),
///     test_input: vec![],
///     edges: vec![1, 0, 1, 0],
///     syscalls: vec![0, 1, 0, 1],
/// };
///
/// trace::save_trace_dump(&my_trace, &Path::new("/path/to/my_trace.trace"));
/// ```
pub fn save_trace_dump(trace: &Trace, output_dir: &Path) -> Result<(), RosaError> {
    let mut output = vec![];
    let edges_length: u64 = trace
        .edges
        .len()
        .try_into()
        .expect("failed to convert edges length to u64.");
    let syscalls_length: u64 = trace
        .syscalls
        .len()
        .try_into()
        .expect("failed to convert syscalls length to u64.");

    output.extend(edges_length.to_le_bytes().to_vec());
    output.extend(syscalls_length.to_le_bytes().to_vec());
    output.extend(&trace.edges);
    output.extend(&trace.syscalls);

    // Write the result to a file.
    let trace_dump_file = output_dir.join(&trace.uid).with_extension("trace");
    fs::write(&trace_dump_file, &output).map_err(|err| {
        error!(
            "could not write trace dump to {}: {}.",
            trace_dump_file.display(),
            err
        )
    })?;

    Ok(())
}
