//! Runtime trace definition & utilities.
//!
//! This module describes runtime traces and provides different utilities, such as IO.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    hash::{DefaultHasher, Hash, Hasher},
    io::Read,
    path::{Path, PathBuf},
};

use itertools::Itertools;

use crate::error::RosaError;

/// Runtime trace definition.
///
/// A runtime trace is produced by a _test input_ fed to a _target program_. Its full description
/// thus contains both the test input that produced it, as well as the runtime components (edges &
/// syscalls) of the trace.
#[derive(Debug, Clone, PartialEq)]
pub struct Trace {
    /// The name of the trace.
    ///
    /// This is usually the name given (to the input that produced the trace) by the fuzzer.
    pub name: String,
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

impl Hash for Trace {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.edges.hash(state);
        self.syscalls.hash(state);
    }
}

impl Trace {
    /// Loads a runtime trace from file.
    ///
    /// A runtime trace is composed of an associated test input (the test input that produced it)
    /// and a trace dump, containing the components of the runtime trace (edges and syscalls). In
    /// order to make dealing with traces easier, we assign a unique ID to each of them.
    ///
    /// # Examples
    /// ```
    /// use std::path::Path;
    /// use rosa::trace::Trace;
    ///
    /// let _trace = Trace::load(
    ///     "my_trace",
    ///     &Path::new("/path/to/test_input_file"),
    ///     &Path::new("/path/to/trace_file.trace"),
    /// );
    ///
    /// // With AFL/AFL++, traces would usually be in these dirs:
    /// let _afl_trace = Trace::load(
    ///     "afl_trace",
    ///     &Path::new("fuzzer_out/queue/id_000000"),
    ///     &Path::new("fuzzer_out/trace_dumps/id_000000.trace"),
    /// );
    /// ```
    pub fn load(
        name: &str,
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
        // Read the length of the edges (64 bits, so 8 * u8).
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
        // Read the length of the syscalls (64 bits, so 8 * u8).
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
            name: name.to_string(),
            test_input,
            edges,
            syscalls,
        })
    }

    /// Create a trace from existing data.
    ///
    /// The edges and syscalls are not fed in an *existential vector* format as the trace expects,
    /// but rather in the form of slices of indices of edge or syscall hits. The rest of the vector
    /// is populated with zeroes.
    ///
    /// # Examples
    /// ```
    /// use rosa::trace::Trace;
    ///
    /// let trace = Trace::from(
    ///     "my_trace",
    ///     &[0x01, 0x02, 0x03, 0x04],
    ///     &[1, 4, 17, 4],
    ///     20,
    ///     &[2, 2, 3, 11],
    ///     14,
    /// );
    ///
    /// assert_eq!(
    ///     trace,
    ///     Trace {
    ///         name: "my_trace".to_string(),
    ///         test_input: vec![0x01, 0x02, 0x03, 0x04],
    ///         edges: vec![0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
    ///         syscalls: vec![0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
    ///     }
    /// );
    /// ```
    pub fn from(
        name: &str,
        test_input: &[u8],
        edges: &[usize],
        edges_len: usize,
        syscalls: &[usize],
        syscalls_len: usize,
    ) -> Self {
        let mut edges_vector = vec![0; edges_len];
        let mut syscalls_vector = vec![0; syscalls_len];

        edges.iter().unique().for_each(|index| {
            edges_vector[*index] = 1;
        });
        syscalls.iter().unique().for_each(|index| {
            syscalls_vector[*index] = 1;
        });

        Trace {
            name: name.to_string(),
            test_input: test_input.to_vec(),
            edges: edges_vector,
            syscalls: syscalls_vector,
        }
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
    ///     name: "my_trace".to_string(),
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
            .map(|byte| {
                if (byte as char) >= ' ' && (byte as char) <= '~' {
                    (byte as char).to_string()
                } else {
                    format!("\\x{:0>2x}", byte)
                }
            })
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
    ///     name: "my_trace".to_string(),
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
    ///     name: "my_trace".to_string(),
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

    /// Get the unique ID of the trace in terms of edges and syscalls in base 64.
    pub fn uid(&self) -> String {
        let mut s = DefaultHasher::new();
        self.hash(&mut s);

        format!("{:016x}", s.finish())
    }

    /// Save the test input of a trace to a file.
    ///
    /// # Examples
    /// ```
    /// use std::path::Path;
    /// use rosa::trace::Trace;
    ///
    /// let my_trace = Trace {
    ///     name: "my_trace".to_string(),
    ///     test_input: vec![0x01, 0x02, 0x03, 0x04],
    ///     edges: vec![],
    ///     syscalls: vec![],
    /// };
    ///
    /// let _ = my_trace.save_test_input(&Path::new("/path/to/my_trace"));
    /// ```
    pub fn save_test_input(&self, output_file: &Path) -> Result<(), RosaError> {
        fs::write(output_file, &self.test_input).map_err(|err| {
            error!(
                "could not write trace test input to {}: {}.",
                output_file.display(),
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
    /// # Examples
    /// ```
    /// use std::path::Path;
    /// use rosa::trace::Trace;
    ///
    /// let my_trace = Trace {
    ///     name: "my_trace".to_string(),
    ///     test_input: vec![],
    ///     edges: vec![1, 0, 1, 0],
    ///     syscalls: vec![0, 1, 0, 1],
    /// };
    ///
    /// let _ = my_trace.save_trace_dump(&Path::new("/path/to/my_trace.trace"));
    /// ```
    pub fn save_trace_dump(&self, output_file: &Path) -> Result<(), RosaError> {
        let mut output = vec![];
        let edges_length: u64 = self
            .edges
            .len()
            .try_into()
            .expect("failed to convert edges length to u64.");
        let syscalls_length: u64 = self
            .syscalls
            .len()
            .try_into()
            .expect("failed to convert syscalls length to u64.");

        output.extend(edges_length.to_le_bytes().to_vec());
        output.extend(syscalls_length.to_le_bytes().to_vec());
        output.extend(&self.edges);
        output.extend(&self.syscalls);

        // Write the result to a file.
        fs::write(output_file, &output).map_err(|err| {
            error!(
                "could not write trace dump to {}: {}.",
                output_file.display(),
                err
            )
        })?;

        Ok(())
    }
}

/// A database of traces.
///
/// This structure makes it easier to collect new unique traces, as it stores information about
/// which associated test inputs have already been evaluated. This in turn can improve speed when
/// considering if we should keep a given test input-trace pair.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceDatabase {
    /// A map of trace UIDs to traces.
    traces: HashMap<String, Trace>,
    /// A set of known input files (and by extension, known traces).
    known_inputs: HashSet<PathBuf>,
}

impl TraceDatabase {
    /// Create a new database of traces.
    pub fn new() -> Self {
        Self {
            traces: HashMap::new(),
            known_inputs: HashSet::new(),
        }
    }

    /// Get all traces currently in the database.
    pub fn traces(&self) -> Vec<Trace> {
        self.traces.clone().into_values().collect()
    }

    /// Check if a given input file is known to the database.
    ///
    /// By "known" we mean that it has already been evaluated: either it was accepted and exists in
    /// the database, or it was rejected and should not be evaluated again.
    pub fn is_known_input(&self, input: &Path) -> bool {
        input
            .canonicalize()
            .ok()
            .map(|input| self.known_inputs.contains(&input))
            .unwrap_or(false)
    }

    /// Register a new input file.
    ///
    /// This should be done once an input file has been evaluated, whether is has been accepted
    /// (and added to the database) or not.
    pub fn register_input(&mut self, input: &Path) {
        if let Ok(input) = input.canonicalize() {
            if !self.is_known_input(&input) {
                self.known_inputs.insert(input);
            }
        }
    }

    /// Check whether or not a trace exists in the database.
    pub fn has_trace(&self, uid: &str) -> bool {
        self.traces.contains_key(uid)
    }

    /// Insert a new trace to the database.
    pub fn insert_trace(&mut self, trace: Trace) {
        self.traces.insert(trace.uid(), trace);
    }
}

impl Default for TraceDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Get all the test input files from a directory.
///
/// Input files are expected to be any files that do not have the extension `.trace`.
pub fn get_test_input_files(test_input_dir: &Path) -> Result<Vec<PathBuf>, RosaError> {
    fs::read_dir(test_input_dir).map_or_else(
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
                .filter(|path| {
                    path.is_file()
                        && path
                            .extension()
                            .is_none_or(|extension| extension != "trace")
                })
                .collect())
        },
    )
}

/// Get the full trace info needed to load traces.
///
/// This function returns a 3-tuple `(trace_name, trace_test_input_file, trace_dump_file)` for each
/// corresponding test input file passed to it. That is later used to load traces.
fn get_trace_info(
    test_input_files: Vec<PathBuf>,
    trace_dump_dir: &Path,
    skip_missing_traces: bool,
) -> Vec<(String, PathBuf, PathBuf)> {
    test_input_files
        .into_iter()
        // Get the name of the trace from the name of the test input file.
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
        .filter_map(|(trace_name, test_input_file)| {
            let trace_dump_file = trace_dump_dir.join(&trace_name).with_extension(
                // Make sure to preserve any extension present on the test input file itself.
                match test_input_file.extension() {
                    None => "trace".to_string(),
                    Some(extension) => format!(
                        "{}.trace",
                        extension
                            .to_str()
                            .expect("failed to convert test input file extension to str.")
                    ),
                }
                .as_str(),
            );

            // If the trace dump file does not exist and we're skipping incomplete traces, we'll
            // simply let the map filter it out. Otherwise, we will put it in; if it doesn't exist,
            // the error will get detected when we try to read the file.
            if !trace_dump_file.is_file() && skip_missing_traces {
                None
            } else {
                Some((trace_name, test_input_file.to_path_buf(), trace_dump_file))
            }
        })
        .collect()
}

/// Load multiple traces from file.
///
/// This function is used to load a lot of traces in bulk, while filtering some of them out
/// depending on different criteria. It's the function to use when "hot-loading", i.e. loading
/// while the fuzzer is actively producing new traces.
///
/// For each test input file `X` discovered in `test_input_dir`, exactly one trace dump file
/// `X.trace` is expected to be found in `trace_dump_dir`. Whether this will provoke an error or
/// not is determined by the `skip_missing_traces` argument (see below).
///
/// # Examples
/// ```
/// use std::path::Path;
/// use rosa::trace::{self, TraceDatabase};
///
/// let mut trace_db = TraceDatabase::new();
/// let _traces = trace::load_traces(
///     &Path::new("/path/to/test_input_dir/"),
///     &Path::new("/path/to/trace_dump_dir/"),
///     "main",
///     &mut trace_db,
///     // Will skip any incomplete/missing trace dumps.
///     false,
/// );
///
/// // The previous call populated the `trace_db` database, which means that this call will only
/// // pick up traces that the previous one did not.
/// let _new_traces = trace::load_traces(
///     &Path::new("/path/to/test_input_dir/"),
///     &Path::new("/path/to/trace_dump_dir/"),
///     "main",
///     &mut trace_db,
///     // Will expect every trace dump to be present & complete.
///     true,
/// );
/// ```
pub fn load_traces(
    test_input_dir: &Path,
    trace_dump_dir: &Path,
    name_prefix: &str,
    trace_db: &mut TraceDatabase,
    skip_missing_traces: bool,
) -> Result<Vec<Trace>, RosaError> {
    let mut test_inputs: Vec<PathBuf> = get_test_input_files(test_input_dir)?
        .into_iter()
        // Only keep new inputs.
        .filter(|input| !trace_db.is_known_input(input))
        .collect();
    // Make sure the test input names are sorted so that we have consistency when loading.
    test_inputs.sort();
    let trace_info = get_trace_info(test_inputs, trace_dump_dir, skip_missing_traces);

    let traces_and_inputs: Vec<(Trace, PathBuf)> = trace_info
        .into_iter()
        // Attempt to load the trace.
        .map(|(trace_name, test_input_file, trace_dump_file)| {
            if trace_dump_file.is_file() {
                // Sometimes a trace load might fail because the trace file is still being
                // written. In that case, if we're skipping traces anyway, might as well skip
                // it here too.
                let trace = Trace::load(
                    &format!("{}_{}", name_prefix, trace_name),
                    &test_input_file,
                    &trace_dump_file,
                );

                match (trace, skip_missing_traces) {
                    // If load was successful, then the trace is ok.
                    (Ok(trace), _) => Ok(Some((trace, test_input_file))),
                    // Load was unsuccessful, but we're skipping traces so it's fine.
                    (Err(_), true) => Ok(None),
                    // Load was unsuccessful, and we're not skipping traces: not fine.
                    (Err(err), false) => Err(err),
                }
            } else {
                fail!("missing trace dump file for trace '{}'.", trace_name)
            }
        })
        // Filter out the skipped traces.
        .filter_map(|element| element.transpose())
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

/// Save a collection of traces to an output directory.
///
/// Specifically, create two files per trace:
/// - A file containing the **test input** of the trace;
/// - A file containing the **trace dump** of the trace.
///
/// # Examples
/// ```
/// use std::path::Path;
/// use rosa::trace::{self, Trace};
///
/// let my_traces = vec![
///     Trace {
///         name: "trace1".to_string(), test_input: vec![0x01], edges: vec![], syscalls: vec![]
///     },
///     Trace {
///         name: "trace2".to_string(), test_input: vec![0x02], edges: vec![], syscalls: vec![]
///     },
/// ];
///
/// let _ = trace::save_traces(&my_traces, &Path::new("/path/to/traces_dir/"));
/// ```
pub fn save_traces(traces: &[Trace], output_dir: &Path) -> Result<(), RosaError> {
    traces.iter().try_for_each(|trace| {
        let base_path = output_dir.join(trace.uid());
        trace
            .save_test_input(&base_path)
            .and_then(|()| trace.save_trace_dump(&base_path.with_extension("trace")))
    })
}

/// Get the coverage of a set of traces in terms of edges and syscalls.
///
/// # Examples
/// ```
/// use rosa::trace::{self, Trace};
///
/// let traces = vec![
///     Trace {
///         name: "trace1".to_string(),
///         test_input: vec![],
///         edges: vec![0, 1, 0, 1, 0, 0, 0, 0],
///         syscalls: vec![1, 1, 0, 0],
///     },
///     Trace {
///         name: "trace2".to_string(),
///         test_input: vec![],
///         edges: vec![0, 0, 0, 0, 1, 0, 1, 0],
///         syscalls: vec![0, 1, 1, 0],
///     }
/// ];
///
/// assert_eq!(trace::get_coverage(&traces), (0.5, 0.75));
/// ```
pub fn get_coverage(traces: &[Trace]) -> (f64, f64) {
    let total_edges = traces.first().map(|trace| trace.edges.len()).unwrap_or(0);
    let total_syscalls = traces
        .first()
        .map(|trace| trace.syscalls.len())
        .unwrap_or(0);

    let edge_hits = traces
        .iter()
        .fold(vec![0; total_edges], |acc: Vec<u8>, trace| {
            trace
                .edges
                .iter()
                .zip(acc)
                .map(|(trace_edge, acc_edge)| (trace_edge | acc_edge))
                .collect()
        })
        .into_iter()
        .filter(|edge| *edge == 1)
        .count();
    let syscall_hits = traces
        .iter()
        .fold(vec![0; total_syscalls], |acc: Vec<u8>, trace| {
            trace
                .syscalls
                .iter()
                .zip(acc)
                .map(|(trace_syscall, acc_syscall)| trace_syscall | acc_syscall)
                .collect()
        })
        .into_iter()
        .filter(|syscall| *syscall == 1)
        .count();

    (
        (edge_hits as f64) / (total_edges as f64),
        (syscall_hits as f64) / (total_syscalls as f64),
    )
}
