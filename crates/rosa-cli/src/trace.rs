//! TODO: doc

use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use clap::ValueEnum;

use rosa::{error, error::RosaError, fail, trace::Trace};

/// The trace component to analyze.
#[derive(Clone, ValueEnum)]
pub enum Component {
    /// Only take edges into account.
    Edges,
    /// Only take system calls into account.
    Syscalls,
}

/// Loads a runtime trace from file.
///
/// A runtime trace is composed of an associated test input (the test input that produced it)
/// and a trace dump, containing the components of the runtime trace (edges and syscalls). In
/// order to make dealing with traces easier, we assign an ID to each of them.
///
/// # Examples
/// ```
/// use std::path::Path;
/// use rosa_cli::trace;
///
/// let _trace = trace::load_trace_from_file(
///     "my_trace",
///     &Path::new("/path/to/test_input_file"),
///     &Path::new("/path/to/trace_file.trace"),
/// );
///
/// // With AFL/AFL++, traces would usually be in these dirs:
/// let _afl_trace = trace::load_trace_from_file(
///     "afl_trace",
///     &Path::new("fuzzer_out/queue/id_000000"),
///     &Path::new("fuzzer_out/trace_dumps/id_000000.trace"),
/// );
/// ```
pub fn load_trace_from_file(
    name: &str,
    test_input_file: &Path,
    trace_dump_file: &Path,
) -> Result<Trace, RosaError> {
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
/// let _ = rosa_cli::trace::save_test_input_to_file(&my_trace, &Path::new("/path/to/my_trace"));
/// ```
pub fn save_test_input_to_file(trace: &Trace, output_file: &Path) -> Result<(), RosaError> {
    fs::write(output_file, &trace.test_input).map_err(|err| {
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
/// Just like in [load_trace_from_file], we will maintain the expected format of a binary trace
/// dump:
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
/// let _ = rosa_cli::trace::save_trace_dump_to_file(
///     &my_trace, &Path::new("/path/to/my_trace.trace")
/// );
/// ```
pub fn save_trace_dump_to_file(trace: &Trace, output_file: &Path) -> Result<(), RosaError> {
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
    fs::write(output_file, &output).map_err(|err| {
        error!(
            "could not write trace dump to {}: {}.",
            output_file.display(),
            err
        )
    })?;

    Ok(())
}

/// Load multiple stored traces.
///
/// This function is used to load traces stored after a ROSA campaign, e.g., in the ROSA output
/// directory. It is **not** meant to be used to "hot-load" traces while the fuzzer is running; use
/// [collect_one_trace](crate::fuzzer::FuzzerBackend::collect_one_trace) instead.
///
/// # Examples
/// ```
/// use std::path::Path;
/// use rosa_cli::trace;
///
/// let _traces = trace::load_traces_from_dir(
///     &Path::new("/path/to/rosa-out/traces")
/// );
/// ```
pub fn load_traces_from_dir(traces_dir: &Path) -> Result<Vec<Trace>, RosaError> {
    // Get all files corresponding to test inputs.
    // These are expected to be all files which do not end in `.trace`.
    let test_input_paths: Vec<PathBuf> = fs::read_dir(traces_dir).map_or_else(
        |err| {
            fail!(
                "invalid test input directory '{}': {}.",
                traces_dir.display(),
                err
            )
        },
        |res| {
            Ok(res
                // Ignore files/dirs we cannot read.
                .filter_map(|item| item.ok())
                .map(|item| item.path())
                // Only keep files that do not end in `.trace`.
                // Ignore `README.txt` files (as those are put in the output directories of ROSA by
                // default).
                .filter(|path| {
                    path.is_file()
                        && path
                            .extension()
                            .is_none_or(|extension| extension != "trace")
                        && path
                            .file_name()
                            .expect("could not get file name for potential test input file.")
                            != "README.txt"
                })
                .collect())
        },
    )?;

    test_input_paths
        .into_iter()
        .map(|test_input_path| {
            load_trace_from_file(
                &test_input_path
                    .file_name()
                    .expect("could not get file name for potential test input file.")
                    .to_string_lossy(),
                &test_input_path,
                &test_input_path.with_extension("trace"),
            )
        })
        .collect()
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
/// use rosa::trace::Trace;
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
/// let _ = rosa_cli::trace::save_traces_to_dir(&my_traces, &Path::new("/path/to/traces_dir/"));
/// ```
pub fn save_traces_to_dir(traces: &[Trace], output_dir: &Path) -> Result<(), RosaError> {
    traces.iter().try_for_each(|trace| {
        let base_path = output_dir.join(trace.id());
        save_test_input_to_file(trace, &base_path)
            .and_then(|()| save_trace_dump_to_file(trace, &base_path.with_extension("trace")))
    })
}
