use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use crate::error::RosaError;

/// Runtime trace definition.
#[derive(Debug, Clone)]
pub struct Trace {
    /// The unique ID of the trace.
    pub uid: String,
    /// The test input associated with the trace.
    pub test_input: Vec<u8>,
    /// The edges found in the trace (existential vector).
    pub edges: Vec<u8>,
    /// The syscalls found in the trace (existential vector).
    pub syscalls: Vec<u8>,
}

impl Trace {
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

pub fn load_traces(
    test_input_dir: &Path,
    trace_dump_dir: &Path,
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
            match trace_dump_file.is_file() {
                true => {
                    let trace = Trace::load(&trace_uid, &test_input_file, &trace_dump_file)?;
                    // If load was successful, log the trace as a known trace.
                    known_traces.insert(trace_uid.to_string(), trace.clone());

                    Ok(trace)
                }
                false => {
                    fail!("missing trace dump file for trace '{}'.", trace_uid)
                }
            }
        })
        .collect()
}

pub fn save_traces(traces: &[Trace], output_dir: &Path) -> Result<(), RosaError> {
    traces.iter().try_for_each(|trace| {
        save_trace_test_input(trace, output_dir).and_then(|()| save_trace_dump(trace, output_dir))
    })
}

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

fn save_trace_dump(trace: &Trace, output_dir: &Path) -> Result<(), RosaError> {
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
