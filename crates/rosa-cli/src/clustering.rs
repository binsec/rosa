//! TODO: doc

use std::{fs, path::Path};

use rosa_core::{clustering::Cluster, error, error::RosaError, trace::Trace};

use crate::trace::load_trace_from_file;

/// Load a cluster from a cluster file.
///
/// Note that the min/max edge/syscall distances are all set to zero and may not be accurate.
/// If they are needed, they should be recomputed from scratch after loading.
pub fn load_cluster_from_file(file: &Path, traces_dir: &Path) -> Result<Cluster, RosaError> {
    let id = file
        .with_extension("")
        .file_name()
        .expect("failed to get name of cluster file.")
        .to_str()
        .expect("failed to convert cluster file name to string.")
        .to_string();
    let traces = fs::read_to_string(file)
        .map_err(|err| error!("could not read cluster file '{}': {}.", file.display(), err))?
        .split('\n')
        .filter(|line| !line.is_empty())
        .map(|trace_id| {
            load_trace_from_file(
                trace_id,
                &traces_dir.join(trace_id),
                &traces_dir.join(trace_id).with_extension("trace"),
            )
        })
        .collect::<Result<Vec<Trace>, RosaError>>()?;

    // We should always have at least one trace per cluster.
    assert!(!traces.is_empty());

    Ok(Cluster {
        id,
        traces,
        min_edge_distance: 0,
        max_edge_distance: 0,
        min_syscall_distance: 0,
        max_syscall_distance: 0,
    })
}

/// Save the cluster to a file.
///
/// The cluster is saved in a very simple textual form, with the IDs of its traces, each on a
/// separate line.
pub fn save_cluster_to_file(cluster: &Cluster, file: &Path) -> Result<(), RosaError> {
    let trace_ids: Vec<String> = cluster.traces.iter().map(|trace| trace.id()).collect();
    fs::write(file, format!("{}\n", trace_ids.join("\n"))).map_err(|err| {
        error!(
            "could not save cluster to file {}: {}.",
            file.display(),
            err
        )
    })
}

/// Save clusters to file.
///
/// This function provides a way to dump clusters into `.txt` files in order to understand which
/// trace is in which cluster. Each cluster file is a simple `.txt` file, containing the IDs of
/// all the traces within the cluster, with one ID per line.
///
/// # Examples
/// ```
/// use std::path::Path;
/// use rosa_core::{
///     clustering::Cluster,
///     trace::Trace,
/// };
///
/// // Dummy clusters to demonstrate function use.
/// let clusters = vec![
///     Cluster {
///         id: "cluster_1".to_string(),
///         traces: vec![
///             Trace {
///                 name: "trace_1".to_string(),
///                 test_input: vec![],
///                 edges: vec![],
///                 syscalls: vec![],
///             },
///             Trace {
///                 name: "trace_2".to_string(),
///                 test_input: vec![],
///                 edges: vec![],
///                 syscalls: vec![],
///             },
///         ],
///         min_edge_distance: 1,
///         max_edge_distance: 1,
///         min_syscall_distance: 0,
///         max_syscall_distance: 0,
///     },
/// ];
///
/// let _ = rosa_cli::clustering::save_clusters_to_dir(
///     &clusters, &Path::new("/path/to/clusters_dir/")
/// );
/// ```
pub fn save_clusters_to_dir(clusters: &[Cluster], output_dir: &Path) -> Result<(), RosaError> {
    clusters.iter().try_for_each(|cluster| {
        let cluster_file = output_dir.join(&cluster.id).with_extension("txt");
        save_cluster_to_file(cluster, &cluster_file)
    })
}
