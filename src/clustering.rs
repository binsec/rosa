//! Cluster definitions & algorithms.
//!
//! This module describes trace clusters and provides clustering/cluster similarity algorithms.

use std::{cmp, fs, path::Path};

use crate::{
    criterion::Criterion, distance_metric::DistanceMetric, error::RosaError, trace::Trace,
};

/// A trace cluster, containing similar traces.
#[derive(Clone, Debug)]
pub struct Cluster {
    /// The unique ID of the cluster.
    pub uid: String,
    /// The traces contained in the cluster.
    pub traces: Vec<Trace>,
    /// The minimum internal edge distance (in terms of similarity) between the traces.
    pub min_edge_distance: u64,
    /// The maximum internal edge distance (in terms of similarity) between the traces.
    pub max_edge_distance: u64,
    /// The minimum internal syscall distance (in terms of similarity) between the traces.
    pub min_syscall_distance: u64,
    /// The maximum internal syscall distance (in terms of similarity) between the traces.
    pub max_syscall_distance: u64,
}

/// Get the most similar cluster to a trace, given a collection of clusters.
///
/// The most similar cluster is chosen given a criterion and a distance metric; the distance metric
/// is used to determine similarity, while the criterion is used to decide how similarity will be
/// measured in terms of the components of the traces. See [Criterion] and [DistanceMetric].
///
/// # Arguments
/// * `trace` - The trace for which to get the most similar cluster.
/// * `clusters` - The collection of available clusters to choose from.
/// * `criterion` - The criterion to use.
/// * `distance_metric` - The distance metric to use.
///
/// # Examples
/// ```
/// use rosa::{
///     clustering::{self, Cluster},
///     criterion::Criterion,
///     distance_metric::DistanceMetric,
///     trace::Trace,
/// };
///
/// // Dummy clusters to demonstrate function use.
/// // Test inputs are not taken into account when choosing the most similar cluster. In fact,
/// // we'll only use edges to make the example simpler.
/// let clusters = vec![
///     Cluster {
///         uid: "cluster_1".to_string(),
///         traces: vec![
///             Trace {
///                 name: "trace_1".to_string(),
///                 test_input: vec![],
///                 edges: vec![0, 1, 1, 0],
///                 syscalls: vec![],
///             },
///             Trace {
///                 name: "trace_2".to_string(),
///                 test_input: vec![],
///                 edges: vec![0, 1, 0, 0],
///                 syscalls: vec![],
///             },
///         ],
///         min_edge_distance: 1,
///         max_edge_distance: 1,
///         min_syscall_distance: 0,
///         max_syscall_distance: 0,
///     },
///     Cluster {
///         uid: "cluster_2".to_string(),
///         traces: vec![
///             Trace {
///                 name: "trace_3".to_string(),
///                 test_input: vec![],
///                 edges: vec![0, 0, 1, 1],
///                 syscalls: vec![],
///             },
///             Trace {
///                 name: "trace_4".to_string(),
///                 test_input: vec![],
///                 edges: vec![0, 0, 0, 1],
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
/// // Dummy trace for which to get the most similar cluster. It's identical to `trace_2` in
/// // cluster `cluster_1`.
/// let candidate_trace = Trace {
///     name: "candidate".to_string(),
///     test_input: vec![],
///     edges: vec![0, 1, 0, 0],
///     syscalls: vec![],
/// };
///
/// assert_eq!(
///     clustering::get_most_similar_cluster(
///         &candidate_trace,
///         &clusters,
///         Criterion::EdgesOnly,
///         DistanceMetric::Hamming,
///     ).unwrap().uid,
///     clusters[0].uid,
/// );
/// ```
pub fn get_most_similar_cluster<'a>(
    trace: &Trace,
    clusters: &'a [Cluster],
    criterion: Criterion,
    distance_metric: DistanceMetric,
) -> Option<&'a Cluster> {
    let (_, cluster_index) = clusters.iter().enumerate().fold(
        (u64::MAX, None),
        |(min_distance, cluster_index), (index, cluster)| {
            let min_edge_distance = cluster
                .traces
                .iter()
                .map(|cluster_trace| distance_metric.dist(&trace.edges, &cluster_trace.edges))
                .min();
            let min_syscall_distance = cluster
                .traces
                .iter()
                .map(|cluster_trace| distance_metric.dist(&trace.syscalls, &cluster_trace.syscalls))
                .min();
            let min_combined_distance = cluster
                .traces
                .iter()
                .map(|cluster_trace| {
                    let edge_distance = distance_metric.dist(&trace.edges, &cluster_trace.edges);
                    let syscall_distance =
                        distance_metric.dist(&trace.syscalls, &cluster_trace.syscalls);

                    // Watch out for potential overflow, since we're adding two u64s.
                    // If it does overflow, just return the biggest possible value.
                    edge_distance
                        .checked_add(syscall_distance)
                        .unwrap_or(u64::MAX)
                })
                .min();

            let new_min_distance = match criterion {
                Criterion::EdgesOnly => min_edge_distance,
                Criterion::SyscallsOnly => min_syscall_distance,
                Criterion::EdgesOrSyscalls => match (min_edge_distance, min_syscall_distance) {
                    // Get the proportionally smallest distance.
                    (Some(min_edge_distance), Some(min_syscall_distance)) => Some(f64::min(
                        (min_edge_distance as f64) / (trace.edges.len() as f64),
                        (min_syscall_distance as f64) / (trace.syscalls.len() as f64),
                    )
                        as u64),
                    // If either is None, return the other one (or return None if both are None).
                    (None, dist) | (dist, None) => dist,
                },
                Criterion::EdgesAndSyscalls => min_combined_distance,
            }
            .unwrap_or(u64::MAX);

            if new_min_distance < min_distance {
                (new_min_distance, Some(index))
            } else {
                (min_distance, cluster_index)
            }
        },
    );

    cluster_index.map(|index| &clusters[index])
}

/// Group traces into clusters, based on similarity.
///
/// This is a naive clustering algorithm; it tries to put a trace into the most similar existing
/// cluster if it fits the criterion and the tolerances, otherwise it creates a new cluster
/// containing the trace.
///
/// # Arguments
/// * `traces` - The traces to group into clusters.
/// * `criterion` - The criterion to use.
/// * `distance_metric` - The distance metric to use.
/// * `edge_tolerance` - The tolerance to consider in terms of edges. Essentially, for a tolerance
///   `t`, a difference of up to `t` edges will be tolerated within the same cluster.
/// * `syscall_tolerance` - The tolerance to consider in terms of syscalls. Essentially, for a
///   tolerance `t`, a difference of up to `t` syscalls will be tolerated within the same cluster.
///
/// # Examples
/// ```
/// use rosa::{
///     clustering,
///     criterion::Criterion,
///     distance_metric::DistanceMetric,
///     trace::Trace,
/// };
///
/// // A dummy collection of traces to demonstrate the function.
/// // Test input is not taken into account during clustering so it doesn't matter here.
/// // In fact, to simplify the example, only the edges will be taken into account.
/// let traces = vec![
///     Trace {
///         name: "trace_1".to_string(),
///         test_input: vec![],
///         edges: vec![0, 1, 0, 1],
///         syscalls: vec![],
///     },
///     Trace {
///         name: "trace_2".to_string(),
///         test_input: vec![],
///         edges: vec![0, 1, 0, 0],
///         syscalls: vec![],
///     },
/// ];
///
/// // With zero edge tolerance, the two different traces will be put into two different clusters.
/// let strict_clusters = clustering::cluster_traces(
///     &traces, Criterion::EdgesOnly, DistanceMetric::Hamming, 0, 0
/// );
/// assert_eq!(strict_clusters.len(), 2);
/// assert_eq!(strict_clusters[0].traces.len(), 1);
/// assert_eq!(strict_clusters[1].traces.len(), 1);
/// assert_eq!(strict_clusters[0].traces[0].name, "trace_1".to_string());
/// assert_eq!(strict_clusters[1].traces[0].name, "trace_2".to_string());
///
/// // With some tolerance, both traces will be grouped into the same cluster.
/// let relaxed_clusters = clustering::cluster_traces(
///     &traces, Criterion::EdgesOnly, DistanceMetric::Hamming, 1, 0
/// );
/// assert_eq!(relaxed_clusters.len(), 1);
/// assert_eq!(relaxed_clusters[0].traces.len(), 2);
/// assert_eq!(relaxed_clusters[0].traces[0].name, "trace_1".to_string());
/// assert_eq!(relaxed_clusters[0].traces[1].name, "trace_2".to_string());
/// ```
pub fn cluster_traces(
    traces: &[Trace],
    criterion: Criterion,
    distance_metric: DistanceMetric,
    edge_tolerance: u64,
    syscall_tolerance: u64,
) -> Vec<Cluster> {
    traces.iter().fold(Vec::new(), |mut clusters, trace| {
        let result = get_most_similar_cluster(trace, &clusters, criterion, distance_metric).map(
            |most_similar_cluster| {
                let max_edge_distance = most_similar_cluster
                    .traces
                    .iter()
                    .map(|cluster_trace| distance_metric.dist(&trace.edges, &cluster_trace.edges))
                    .max()
                    .expect(
                        "failed to get max edge distance between trace and most similar cluster.",
                    );
                let max_syscall_distance = most_similar_cluster
                    .traces
                    .iter()
                    .map(|cluster_trace| {
                        distance_metric.dist(&trace.syscalls, &cluster_trace.syscalls)
                    })
                    .max()
                    .expect(
                        "failed to get max syscall distance between trace and most similar\
                        cluster.",
                    );

                let edge_criterion = max_edge_distance <= most_similar_cluster.min_edge_distance;
                let syscall_criterion =
                    max_syscall_distance <= most_similar_cluster.min_syscall_distance;

                let cluster_matches = match criterion {
                    Criterion::EdgesOnly => edge_criterion,
                    Criterion::SyscallsOnly => syscall_criterion,
                    Criterion::EdgesOrSyscalls => edge_criterion || syscall_criterion,
                    Criterion::EdgesAndSyscalls => edge_criterion && syscall_criterion,
                };

                (
                    cluster_matches.then_some(
                        clusters
                            .iter()
                            .position(|c| c.uid == most_similar_cluster.uid)
                            .expect("failed to get index of matching cluster."),
                    ),
                    max_edge_distance,
                    max_syscall_distance,
                )
            },
        );

        match result {
            Some((Some(cluster_index), trace_max_edge_distance, trace_max_syscall_distance)) => {
                // A cluster was found that fulfills the criteria needed to integrate the trace.
                let matching_cluster = &mut clusters[cluster_index];

                matching_cluster.traces.push(trace.clone());

                // Make sure to update the minimum/maximum distances of the cluster.
                matching_cluster.min_edge_distance = cmp::min(
                    matching_cluster.min_edge_distance,
                    // Make sure to not go lower than the specified tolerance.
                    cmp::max(trace_max_edge_distance, edge_tolerance),
                );
                matching_cluster.max_edge_distance =
                    cmp::max(matching_cluster.max_edge_distance, trace_max_edge_distance);

                matching_cluster.min_syscall_distance = cmp::min(
                    matching_cluster.min_syscall_distance,
                    // Make sure to not go lower than the specified tolerance.
                    cmp::max(trace_max_syscall_distance, syscall_tolerance),
                );
                matching_cluster.max_syscall_distance = cmp::max(
                    matching_cluster.max_syscall_distance,
                    trace_max_syscall_distance,
                );
            }
            Some((None, _, _)) | None => {
                // Either no cluster was found (because none exist) or the one that was found
                // didn't match; either way, we have to create a new cluster for the trace.
                clusters.push(Cluster {
                    uid: format!("cluster_{:0>6}", clusters.len()),
                    traces: vec![trace.clone()],
                    min_edge_distance: edge_tolerance,
                    max_edge_distance: edge_tolerance,
                    min_syscall_distance: syscall_tolerance,
                    max_syscall_distance: syscall_tolerance,
                });
            }
        }

        clusters
    })
}

/// Save clusters to file.
///
/// This function provides a way to dump clusters into `.txt` files in order to understand which
/// trace is in which cluster. Each cluster file is a simple `.txt` file, containing the UIDs of
/// all the traces within the cluster, with one UID per line.
///
/// # Arguments
/// * `clusters` - The clusters to save.
/// * `output_dir` - The directory in which to save the clusters. One file will be created per
///   cluster; the file's name will be the cluster's UID.
///
/// # Examples
/// ```
/// use std::path::Path;
/// use rosa::{
///     clustering::{self, Cluster},
///     trace::Trace,
/// };
///
/// // Dummy clusters to demonstrate function use.
/// let clusters = vec![
///     Cluster {
///         uid: "cluster_1".to_string(),
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
/// let _ = clustering::save_clusters(&clusters, &Path::new("/path/to/clusters_dir/"));
/// ```
pub fn save_clusters(clusters: &[Cluster], output_dir: &Path) -> Result<(), RosaError> {
    clusters.iter().try_for_each(|cluster| {
        let trace_uids: Vec<String> = cluster.traces.iter().map(|trace| trace.uid()).collect();
        let cluster_file = output_dir.join(&cluster.uid).with_extension("txt");
        fs::write(&cluster_file, format!("{}\n", trace_uids.join("\n"))).map_err(|err| {
            error!(
                "could not save cluster to file {}: {}.",
                cluster_file.display(),
                err
            )
        })
    })
}
