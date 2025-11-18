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

impl Cluster {
    /// Load a cluster from a cluster file.
    ///
    /// Note that the min/max edge/syscall distances are all set to zero and may not be accurate.
    /// If they are needed, they should be recomputed from scratch after loading.
    pub fn load(file: &Path, traces_dir: &Path) -> Result<Self, RosaError> {
        let uid = file
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
            .map(|trace_uid| {
                Trace::load(
                    trace_uid,
                    &traces_dir.join(trace_uid),
                    &traces_dir.join(trace_uid).with_extension("trace"),
                )
            })
            .collect::<Result<Vec<Trace>, RosaError>>()?;

        // We should always have at least one trace per cluster.
        assert!(!traces.is_empty());

        Ok(Self {
            uid,
            traces,
            min_edge_distance: 0,
            max_edge_distance: 0,
            min_syscall_distance: 0,
            max_syscall_distance: 0,
        })
    }

    /// Save the cluster to a file.
    ///
    /// The cluster is saved in a very simple textual form, with the UIDs of its traces, each on a
    /// separate line.
    pub fn save(&self, file: &Path) -> Result<(), RosaError> {
        let trace_uids: Vec<String> = self.traces.iter().map(|trace| trace.uid()).collect();
        fs::write(file, format!("{}\n", trace_uids.join("\n"))).map_err(|err| {
            error!(
                "could not save cluster to file {}: {}.",
                file.display(),
                err
            )
        })
    }
}

/// Get the most similar cluster to a trace, given a collection of clusters.
///
/// The most similar cluster is chosen given a criterion and a distance metric; the distance metric
/// is used to determine similarity, while the criterion is used to decide how similarity will be
/// measured in terms of the components of the traces. See [Criterion] and [DistanceMetric].
///
/// # Examples
/// ```
/// use rosa::{
///     clustering::{self, Cluster},
///     criterion::Criterion,
///     distance_metric::hamming::Hamming,
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
///     name: "candidate".to_string(), test_input: vec![],
///     edges: vec![0, 1, 0, 0],
///     syscalls: vec![],
/// };
///
/// assert_eq!(
///     clustering::get_most_similar_cluster(
///         &candidate_trace,
///         &clusters,
///         Criterion::EdgesOnly,
///         Box::new(Hamming),
///     ).expect("failed to get most similar cluster").uid,
///     clusters[0].uid,
/// );
/// ```
pub fn get_most_similar_cluster<'a>(
    trace: &Trace,
    clusters: &'a [Cluster],
    criterion: Criterion,
    distance_metric: Box<dyn DistanceMetric>,
) -> Option<&'a Cluster> {
    // The `min_distance` here has two components, to account for all possible criteria.
    // In most cases (i.e., everything besides [Criterion::EdgesAndSyscalls]) only the first
    // component matters, as we are only taking a single metric into account.
    // However, when using [Criterion::EdgesAndSyscalls], we want to minimize *both* edge and
    // system call distance (with edge distance taking priority). Hence, we use the second
    // component to keep track of the "secondary"/tiebreaker metric which is syscall distance.
    let (_, cluster_index) = clusters.iter().enumerate().fold(
        ((u64::MAX, u64::MAX), None),
        |(min_distance, cluster_index), (index, cluster)| {
            let min_edge_distance = cluster
                .traces
                .iter()
                .map(|cluster_trace| distance_metric.distance(&trace.edges, &cluster_trace.edges))
                .min();
            let min_syscall_distance = cluster
                .traces
                .iter()
                .map(|cluster_trace| {
                    distance_metric.distance(&trace.syscalls, &cluster_trace.syscalls)
                })
                .min();

            let new_min_distance = match criterion {
                Criterion::EdgesOnly => (min_edge_distance.unwrap_or(u64::MAX), u64::MAX),
                Criterion::SyscallsOnly => (min_syscall_distance.unwrap_or(u64::MAX), u64::MAX),
                Criterion::EdgesOrSyscalls => match (min_edge_distance, min_syscall_distance) {
                    // Get the objectively smallest distance.
                    (Some(min_edge_distance), Some(min_syscall_distance)) => {
                        (cmp::min(min_edge_distance, min_syscall_distance), u64::MAX)
                    }
                    // If either is None, return the other one (or unwrap).
                    (None, dist) | (dist, None) => (dist.unwrap_or(u64::MAX), u64::MAX),
                },
                Criterion::EdgesAndSyscalls => {
                    // If there are multiple traces with the minimum edge distance, get the one
                    // that also has minimum syscall distance.
                    let new_min_edge_distance = min_edge_distance.unwrap_or(u64::MAX);
                    let new_min_syscall_distance = cluster
                        .traces
                        .iter()
                        .filter(|cluster_trace| {
                            distance_metric.distance(&trace.edges, &cluster_trace.edges)
                                == new_min_edge_distance
                        })
                        .map(|cluster_trace| {
                            distance_metric.distance(&trace.syscalls, &cluster_trace.syscalls)
                        })
                        .min()
                        .unwrap_or(u64::MAX);

                    (new_min_edge_distance, new_min_syscall_distance)
                }
            };

            if (new_min_distance.0 < min_distance.0)
                || (new_min_distance.0 == min_distance.0 && new_min_distance.1 < min_distance.1)
            {
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
/// # Examples
/// ```
/// use rosa::{
///     clustering,
///     criterion::Criterion,
///     distance_metric::hamming::Hamming,
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
///     &traces, Criterion::EdgesOnly, Box::new(Hamming), 0, 0
/// );
/// assert_eq!(strict_clusters.len(), 2);
/// assert_eq!(strict_clusters[0].traces.len(), 1);
/// assert_eq!(strict_clusters[1].traces.len(), 1);
/// assert_eq!(strict_clusters[0].traces[0].name, "trace_1".to_string());
/// assert_eq!(strict_clusters[1].traces[0].name, "trace_2".to_string());
///
/// // With some tolerance, both traces will be grouped into the same cluster.
/// let relaxed_clusters = clustering::cluster_traces(
///     &traces, Criterion::EdgesOnly, Box::new(Hamming), 1, 0
/// );
/// assert_eq!(relaxed_clusters.len(), 1);
/// assert_eq!(relaxed_clusters[0].traces.len(), 2);
/// assert_eq!(relaxed_clusters[0].traces[0].name, "trace_1".to_string());
/// assert_eq!(relaxed_clusters[0].traces[1].name, "trace_2".to_string());
/// ```
pub fn cluster_traces(
    traces: &[Trace],
    criterion: Criterion,
    distance_metric: Box<dyn DistanceMetric>,
    edge_tolerance: u64,
    syscall_tolerance: u64,
) -> Vec<Cluster> {
    match (edge_tolerance, syscall_tolerance, criterion) {
        // If both tolerances are 0, and we care about edges, we will never be able to put two
        // traces in the same cluster. This is because we only keep traces that have unique edge
        // vectors. It's worth it to simply create the corresponding clusters here, as it's much
        // faster.
        (0, 0, Criterion::EdgesAndSyscalls) | (0, 0, Criterion::EdgesOnly) => traces
            .iter()
            .enumerate()
            .map(|(index, trace)| Cluster {
                uid: format!("cluster_{:0>6}", index),
                traces: vec![trace.clone()],
                min_edge_distance: edge_tolerance,
                max_edge_distance: edge_tolerance,
                min_syscall_distance: syscall_tolerance,
                max_syscall_distance: syscall_tolerance,
            })
            .collect(),
        // In the general case, we cannot optimize, so we have to go through the full clustering
        // algorithm.
        _ => traces.iter().fold(Vec::new(), |mut clusters, trace| {
            let result =
                get_most_similar_cluster(trace, &clusters, criterion, distance_metric.clone()).map(
                    |most_similar_cluster| {
                        let max_edge_distance = most_similar_cluster
                    .traces
                    .iter()
                    .map(|cluster_trace| {
                        distance_metric.distance(&trace.edges, &cluster_trace.edges)
                    })
                    .max()
                    .expect(
                        "failed to get max edge distance between trace and most similar cluster.",
                    );
                        let max_syscall_distance = most_similar_cluster
                            .traces
                            .iter()
                            .map(|cluster_trace| {
                                distance_metric.distance(&trace.syscalls, &cluster_trace.syscalls)
                            })
                            .max()
                            .expect(
                                "failed to get max syscall distance between trace and most similar\
                                cluster.",
                            );

                        let edge_criterion =
                            max_edge_distance <= most_similar_cluster.min_edge_distance;
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
                Some((
                    Some(cluster_index),
                    trace_max_edge_distance,
                    trace_max_syscall_distance,
                )) => {
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
        }),
    }
}

/// Save clusters to file.
///
/// This function provides a way to dump clusters into `.txt` files in order to understand which
/// trace is in which cluster. Each cluster file is a simple `.txt` file, containing the UIDs of
/// all the traces within the cluster, with one UID per line.
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
        let cluster_file = output_dir.join(&cluster.uid).with_extension("txt");
        cluster.save(&cluster_file)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distance_metric::hamming::Hamming;

    #[test]
    fn same_cluster_syscall_diffs() {
        let phase_one_traces = vec![
            Trace {
                name: "trace_1".to_string(),
                test_input: Vec::new(),
                edges: vec![1, 0, 1, 0],
                syscalls: vec![1, 0, 1],
            },
            Trace {
                name: "trace_2".to_string(),
                test_input: Vec::new(),
                edges: vec![1, 1, 1, 0],
                syscalls: vec![1, 1, 0],
            },
            Trace {
                name: "trace_3".to_string(),
                test_input: Vec::new(),
                edges: vec![0, 1, 1, 0],
                syscalls: vec![0, 1, 1],
            },
            Trace {
                name: "trace_4".to_string(),
                test_input: Vec::new(),
                edges: vec![1, 0, 0, 0],
                syscalls: vec![1, 1, 1],
            },
        ];

        let clusters = cluster_traces(
            &phase_one_traces,
            Criterion::EdgesOnly,
            Box::new(Hamming),
            0,
            0,
        );

        assert_eq!(clusters.len(), 4);
        assert_eq!(clusters[0].traces.len(), 1);
        assert_eq!(clusters[0].traces[0].name, "trace_1".to_string());
        assert_eq!(clusters[1].traces.len(), 1);
        assert_eq!(clusters[1].traces[0].name, "trace_2".to_string());
        assert_eq!(clusters[2].traces.len(), 1);
        assert_eq!(clusters[2].traces[0].name, "trace_3".to_string());
        assert_eq!(clusters[3].traces.len(), 1);
        assert_eq!(clusters[3].traces[0].name, "trace_4".to_string());

        let new_trace = Trace {
            name: "trace_5".to_string(),
            test_input: Vec::new(),
            edges: vec![1, 1, 1, 1],
            syscalls: vec![1, 1, 1],
        };

        let most_similar_cluster = get_most_similar_cluster(
            &new_trace,
            &clusters,
            Criterion::EdgesAndSyscalls,
            Box::new(Hamming),
        )
        .unwrap();
        assert_eq!(most_similar_cluster.traces.len(), 1);
        assert_eq!(most_similar_cluster.traces[0].name, "trace_2".to_string());
    }

    #[test]
    fn same_cluster_edge_diffs() {
        let phase_one_traces = vec![
            Trace {
                name: "trace_1".to_string(),
                test_input: Vec::new(),
                edges: vec![1, 0, 1, 0],
                syscalls: vec![1, 0, 1],
            },
            Trace {
                name: "trace_2".to_string(),
                test_input: Vec::new(),
                edges: vec![1, 1, 0, 0],
                syscalls: vec![1, 1, 0],
            },
            Trace {
                name: "trace_3".to_string(),
                test_input: Vec::new(),
                edges: vec![0, 1, 1, 0],
                syscalls: vec![1, 1, 1],
            },
            Trace {
                name: "trace_4".to_string(),
                test_input: Vec::new(),
                edges: vec![1, 0, 0, 0],
                syscalls: vec![1, 1, 1],
            },
        ];

        let clusters = cluster_traces(
            &phase_one_traces,
            Criterion::EdgesOnly,
            Box::new(Hamming),
            0,
            0,
        );

        assert_eq!(clusters.len(), 4);
        assert_eq!(clusters[0].traces.len(), 1);
        assert_eq!(clusters[0].traces[0].name, "trace_1".to_string());
        assert_eq!(clusters[1].traces.len(), 1);
        assert_eq!(clusters[1].traces[0].name, "trace_2".to_string());
        assert_eq!(clusters[2].traces.len(), 1);
        assert_eq!(clusters[2].traces[0].name, "trace_3".to_string());
        assert_eq!(clusters[3].traces.len(), 1);
        assert_eq!(clusters[3].traces[0].name, "trace_4".to_string());

        let new_trace = Trace {
            name: "trace_5".to_string(),
            test_input: Vec::new(),
            edges: vec![1, 1, 1, 1],
            syscalls: vec![1, 1, 1],
        };

        let most_similar_cluster = get_most_similar_cluster(
            &new_trace,
            &clusters,
            Criterion::EdgesAndSyscalls,
            Box::new(Hamming),
        )
        .unwrap();
        assert_eq!(most_similar_cluster.traces.len(), 1);
        assert_eq!(most_similar_cluster.traces[0].name, "trace_3".to_string());
    }
}
