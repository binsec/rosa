use std::{cmp, fs, path::PathBuf};

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

    cluster_index.and_then(|index| Some(&clusters[index]))
}

pub fn cluster_traces(
    traces: &[Trace],
    criterion: Criterion,
    distance_metric: DistanceMetric,
    edge_tolerance: u64,
    syscall_tolerance: u64,
) -> Vec<Cluster> {
    traces.iter().fold(Vec::new(), |mut clusters, trace| {
        let result = get_most_similar_cluster(&trace, &clusters, criterion, distance_metric).map(
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

pub fn save_clusters(clusters: &[Cluster], output_dir: &PathBuf) -> Result<(), RosaError> {
    clusters.iter().try_for_each(|cluster| {
        let trace_uids: Vec<&str> = cluster
            .traces
            .iter()
            .map(|trace| trace.uid.as_ref())
            .collect();
        let cluster_file = output_dir.join(&cluster.uid).with_extension("txt");
        fs::write(&cluster_file, format!("{}\n", trace_uids.join("\n"))).or_else(|err| {
            fail!(
                "could not save cluster to file {}: {}.",
                cluster_file.display(),
                err
            )
        })
    })
}
