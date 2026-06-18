//! Cluster definitions & algorithms.
//!
//! This module describes trace clusters and provides clustering/cluster similarity algorithms.

use std::{cmp, slice};

use itertools::Itertools;

use crate::{
    criterion::Criterion, distance_metric::DistanceMetric, error::RosaError, trace::Trace,
};

/// A trace cluster, containing similar traces.
#[derive(Clone, Debug)]
pub struct Cluster {
    /// The name of the cluster.
    name: String,
    /// The traces contained in the cluster.
    traces: Vec<Trace>,
}

impl Cluster {
    /// Build a new cluster given a set of traces.
    ///
    /// If the traces are not uniform (i.e., having edge and syscall vectors of the same size),
    /// then an [Err] is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use rosa_core::{
    ///     trace::Trace,
    ///     clustering::Cluster,
    /// };
    ///
    /// let traces = [
    ///     Trace::build("trace_1", &[0x01, 0x02], &[0, 1], 3, &[1, 0], 2).unwrap(),
    ///     Trace::build("trace_2", &[0x03, 0x04], &[1, 0], 3, &[0, 1], 2).unwrap(),
    /// ];
    ///
    /// let cluster = Cluster::build("my_cluster", &traces).unwrap();
    /// assert_eq!(cluster.traces().len(), 2);
    /// assert_eq!(cluster.shape(), Some((3, 2)));
    ///
    /// // All traces must have the same shape (i.e., edge and syscall sizes).
    /// let traces = [
    ///     Trace::build("trace_1", &[0x01, 0x02], &[0, 1], 3, &[1, 0], 2).unwrap(),
    ///     Trace::build("trace_2", &[0x03, 0x04], &[1, 0], 2, &[0, 1], 2).unwrap(),
    /// ];
    /// assert_eq!(
    ///     Cluster::build("my_cluster", &traces).unwrap_err().message,
    ///     format!(
    ///         "cluster my_cluster: trace {} has shape (3, 2) but trace {} has shape (2, 2).",
    ///         traces[0].id(),
    ///         traces[1].id(),
    ///     ),
    /// );
    /// ```
    pub fn build(name: &str, traces: &[Trace]) -> Result<Self, RosaError> {
        // Ensure that all traces have the same shape.
        //
        // Note that we do not have to check if they are non-empty, since [Trace::build] checks
        // that by construction.
        if let Some(first_trace) = traces.first() {
            let first_trace_shape = first_trace.shape();

            traces.iter().try_for_each(|trace| {
                let trace_shape = trace.shape();

                (first_trace_shape == trace_shape)
                    .then_some(())
                    .ok_or(error!(
                        "cluster {}: trace {} has shape ({}, {}) but trace {} has shape ({}, {}).",
                        name,
                        first_trace.id(),
                        first_trace_shape.0,
                        first_trace_shape.1,
                        trace.id(),
                        trace_shape.0,
                        trace_shape.1
                    ))
            })?;
        }

        Ok(Self {
            name: name.to_string(),
            traces: traces.to_vec(),
        })
    }

    /// Get the ID of the cluster.
    pub fn id(&self) -> String {
        self.name.clone()
    }

    /// Get the traces of the cluster.
    pub fn traces(&self) -> &[Trace] {
        &self.traces
    }

    /// Get the shape of the cluster.
    ///
    /// The shape is the tuple `(edge_len, syscall_len)`.
    pub fn shape(&self) -> Option<(usize, usize)> {
        // Since [Self::build] guarantees that all traces have the same shape by construction, we
        // can just fetch the shape of the first trace.
        self.traces.first().map(|trace| trace.shape())
    }

    /// Get the edge distances of all combinations of traces in the cluster.
    ///
    /// # Examples
    ///
    /// ```
    /// use rosa_core::{
    ///     clustering::Cluster,
    ///     trace::Trace,
    ///     distance_metric::hamming::Hamming,
    /// };
    ///
    /// let cluster = Cluster::build(
    ///     "my_cluster",
    ///     &[
    ///         Trace::build_with_vectors(
    ///             "trace_1",
    ///             &[],
    ///             &[0, 1, 1, 0],
    ///             &[1, 0, 0, 0],
    ///         ).unwrap(),
    ///         Trace::build_with_vectors(
    ///             "trace_2",
    ///             &[],
    ///             &[0, 1, 1, 1],
    ///             &[1, 0, 1, 0],
    ///         ).unwrap(),
    ///         Trace::build_with_vectors(
    ///             "trace_3",
    ///             &[],
    ///             &[0, 0, 0, 1],
    ///             &[0, 0, 1, 0],
    ///         ).unwrap(),
    ///     ]
    /// ).unwrap();
    ///
    /// assert_eq!(
    ///     cluster.edge_distances(&Hamming),
    ///     vec![1, 3, 2],
    /// );
    /// ```
    ///
    /// # Safety
    ///
    /// [Itertools::combinations] is used to get all unique **pairs** of traces. If the number of
    /// traces is below 2, then this method returns an empty vector. Otherwise, the
    /// [Itertools::combinations] iterator returns a vector element for each pair, where the vector
    /// is expected to contain two elements. This method asserts this via `.expect()`.
    pub fn edge_distances(&self, distance_metric: &impl DistanceMetric) -> Vec<u64> {
        self.traces
            .iter()
            .combinations(2)
            .map(|traces| {
                // See method documentation. `Itertools::combinations(2)` should be guaranteed to
                // give us a `Vec<>` with 2 elements.
                let [trace1, trace2] = traces.as_slice() else {
                    unreachable!("Itertools::combinations(2) should yield Vec<> of size 2");
                };

                distance_metric.distance(trace1.edges(), trace2.edges())
            })
            .collect()
    }

    /// Get the syscall distances of all combinations of traces in the cluster.
    ///
    /// # Examples
    ///
    /// ```
    /// use rosa_core::{
    ///     clustering::Cluster,
    ///     trace::Trace,
    ///     distance_metric::hamming::Hamming,
    /// };
    ///
    /// let cluster = Cluster::build(
    ///     "my_cluster",
    ///     &[
    ///         Trace::build_with_vectors(
    ///             "trace_1",
    ///             &[],
    ///             &[0, 1, 1, 0],
    ///             &[1, 0, 0, 0],
    ///         ).unwrap(),
    ///         Trace::build_with_vectors(
    ///             "trace_2",
    ///             &[],
    ///             &[0, 1, 1, 1],
    ///             &[1, 0, 1, 0],
    ///         ).unwrap(),
    ///         Trace::build_with_vectors(
    ///             "trace_3",
    ///             &[],
    ///             &[0, 0, 0, 1],
    ///             &[0, 0, 1, 0],
    ///         ).unwrap(),
    ///     ]
    /// ).unwrap();
    ///
    /// assert_eq!(
    ///     cluster.syscall_distances(&Hamming),
    ///     vec![1, 2, 1],
    /// );
    /// ```
    ///
    /// # Safety
    ///
    /// [Itertools::combinations] is used to get all unique **pairs** of traces. If the number of
    /// traces is below 2, then this method returns an empty vector. Otherwise, the
    /// [Itertools::combinations] iterator returns a vector element for each pair, where the vector
    /// is expected to contain two elements. This method asserts this via `.expect()`.
    pub fn syscall_distances(&self, distance_metric: &impl DistanceMetric) -> Vec<u64> {
        self.traces
            .iter()
            .combinations(2)
            .map(|traces| {
                // See method documentation. `Itertools::combinations(2)` should be guaranteed to
                // give us a `Vec<>` with 2 elements.
                let [trace1, trace2] = traces.as_slice() else {
                    unreachable!("Itertools::combinations(2) should yield Vec<> of size 2");
                };

                distance_metric.distance(trace1.syscalls(), trace2.syscalls())
            })
            .collect()
    }

    /// Get the minimum edge-wise distance between traces of the cluster.
    ///
    /// If there are less than 2 traces in the cluster, the minimum distance is defined to be 0.
    pub fn min_edge_distance(&self, distance_metric: &impl DistanceMetric) -> u64 {
        self.edge_distances(distance_metric)
            .into_iter()
            .min()
            .unwrap_or(0)
    }

    /// Get the maximum edge-wise distance between traces of the cluster.
    ///
    /// If there are less than 2 traces in the cluster, the maximum distance is defined to be 0.
    pub fn max_edge_distance(&self, distance_metric: &impl DistanceMetric) -> u64 {
        self.edge_distances(distance_metric)
            .into_iter()
            .max()
            .unwrap_or(0)
    }

    /// Get the minimum syscall-wise distance between traces of the cluster.
    ///
    /// If there are less than 2 traces in the cluster, the minimum distance is defined to be 0.
    pub fn min_syscall_distance(&self, distance_metric: &impl DistanceMetric) -> u64 {
        self.syscall_distances(distance_metric)
            .into_iter()
            .min()
            .unwrap_or(0)
    }

    /// Get the maximum syscall-wise distance between traces of the cluster.
    ///
    /// If there are less than 2 traces in the cluster, the maximum distance is defined to be 0.
    pub fn max_syscall_distance(&self, distance_metric: &impl DistanceMetric) -> u64 {
        self.syscall_distances(distance_metric)
            .into_iter()
            .max()
            .unwrap_or(0)
    }
}

/// Get the most similar cluster to a trace, given a collection of clusters.
///
/// The most similar cluster is chosen given a criterion and a distance metric; the distance metric
/// is used to determine similarity, while the criterion is used to decide how similarity will be
/// measured in terms of the components of the traces. See [Criterion] and [DistanceMetric].
///
/// # Examples
///
/// ```
/// use rosa_core::{
///     clustering::{self, Cluster},
///     criterion::Criterion,
///     distance_metric::hamming::Hamming,
///     trace::Trace,
/// };
///
/// // Dummy clusters to demonstrate function use.
/// // Test inputs are not taken into account when choosing the most similar cluster.
/// let clusters = vec![
///     Cluster::build(
///         "cluster_1",
///         &[
///             Trace::build_with_vectors(
///                 "trace_1",
///                 &[],
///                 &[0, 1, 1, 0],
///                 &[0, 1],
///             ).unwrap(),
///             Trace::build_with_vectors(
///                 "trace_2",
///                 &[],
///                 &[0, 1, 0, 0],
///                 &[1, 0],
///             ).unwrap(),
///         ],
///     ).unwrap(),
///     Cluster::build(
///         "cluster_2",
///         &[
///             Trace::build_with_vectors(
///                 "trace_3",
///                 &[],
///                 &[0, 0, 1, 1],
///                 &[0, 1],
///             ).unwrap(),
///             Trace::build_with_vectors(
///                 "trace_4",
///                 &[],
///                 &[0, 0, 0, 1],
///                 &[1, 0],
///             ).unwrap(),
///         ],
///     ).unwrap(),
/// ];
///
/// // Dummy trace for which to get the most similar cluster. It's identical to `trace_2` in
/// // cluster `cluster_1`.
/// let candidate_trace = Trace::build_with_vectors(
///     "candidate",
///     &[],
///     &[0, 1, 0, 0],
///     &[1, 0],
/// ).unwrap();
///
/// assert_eq!(
///     clustering::get_most_similar_cluster(
///         &candidate_trace,
///         &clusters,
///         Criterion::EdgesOnly,
///         Hamming,
///     ).expect("failed to get most similar cluster").id(),
///     clusters[0].id(),
/// );
/// ```
pub fn get_most_similar_cluster<'a, DM>(
    trace: &Trace,
    clusters: &'a [Cluster],
    criterion: Criterion,
    distance_metric: DM,
) -> Option<&'a Cluster>
where
    DM: DistanceMetric,
{
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
                .map(|cluster_trace| distance_metric.distance(trace.edges(), cluster_trace.edges()))
                .min();
            let min_syscall_distance = cluster
                .traces
                .iter()
                .map(|cluster_trace| {
                    distance_metric.distance(trace.syscalls(), cluster_trace.syscalls())
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
                            distance_metric.distance(trace.edges(), cluster_trace.edges())
                                == new_min_edge_distance
                        })
                        .map(|cluster_trace| {
                            distance_metric.distance(trace.syscalls(), cluster_trace.syscalls())
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
///
/// ```
/// use rosa_core::{
///     clustering,
///     criterion::Criterion,
///     distance_metric::hamming::Hamming,
///     trace::Trace,
/// };
///
/// // A dummy collection of traces to demonstrate the function.
/// // Test input is not taken into account during clustering so it doesn't matter here.
/// let traces = vec![
///     Trace::build_with_vectors(
///         "trace_1",
///         &[],
///         &[0, 1, 0, 1],
///         &[0, 1],
///     ).unwrap(),
///     Trace::build_with_vectors(
///         "trace_2",
///         &[],
///         &[0, 1, 0, 0],
///         &[1, 0],
///     ).unwrap(),
/// ];
///
/// // With zero edge tolerance, the two different traces will be put into two different clusters.
/// let strict_clusters = clustering::cluster_traces(
///     &traces, Criterion::EdgesOnly, Hamming, 0, 0
/// ).unwrap();
/// assert_eq!(strict_clusters.len(), 2);
/// assert_eq!(strict_clusters[0].traces().len(), 1);
/// assert_eq!(strict_clusters[1].traces().len(), 1);
/// assert_eq!(strict_clusters[0].traces()[0].name(), "trace_1");
/// assert_eq!(strict_clusters[1].traces()[0].name(), "trace_2");
/// // Both edge and system call minimum distances should be 0 within each cluster, since each
/// // cluster only contains one trace.
/// assert_eq!(strict_clusters[0].min_edge_distance(&Hamming), 0);
/// assert_eq!(strict_clusters[0].min_syscall_distance(&Hamming), 0);
/// assert_eq!(strict_clusters[1].min_edge_distance(&Hamming), 0);
/// assert_eq!(strict_clusters[1].min_syscall_distance(&Hamming), 0);
///
/// // With some tolerance, both traces will be grouped into the same cluster.
/// let relaxed_clusters = clustering::cluster_traces(
///     &traces, Criterion::EdgesOnly, Hamming, 1, 0
/// ).unwrap();
/// assert_eq!(relaxed_clusters.len(), 1);
/// assert_eq!(relaxed_clusters[0].traces().len(), 2);
/// assert_eq!(relaxed_clusters[0].traces()[0].name(), "trace_1");
/// assert_eq!(relaxed_clusters[0].traces()[1].name(), "trace_2");
/// assert_eq!(relaxed_clusters[0].min_edge_distance(&Hamming), 1);
/// // While the specified syscall tolerance is 0, since the criterion is [Criterion::EdgesOnly],
/// // it is not taken into account.
/// assert_eq!(relaxed_clusters[0].min_syscall_distance(&Hamming), 2);
/// ```
pub fn cluster_traces<DM>(
    traces: &[Trace],
    criterion: Criterion,
    distance_metric: DM,
    edge_tolerance: u64,
    syscall_tolerance: u64,
) -> Result<Vec<Cluster>, RosaError>
where
    DM: DistanceMetric + Clone,
{
    if edge_tolerance == 0
        && syscall_tolerance == 0
        && (criterion == Criterion::EdgesAndSyscalls || criterion == Criterion::EdgesOnly)
    {
        // If both tolerances are 0, and we care about edges, we will never be able to put two
        // traces in the same cluster. This is because we only keep traces that have unique edge
        // vectors. It's worth it to simply create the corresponding clusters here, as it's much
        // faster.
        traces
            .iter()
            .enumerate()
            .map(|(index, trace)| {
                Cluster::build(&format!("cluster_{:0>6}", index), slice::from_ref(trace))
            })
            .collect()
    } else {
        // In the general case, we cannot optimize, so we have to go through the full clustering
        // algorithm.
        traces.iter().try_fold(Vec::new(), |clusters, trace| {
            let result =
                get_most_similar_cluster(trace, &clusters, criterion, distance_metric.clone()).map(
                    |most_similar_cluster| {
                        let max_edge_distance = most_similar_cluster
                            .traces
                            .iter()
                            .map(|cluster_trace| {
                                distance_metric.distance(trace.edges(), cluster_trace.edges())
                            })
                            .max()
                            .expect(
                                "failed to get max edge distance between trace and most similar\
                                cluster.",
                            );
                        let max_syscall_distance = most_similar_cluster
                            .traces
                            .iter()
                            .map(|cluster_trace| {
                                distance_metric.distance(trace.syscalls(), cluster_trace.syscalls())
                            })
                            .max()
                            .expect(
                                "failed to get max syscall distance between trace and most similar\
                                cluster.",
                            );

                        let edge_criterion = max_edge_distance
                            <= cmp::max(
                                most_similar_cluster.min_edge_distance(&distance_metric),
                                edge_tolerance,
                            );
                        let syscall_criterion = max_syscall_distance
                            <= cmp::max(
                                most_similar_cluster.min_syscall_distance(&distance_metric),
                                syscall_tolerance,
                            );

                        let cluster_matches = match criterion {
                            Criterion::EdgesOnly => edge_criterion,
                            Criterion::SyscallsOnly => syscall_criterion,
                            Criterion::EdgesOrSyscalls => edge_criterion || syscall_criterion,
                            Criterion::EdgesAndSyscalls => edge_criterion && syscall_criterion,
                        };

                        cluster_matches.then_some(most_similar_cluster)
                    },
                );

            match result {
                // A cluster was found that fulfills the criteria needed to integrate the trace.
                Some(Some(most_similar_cluster)) => clusters
                    .clone()
                    .into_iter()
                    .map(|cluster| {
                        if cluster.id() == most_similar_cluster.id() {
                            // Note that this will check whether the inserted trace has the same
                            // shape (i.e., edge & syscall size) as the other traces.
                            Cluster::build(
                                &most_similar_cluster.id(),
                                &[most_similar_cluster.traces(), slice::from_ref(trace)].concat(),
                            )
                        } else {
                            Ok(cluster.clone())
                        }
                    })
                    .collect(),
                // Either no cluster was found (because none exist) or the one that was found didn't
                // match; either way, we have to create a new cluster for the trace.
                Some(None) | None => {
                    let new_cluster = Cluster::build(
                        &format!("cluster_{:0>6}", clusters.len()),
                        slice::from_ref(trace),
                    )?;

                    Ok([clusters.clone(), vec![new_cluster]].concat())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests;
