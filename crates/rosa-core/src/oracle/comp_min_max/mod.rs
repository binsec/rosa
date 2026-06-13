//! The CompMinMax metamorphic oracle algorithm.
//!
//! Two sets of distances are computed:
//! - D_t: the set of distances between the trace and every trace in the cluster;
//! - D_c: the set of distances between every pair of traces within the cluster.
//!
//! If `min(D_t) > max(D_c)`, the trace is considered to correspond to a backdoor.

use serde::{Deserialize, Serialize};

use crate::{
    clustering::Cluster,
    criterion::Criterion,
    distance_metric::DistanceMetric,
    error::RosaError,
    oracle::{Decision, DecisionReason, Discriminants, Oracle},
    trace::Trace,
};

#[cfg(test)]
mod tests;

/// The CompMinMax metamorphic oracle algorithm.
#[derive(Serialize, Deserialize, Clone)]
pub struct CompMinMax;

impl<DM> Oracle<DM> for CompMinMax
where
    DM: DistanceMetric,
{
    const NAME: &'static str = "comp-min-max";

    fn decide(
        &self,
        trace: &Trace,
        cluster: &Cluster,
        criterion: Criterion,
        distance_metric: DM,
    ) -> Result<Decision, RosaError> {
        // Check that the trace has the same shape as the cluster.
        let trace_shape = trace.shape();
        let cluster_shape = cluster
            .shape()
            .ok_or(error!("cluster {} is empty.", cluster.id()))?;

        (trace_shape == cluster_shape).then_some(()).ok_or(error!(
            "oracle: trace {} has shape ({}, {}), but cluster {} has shape ({}, {}).",
            trace.id(),
            trace_shape.0,
            trace_shape.1,
            cluster.id(),
            cluster_shape.0,
            cluster_shape.1
        ))?;

        /// Get the minimum edge distance between a trace and a cluster.
        fn get_min_edge_distance<DM: DistanceMetric>(
            trace: &Trace,
            cluster: &Cluster,
            distance_metric: &DM,
        ) -> Result<u64, RosaError> {
            cluster
                .traces()
                .iter()
                .map(|cluster_trace| distance_metric.distance(trace.edges(), cluster_trace.edges()))
                .min()
                .ok_or(error!(
                    "minimum edge distance for trace {} and cluster {} not found: cluster empty.",
                    trace.id(),
                    cluster.id()
                ))
        }

        /// Get the minimum syscall distance between a trace and a cluster.
        fn get_min_syscall_distance<DM: DistanceMetric>(
            trace: &Trace,
            cluster: &Cluster,
            distance_metric: &DM,
        ) -> Result<u64, RosaError> {
            cluster
                .traces()
                .iter()
                .map(|cluster_trace| distance_metric.distance(trace.syscalls(), cluster_trace.syscalls()))
                .min()
                .ok_or(error!(
                    "minimum syscall distance for trace {} and cluster {} not found: cluster empty.",
                    trace.id(),
                    cluster.id()
                ))
        }

        let (edge_criterion, syscall_criterion) = match criterion {
            Criterion::EdgesOnly => {
                (
                    get_min_edge_distance(trace, cluster, &distance_metric)?
                        > cluster.max_edge_distance(&distance_metric),
                    // Dummy value; not used.
                    false,
                )
            }
            Criterion::SyscallsOnly => {
                (
                    // Dummy value; not used.
                    false,
                    get_min_syscall_distance(trace, cluster, &distance_metric)?
                        > cluster.max_syscall_distance(&distance_metric),
                )
            }
            _ => (
                get_min_edge_distance(trace, cluster, &distance_metric)?
                    > cluster.max_edge_distance(&distance_metric),
                get_min_syscall_distance(trace, cluster, &distance_metric)?
                    > cluster.max_syscall_distance(&distance_metric),
            ),
        };

        let (is_backdoor, reason) = match criterion {
            Criterion::EdgesOnly => (edge_criterion, DecisionReason::Edges),
            Criterion::SyscallsOnly => (syscall_criterion, DecisionReason::Syscalls),
            Criterion::EdgesOrSyscalls => (
                edge_criterion || syscall_criterion,
                if edge_criterion || syscall_criterion {
                    if edge_criterion {
                        DecisionReason::Edges
                    } else {
                        DecisionReason::Syscalls
                    }
                } else {
                    DecisionReason::EdgesAndSyscalls
                },
            ),
            Criterion::EdgesAndSyscalls => (
                edge_criterion && syscall_criterion,
                if edge_criterion && syscall_criterion {
                    DecisionReason::EdgesAndSyscalls
                } else if edge_criterion {
                    DecisionReason::Syscalls
                } else {
                    DecisionReason::Edges
                },
            ),
        };

        let (trace_edge_hits, trace_edge_misses): (Vec<usize>, Vec<usize>) =
            trace.edges().iter().enumerate().fold(
                (Vec::new(), Vec::new()),
                |(trace_edge_hits, trace_edge_misses), (index, edge)| {
                    if *edge == 0u8 {
                        (trace_edge_hits, [trace_edge_misses, vec![index]].concat())
                    } else {
                        ([trace_edge_hits, vec![index]].concat(), trace_edge_misses)
                    }
                },
            );
        let (trace_syscall_hits, trace_syscall_misses): (Vec<usize>, Vec<usize>) =
            trace.syscalls().iter().enumerate().fold(
                (Vec::new(), Vec::new()),
                |(trace_syscall_hits, trace_syscall_misses), (index, syscall)| {
                    if *syscall == 0u8 {
                        (
                            trace_syscall_hits,
                            [trace_syscall_misses, vec![index]].concat(),
                        )
                    } else {
                        (
                            [trace_syscall_hits, vec![index]].concat(),
                            trace_syscall_misses,
                        )
                    }
                },
            );

        let edges_only_in_trace: Vec<usize> = trace_edge_hits
            .clone()
            .into_iter()
            .filter(|index| {
                cluster.traces().iter().all(|cluster_trace| {
                    cluster_trace
                        .edges()
                        .get(*index)
                        .map(|value| *value == 0)
                        .unwrap_or(true)
                })
            })
            .collect();
        let edges_only_in_cluster: Vec<usize> = trace_edge_misses
            .clone()
            .into_iter()
            .filter(|index| {
                cluster.traces().iter().any(|cluster_trace| {
                    cluster_trace
                        .edges()
                        .get(*index)
                        .map(|value| *value == 1)
                        .unwrap_or(false)
                })
            })
            .collect();

        let syscalls_only_in_trace: Vec<usize> = trace_syscall_hits
            .clone()
            .into_iter()
            .filter(|index| {
                cluster.traces().iter().all(|cluster_trace| {
                    cluster_trace
                        .syscalls()
                        .get(*index)
                        .map(|value| *value == 0)
                        .unwrap_or(true)
                })
            })
            .collect();
        let syscalls_only_in_cluster: Vec<usize> = trace_syscall_misses
            .clone()
            .into_iter()
            .filter(|index| {
                cluster.traces().iter().any(|cluster_trace| {
                    cluster_trace
                        .syscalls()
                        .get(*index)
                        .map(|value| *value == 1)
                        .unwrap_or(false)
                })
            })
            .collect();

        Ok(Decision {
            trace_id: trace.id(),
            trace_name: trace.name().to_string(),
            cluster_id: cluster.id().clone(),
            is_backdoor,
            reason,
            discriminants: Discriminants {
                trace_edges: edges_only_in_trace,
                cluster_edges: edges_only_in_cluster,
                trace_syscalls: syscalls_only_in_trace,
                cluster_syscalls: syscalls_only_in_cluster,
            },
        })
    }
}
