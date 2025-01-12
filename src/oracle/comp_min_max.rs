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
    oracle::{Decision, DecisionReason, Discriminants, Oracle},
    trace::Trace,
};

/// The CompMinMax metamorphic oracle algorithm.
#[derive(Serialize, Deserialize, Clone)]
pub struct CompMinMax;

#[typetag::serde(name = "comp-min-max")]
impl Oracle for CompMinMax {
    fn name(&self) -> &str {
        "comp-min-max"
    }

    fn decide(
        &self,
        trace: &Trace,
        cluster: &Cluster,
        criterion: Criterion,
        distance_metric: Box<dyn DistanceMetric>,
    ) -> Decision {
        let min_edge_distance = cluster
            .traces
            .iter()
            .map(|cluster_trace| distance_metric.distance(&trace.edges, &cluster_trace.edges))
            .min()
            .expect("failed to get min edge distance between trace and cluster.");
        let min_syscall_distance = cluster
            .traces
            .iter()
            .map(|cluster_trace| distance_metric.distance(&trace.syscalls, &cluster_trace.syscalls))
            .min()
            .expect("failed to get min syscall distance between trace and cluster.");

        let edge_criterion = min_edge_distance > cluster.max_edge_distance;
        let syscall_criterion = min_syscall_distance > cluster.max_syscall_distance;

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

        let trace_edges: Vec<usize> = trace
            .edges
            .iter()
            .enumerate()
            .filter_map(|(index, edge)| match edge {
                0u8 => None,
                _ => Some(index),
            })
            .filter(|index| {
                cluster
                    .traces
                    .iter()
                    .all(|cluster_trace| cluster_trace.edges[*index] == 0)
            })
            .collect();
        let trace_syscalls: Vec<usize> = trace
            .syscalls
            .iter()
            .enumerate()
            .filter_map(|(index, syscall)| match syscall {
                0u8 => None,
                _ => Some(index),
            })
            .filter(|index| {
                cluster
                    .traces
                    .iter()
                    .all(|cluster_trace| cluster_trace.syscalls[*index] == 0)
            })
            .collect();
        let cluster_edges: Vec<usize> = trace
            .edges
            .iter()
            .enumerate()
            .filter_map(|(index, edge)| match edge {
                0u8 => Some(index),
                _ => None,
            })
            .filter(|index| {
                cluster
                    .traces
                    .iter()
                    .any(|cluster_trace| cluster_trace.edges[*index] != 0)
            })
            .collect();
        let cluster_syscalls: Vec<usize> = trace
            .syscalls
            .iter()
            .enumerate()
            .filter_map(|(index, syscall)| match syscall {
                0u8 => Some(index),
                _ => None,
            })
            .filter(|index| {
                cluster
                    .traces
                    .iter()
                    .any(|cluster_trace| cluster_trace.syscalls[*index] != 0)
            })
            .collect();

        Decision {
            trace_uid: trace.uid(),
            trace_name: trace.name.clone(),
            cluster_uid: cluster.uid.clone(),
            is_backdoor,
            reason,
            discriminants: Discriminants {
                trace_edges,
                cluster_edges,
                trace_syscalls,
                cluster_syscalls,
            },
        }
    }
}
