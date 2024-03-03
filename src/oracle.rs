//! Metamorphic oracle definition & utilities.
//!
//! ROSA's backdoor detection is based on a metamorphic oracle: in order for something to be a
//! backdoor, it has to be different enough from similar but _normal_ runtime traces.
//!
//! This module implements various metamorphic oracle algorithms.

use std::{fmt, str};

use serde::{Deserialize, Serialize};

use crate::{
    clustering::Cluster,
    criterion::Criterion,
    decision::{Decision, DecisionReason},
    distance_metric::DistanceMetric,
    error::RosaError,
    trace::Trace,
};

/// The available oracle algorithms.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum Oracle {
    /// The CompMinMax oracle.
    ///
    /// This oracle determines that a given trace is a backdoor, if the **maximum distance**
    /// between the **trace and the cluster** is **greater** than the **minimum internal distance**
    /// of the cluster.
    CompMinMax,
}

impl Oracle {
    /// Decide if a given trace corresponds to a backdoor.
    ///
    /// # Arguments
    /// * `trace` - The trace to examine.
    /// * `cluster` - The cluster to compare the trace to.
    /// * `criterion` - The criterion to use in the comparison.
    /// * `distance_metric` - The distance metric to use in the comparison.
    ///
    /// # Example
    /// ```
    /// use rosa::{
    ///     clustering::{self, Cluster},
    ///     criterion::Criterion,
    ///     distance_metric::DistanceMetric,
    ///     oracle::Oracle,
    ///     trace::Trace,
    /// };
    ///
    /// // Dummy cluster to demonstrate function usage.
    /// let cluster = Cluster {
    ///     uid: "cluster_1".to_string(),
    ///     traces: vec![
    ///         Trace {
    ///             uid: "trace_1".to_string(),
    ///             test_input: vec![],
    ///             edges: vec![1, 0, 0, 0],
    ///             syscalls: vec![],
    ///         },
    ///         Trace {
    ///             uid: "trace_2".to_string(),
    ///             test_input: vec![],
    ///             edges: vec![1, 1, 0, 0],
    ///             syscalls: vec![],
    ///         },
    ///     ],
    ///     min_edge_distance: 1,
    ///     max_edge_distance: 1,
    ///     min_syscall_distance: 0,
    ///     max_syscall_distance: 0,
    /// };
    ///
    /// // The trace to examine.
    /// // Notice how its edges are quite different from the cluster.
    /// let trace = Trace {
    ///     uid: "new_trace".to_string(),
    ///     test_input: vec![],
    ///     edges: vec![1, 1, 1, 1],
    ///     syscalls: vec![],
    /// };
    ///
    /// // The oracle to use.
    /// let oracle = Oracle::CompMinMax;
    ///
    /// assert!(
    ///     oracle.decide(
    ///         &trace,
    ///         &cluster,
    ///         Criterion::EdgesOnly,
    ///         DistanceMetric::Hamming
    ///     ).is_backdoor
    /// );
    ///
    /// ```
    pub fn decide(
        &self,
        trace: &Trace,
        cluster: &Cluster,
        criterion: Criterion,
        distance_metric: DistanceMetric,
    ) -> Decision {
        match self {
            Self::CompMinMax => comp_min_max_oracle(trace, cluster, criterion, distance_metric),
        }
    }
}

impl fmt::Display for Oracle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::CompMinMax => "comp_min_max",
            }
        )
    }
}

impl str::FromStr for Oracle {
    type Err = RosaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "comp_min_max" => Ok(Self::CompMinMax),
            unknown => fail!("invalid oracle '{}'.", unknown),
        }
    }
}

/// Implement the CompMinMax oracle algorithm.
///
/// Two sets of distances are computed:
/// - D_t: the distances between the trace and every trace in the cluster;
/// - D_c: the distances between every pair of traces within the cluster.
///
/// If `min(D_t) > max(D_c)`, the trace is considered to correspond to a backdoor.
///
/// # Arguments
/// * `trace` - The trace to examine.
/// * `cluster` - The cluster to compare the trace to.
/// * `criterion` - The criterion to use in the comparison.
/// * `distance_metric` - The distance metric to use in the comparison.
fn comp_min_max_oracle(
    trace: &Trace,
    cluster: &Cluster,
    criterion: Criterion,
    distance_metric: DistanceMetric,
) -> Decision {
    let min_edge_distance = cluster
        .traces
        .iter()
        .map(|cluster_trace| distance_metric.dist(&trace.edges, &cluster_trace.edges))
        .min()
        .expect("failed to get min edge distance between trace and cluster.");
    let min_syscall_distance = cluster
        .traces
        .iter()
        .map(|cluster_trace| distance_metric.dist(&trace.syscalls, &cluster_trace.syscalls))
        .min()
        .expect("failed to get min syscall distance between trace and cluster.");

    let edge_criterion = min_edge_distance > cluster.max_edge_distance;
    let syscall_criterion = min_syscall_distance > cluster.max_syscall_distance;

    let (is_backdoor, reason) = match criterion {
        Criterion::EdgesOnly => (edge_criterion, DecisionReason::Edges),
        Criterion::SyscallsOnly => (syscall_criterion, DecisionReason::Syscalls),
        Criterion::EdgesOrSyscalls => (
            edge_criterion || syscall_criterion,
            match edge_criterion || syscall_criterion {
                true => match edge_criterion {
                    true => DecisionReason::Edges,
                    false => DecisionReason::Syscalls,
                },
                false => DecisionReason::EdgesAndSyscalls,
            },
        ),
        Criterion::EdgesAndSyscalls => (
            edge_criterion && syscall_criterion,
            match edge_criterion && syscall_criterion {
                true => DecisionReason::EdgesAndSyscalls,
                false => match edge_criterion {
                    true => DecisionReason::Syscalls,
                    false => DecisionReason::Edges,
                },
            },
        ),
    };

    Decision {
        trace_uid: trace.uid.clone(),
        cluster_uid: cluster.uid.clone(),
        is_backdoor,
        reason,
    }
}
