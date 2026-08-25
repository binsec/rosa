use super::*;

use crate::{criterion::Criterion, distance_metric::hamming::Hamming};

/// Auto-check the consistency of the cluster after clustering traces.
///
/// Every criterion guarantees internal consistency regarding the tolerances. For example, with
/// [Criterion::EdgesOnly], all internal distances should be at most as big as the edge-wise
/// tolerance.
macro_rules! cluster_traces {
    (
        $traces:expr,
        $criterion:expr,
        $distance_metric:expr,
        $edge_tolerance:expr,
        $syscall_tolerance:expr
    ) => {{
        // Cluster traces.
        let clusters = cluster_traces(
            $traces,
            $criterion,
            $distance_metric,
            $edge_tolerance,
            $syscall_tolerance,
        )
        .unwrap();

        // Check for consistency.
        clusters.iter().for_each(|cluster| match $criterion {
            Criterion::EdgesOnly => {
                assert!(cluster.max_edge_distance(&$distance_metric) <= $edge_tolerance);
            }
            Criterion::SyscallsOnly => {
                assert!(cluster.max_syscall_distance(&$distance_metric) <= $syscall_tolerance);
            }
            Criterion::EdgesOrSyscalls => {
                // All bets are off; since both components can be responsible for adding traces,
                // both can maximize their respective distances beyond the tolerances.
            }
            Criterion::EdgesAndSyscalls => {
                assert!(cluster.max_edge_distance(&$distance_metric) <= $edge_tolerance);
                assert!(cluster.max_syscall_distance(&$distance_metric) <= $syscall_tolerance)
            }
        });

        clusters
    }};
}

#[test]
fn cluster_traces_edges_only() {
    let phase_one_traces = vec![
        Trace::build("trace_1", &[], &[0], 5, &[], 3).unwrap(),
        Trace::build("trace_2", &[], &[0, 1], 5, &[], 3).unwrap(),
        Trace::build("trace_3", &[], &[1, 2], 5, &[], 3).unwrap(),
        Trace::build("trace_4", &[], &[3], 5, &[], 3).unwrap(),
        Trace::build("trace_5", &[], &[3, 4], 5, &[], 3).unwrap(),
    ];

    // With zero edge-wise tolerance, each trace should go in its own cluster.
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOnly, Hamming, 0, 0);
    assert_eq!(clusters.len(), phase_one_traces.len());
    // Changing the syscall tolerance should not change anything, as we are only taking edges into
    // account.
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOnly, Hamming, 0, 1000);
    assert_eq!(clusters.len(), phase_one_traces.len());

    // With an edge tolerance of 1, we should have 3 clusters:
    // - trace_1, trace_2 (distance 1)
    // - trace_3 (distance 0)
    // - trace_4, trace_5 (distance 1)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOnly, Hamming, 1, 0);
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"]
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge tolerance of 2, we should have 3 clusters:
    // - trace_1, trace_2 (distance 1)
    // - trace_3 (distance 0)
    // - trace_4, trace_5 (distance 1)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOnly, Hamming, 2, 0);
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"],
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge tolerance of 3, we should have 2 clusters:
    // - trace_1, trace_2, trace_3, trace_4 (distance 3)
    // - trace_5 (distance 0)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOnly, Hamming, 3, 0);
    assert_eq!(clusters.len(), 2);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2", "trace_3", "trace_4"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_5"]
    );

    // With an edge tolerance of 1, all traces should fit in a single cluster.
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOnly, Hamming, 4, 0);
    assert_eq!(clusters.len(), 1);
}

#[test]
fn cluster_traces_syscalls_only() {
    let phase_one_traces = vec![
        Trace::build("trace_1", &[], &[], 10, &[0], 5).unwrap(),
        Trace::build("trace_2", &[], &[], 10, &[0, 1], 5).unwrap(),
        Trace::build("trace_3", &[], &[], 10, &[1, 2], 5).unwrap(),
        Trace::build("trace_4", &[], &[], 10, &[3], 5).unwrap(),
        Trace::build("trace_5", &[], &[], 10, &[3, 4], 5).unwrap(),
        // Trace 6 has some different edges but the same system calls as trace 5.
        Trace::build("trace_6", &[], &[1, 2], 10, &[3, 4], 5).unwrap(),
    ];

    // With zero syscall-wise tolerance, each trace should go in its own cluster, except trace 6,
    // which is the same as trace 5 (they should go in the same cluster).
    assert_eq!(
        cluster_traces!(&phase_one_traces, Criterion::SyscallsOnly, Hamming, 0, 0).len(),
        phase_one_traces.len() - 1
    );
    // Changing the edge tolerance should not change anything, as we are only taking syscalls into
    // account.
    assert_eq!(
        cluster_traces!(&phase_one_traces, Criterion::SyscallsOnly, Hamming, 1000, 0).len(),
        phase_one_traces.len() - 1
    );

    // With an syscall tolerance of 1, we should have 3 clusters:
    // - trace_1, trace_2 (distance 1)
    // - trace_3 (distance 0)
    // - trace_4, trace_5, trace_6 (distance 1)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::SyscallsOnly, Hamming, 0, 1);
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"]
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5", "trace_6"]
    );

    // With an syscall tolerance of 2, we should have 3 clusters:
    // - trace_1, trace_2 (distance 1)
    // - trace_3 (distance 0)
    // - trace_4, trace_5, trace_6 (distance 1)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::SyscallsOnly, Hamming, 0, 2);
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"],
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5", "trace_6"]
    );

    // With an syscall tolerance of 3, we should have 2 clusters:
    // - trace_1, trace_2, trace_3, trace_4 (distance 3)
    // - trace_5, trace_6 (distance 0)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::SyscallsOnly, Hamming, 0, 3);
    assert_eq!(clusters.len(), 2);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2", "trace_3", "trace_4"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_5", "trace_6"]
    );

    // With an syscall tolerance of 1, all traces should fit in a single cluster.
    let clusters = cluster_traces!(&phase_one_traces, Criterion::SyscallsOnly, Hamming, 0, 4);
    assert_eq!(clusters.len(), 1);
}

#[test]
fn cluster_traces_edges_or_syscalls() {
    let phase_one_traces = vec![
        Trace::build("trace_1", &[], &[0], 5, &[0], 5).unwrap(),
        Trace::build("trace_2", &[], &[0, 1], 5, &[1], 5).unwrap(),
        Trace::build("trace_3", &[], &[1, 2], 5, &[1, 2], 5).unwrap(),
        Trace::build("trace_4", &[], &[3], 5, &[3, 4], 5).unwrap(),
        Trace::build("trace_5", &[], &[3, 4], 5, &[0, 4], 5).unwrap(),
    ];

    // With zero edge-wise **and** syscall-wise tolerance, each trace should go in its own cluster.
    assert_eq!(
        cluster_traces!(&phase_one_traces, Criterion::EdgesOrSyscalls, Hamming, 0, 0).len(),
        phase_one_traces.len()
    );

    // With an edge-wise tolerance of 1, and a syscall-wise tolerance of 0, we should have 3
    // clusters:
    // - trace_1, trace_2 (edge distance 1, syscall distance 1)
    // - trace_3 (edge distance 0, syscall distance 0)
    // - trace_4, trace_5 (edge distance 1, syscall distance 2)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOrSyscalls, Hamming, 1, 0);
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"]
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge-wise tolerance of 1, and a syscall-wise tolerance of 1, we should have 3
    // clusters:
    // - trace_1, trace_2 (edge distance 1, syscall distance 1)
    // - trace_3 (edge distance 0, syscall distance 0)
    // - trace_4, trace_5 (edge distance 1, syscall distance 2)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOrSyscalls, Hamming, 1, 1);
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"]
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge-wise tolerance of 2, and a syscall-wise tolerance of 0, we should have 3
    // clusters:
    // - trace_1, trace_2 (edge distance 1, syscall distance 1)
    // - trace_3 (edge distance 0, syscall distance 0)
    // - trace_4, trace_5 (edge distance 1, syscall distance 2)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOrSyscalls, Hamming, 2, 0);
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"],
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge-wise tolerance of 2, and a syscall-wise tolerance of 1, we should have 3
    // clusters:
    // - trace_1, trace_2 (edge distance 1, syscall distance 1)
    // - trace_3 (edge distance 0, syscall distance 0)
    // - trace_4, trace_5 (edge distance 1, syscall distance 2)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOrSyscalls, Hamming, 2, 1);
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"],
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge-wise tolerance of 2, and a syscall-wise tolerance of 2, we should have 3
    // clusters:
    // - trace_1, trace_2 (edge distance 1, syscall distance 1)
    // - trace_3 (edge distance 0, syscall distance 0)
    // - trace_4, trace_5 (edge distance 1, syscall distance 2)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOrSyscalls, Hamming, 2, 2);
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"]
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge-wise tolerance of 3, and a syscall-wise tolerance of 0, everything should fit
    // in one cluster.
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOrSyscalls, Hamming, 3, 0);
    assert_eq!(clusters.len(), 1);

    // With an edge-wise tolerance of 0, and a syscall-wise tolerance of 1, we should have 3
    // clusters:
    // - trace_1, trace_5 (edge distance 3, syscall distance 1)
    // - trace_2, trace_3 (edge distance 2, syscall distance 1)
    // - trace_4 (edge distance 0, syscall distance 0)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOrSyscalls, Hamming, 0, 1);
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_5"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_2", "trace_3"]
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4"]
    );

    // With an edge-wise tolerance of 0, and a syscall-wise tolerance of 2, we should have 3
    // clusters:
    // - trace_1, trace_2 (edge distance 2, syscall distance 1)
    // - trace_3 (edge distance 0, syscall distance 0)
    // - trace_4, trace_5 (edge distance 1, syscall distance 2)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOrSyscalls, Hamming, 0, 2);
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"]
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge-wise tolerance of 1, and a syscall-wise tolerance of 2, we should have 3
    // clusters:
    // - trace_1, trace_2 (edge distance 2, syscall distance 1)
    // - trace_3 (edge distance 0, syscall distance 0)
    // - trace_4, trace_5 (edge distance 1, syscall distance 2)
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOrSyscalls, Hamming, 1, 2);
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"]
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge-wise tolerance of 0, and a syscall-wise tolerance of 3, all traces should fit
    // in one cluster.
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOrSyscalls, Hamming, 0, 3);
    assert_eq!(clusters.len(), 1);
}

#[test]
fn cluster_traces_edges_and_syscalls() {
    let phase_one_traces = vec![
        Trace::build("trace_1", &[], &[0], 5, &[0], 5).unwrap(),
        Trace::build("trace_2", &[], &[0, 1], 5, &[1], 5).unwrap(),
        Trace::build("trace_3", &[], &[1, 2], 5, &[1, 2], 5).unwrap(),
        Trace::build("trace_4", &[], &[3], 5, &[3, 4], 5).unwrap(),
        Trace::build("trace_5", &[], &[3, 4], 5, &[0, 4], 5).unwrap(),
    ];

    // With zero edge-wise tolerance, each trace should go in its own cluster.
    assert_eq!(
        cluster_traces!(
            &phase_one_traces,
            Criterion::EdgesAndSyscalls,
            Hamming,
            0,
            0
        )
        .len(),
        phase_one_traces.len()
    );
    // The same thing should happen when exactly one of the tolerances is non-zero, since the other
    // one will be zero, and thus all traces will be put in their own cluster.
    assert_eq!(
        cluster_traces!(
            &phase_one_traces,
            Criterion::EdgesAndSyscalls,
            Hamming,
            1000,
            0
        )
        .len(),
        phase_one_traces.len()
    );
    assert_eq!(
        cluster_traces!(
            &phase_one_traces,
            Criterion::EdgesAndSyscalls,
            Hamming,
            0,
            1000
        )
        .len(),
        phase_one_traces.len()
    );

    // In order for at least one cluster to contain at least two traces, the edge-wise tolerance
    // should be at least 1, and the syscall-wise tolerance should be at least 1. This yields 4
    // clusters:
    // - trace_1 (edge distance 0, syscall distance 0)
    // - trace_2, trace_3 (edge distance 2, syscall distance 1)
    // - trace_4 (edge distance 0, syscall distance 0)
    // - trace_5 (edge distance 0, syscall distance 0)
    let clusters = cluster_traces!(
        &phase_one_traces,
        Criterion::EdgesAndSyscalls,
        Hamming,
        2,
        1
    );
    assert_eq!(clusters.len(), 4);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_2", "trace_3"]
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4"]
    );
    assert_eq!(
        clusters[3]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_5"]
    );

    // With an edge-wise tolerance of 1, and a syscall-wise tolerance of 2, we should have 3
    // clusters:
    // - trace_1, trace_2 (edge distance 1, syscall distance 1)
    // - trace_3 (edge distance 0, syscall distance 0)
    // - trace_4, trace_5 (edge distance 1, syscall distance 2)
    let clusters = cluster_traces!(
        &phase_one_traces,
        Criterion::EdgesAndSyscalls,
        Hamming,
        1,
        2
    );
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"]
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge-wise tolerance of 2, and a syscall-wise tolerance of 2, we should have 3
    // clusters:
    // - trace_1, trace_2 (edge distance 1, syscall distance 1)
    // - trace_3 (edge distance 0, syscall distance 0)
    // - trace_4, trace_5 (edge distance 1, syscall distance 2)
    let clusters = cluster_traces!(
        &phase_one_traces,
        Criterion::EdgesAndSyscalls,
        Hamming,
        2,
        2
    );
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"]
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge-wise tolerance of 3, and a syscall-wise tolerance of 2, we should have 3
    // clusters:
    // - trace_1, trace_2 (edge distance 1, syscall distance 1)
    // - trace_3 (edge distance 0, syscall distance 0)
    // - trace_4, trace_5 (edge distance 1, syscall distance 2)
    let clusters = cluster_traces!(
        &phase_one_traces,
        Criterion::EdgesAndSyscalls,
        Hamming,
        3,
        2
    );
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"]
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge-wise tolerance of 2, and a syscall-wise tolerance of 3, we should have 3
    // clusters:
    // - trace_1, trace_2 (edge distance 1, syscall distance 1)
    // - trace_3 (edge distance 0, syscall distance 0)
    // - trace_4, trace_5 (edge distance 1, syscall distance 2)
    let clusters = cluster_traces!(
        &phase_one_traces,
        Criterion::EdgesAndSyscalls,
        Hamming,
        2,
        3
    );
    assert_eq!(clusters.len(), 3);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_3"]
    );
    assert_eq!(
        clusters[2]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge-wise tolerance of 3, and a syscall-wise tolerance of 3, we should have 2
    // clusters:
    // - trace_1, trace_2, trace_3 (edge distance 3, syscall distance 3)
    // - trace_4, trace_5 (edge distance 1, syscall distance 2)
    let clusters = cluster_traces!(
        &phase_one_traces,
        Criterion::EdgesAndSyscalls,
        Hamming,
        3,
        3
    );
    assert_eq!(clusters.len(), 2);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2", "trace_3"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge-wise tolerance of 4, and a syscall-wise tolerance of 3, we should have 2
    // clusters:
    // - trace_1, trace_2, trace_3 (edge distance 3, syscall distance 3)
    // - trace_4, trace_5 (edge distance 1, syscall distance 2)
    let clusters = cluster_traces!(
        &phase_one_traces,
        Criterion::EdgesAndSyscalls,
        Hamming,
        4,
        3
    );
    assert_eq!(clusters.len(), 2);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2", "trace_3"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_4", "trace_5"]
    );

    // With an edge-wise tolerance of 3, and a syscall-wise tolerance of 4, we should have 2
    // clusters:
    // - trace_1, trace_2, trace_3, trace_4 (edge distance 3, syscall distance 4)
    // - trace_5 (edge distance 0, syscall distance 0)
    let clusters = cluster_traces!(
        &phase_one_traces,
        Criterion::EdgesAndSyscalls,
        Hamming,
        3,
        4
    );
    assert_eq!(clusters.len(), 2);
    assert_eq!(
        clusters[0]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_1", "trace_2", "trace_3", "trace_4"]
    );
    assert_eq!(
        clusters[1]
            .traces()
            .iter()
            .map(|trace| trace.name())
            .collect::<Vec<&str>>(),
        vec!["trace_5"]
    );

    // With an edge-wise tolerance of 4, and a syscall-wise tolerance of 4, all traces should fit
    // in one cluster.
    let clusters = cluster_traces!(
        &phase_one_traces,
        Criterion::EdgesAndSyscalls,
        Hamming,
        4,
        4
    );
    assert_eq!(clusters.len(), 1);
}

#[test]
fn most_similar_cluster_edges_only() {
    // [Criterion::EdgesOnly] should only care about edges.
    // Here, clusters 0 and 1 are equally good matches edge-wise, with cluster 1 being a better
    // match syscall-wise. Yet, the most similar should be 0 (since the first most similar is
    // picked).
    let phase_one_traces = vec![
        Trace::build("trace_1", &[], &[0, 2], 4, &[0, 1], 3).unwrap(),
        Trace::build("trace_2", &[], &[1, 2], 4, &[1, 2], 3).unwrap(),
        Trace::build("trace_3", &[], &[0], 4, &[0], 3).unwrap(),
    ];
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOnly, Hamming, 0, 0);
    assert_eq!(clusters.len(), 3);
    assert_eq!(clusters[0].traces().len(), 1);
    assert_eq!(clusters[0].traces()[0].name(), "trace_1".to_string());
    assert_eq!(clusters[1].traces().len(), 1);
    assert_eq!(clusters[1].traces()[0].name(), "trace_2".to_string());
    assert_eq!(clusters[2].traces().len(), 1);
    assert_eq!(clusters[2].traces()[0].name(), "trace_3".to_string());

    let my_trace = Trace::build("my_trace", &[], &[2], 4, &[1, 2], 3).unwrap();
    let most_similar_cluster =
        get_most_similar_cluster(&my_trace, &clusters, Criterion::EdgesOnly, Hamming).unwrap();

    assert_eq!(most_similar_cluster.clone(), clusters[0]);
    assert_eq!(
        most_similar_cluster.traces()[0].name(),
        "trace_1".to_string()
    );
}

#[test]
fn most_similar_cluster_syscalls_only() {
    // [Criterion::SyscallsOnly] should only care about syscalls.
    // Here, clusters 0 and 1 are equally good matches syscall-wise, with cluster 1 being a better
    // match edge-wise. Yet, the most similar should be 0 (since the first most similar is
    // picked).
    let phase_one_traces = vec![
        Trace::build("trace_1", &[], &[0, 1], 4, &[0, 2], 3).unwrap(),
        Trace::build("trace_2", &[], &[1, 2], 4, &[1, 2], 3).unwrap(),
        Trace::build("trace_3", &[], &[0], 4, &[0], 3).unwrap(),
    ];
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOnly, Hamming, 0, 0);
    assert_eq!(clusters.len(), 3);
    assert_eq!(clusters[0].traces().len(), 1);
    assert_eq!(clusters[0].traces()[0].name(), "trace_1".to_string());
    assert_eq!(clusters[1].traces().len(), 1);
    assert_eq!(clusters[1].traces()[0].name(), "trace_2".to_string());
    assert_eq!(clusters[2].traces().len(), 1);
    assert_eq!(clusters[2].traces()[0].name(), "trace_3".to_string());

    let my_trace = Trace::build("my_trace", &[], &[1, 2], 4, &[2], 3).unwrap();
    let most_similar_cluster =
        get_most_similar_cluster(&my_trace, &clusters, Criterion::SyscallsOnly, Hamming).unwrap();

    assert_eq!(most_similar_cluster.clone(), clusters[0]);
    assert_eq!(
        most_similar_cluster.traces()[0].name(),
        "trace_1".to_string()
    );
}

#[test]
fn most_similar_cluster_edges_or_syscalls_closest_edges() {
    // [Criterion::EdgesOrSyscalls] should care about the smallest distance of the two components.
    // Here, cluster 0 has a smaller syscall-wise distance than cluster 1, but cluster 1 has an
    // even smaller edge-wise distance.
    let phase_one_traces = vec![
        Trace::build("trace_1", &[], &[0, 1], 4, &[2], 3).unwrap(),
        Trace::build("trace_2", &[], &[1, 2], 4, &[1, 2], 3).unwrap(),
        Trace::build("trace_3", &[], &[0], 4, &[0], 3).unwrap(),
    ];
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOnly, Hamming, 0, 0);
    assert_eq!(clusters.len(), 3);
    assert_eq!(clusters[0].traces().len(), 1);
    assert_eq!(clusters[0].traces()[0].name(), "trace_1".to_string());
    assert_eq!(clusters[1].traces().len(), 1);
    assert_eq!(clusters[1].traces()[0].name(), "trace_2".to_string());
    assert_eq!(clusters[2].traces().len(), 1);
    assert_eq!(clusters[2].traces()[0].name(), "trace_3".to_string());

    let my_trace = Trace::build("my_trace", &[], &[1, 2], 4, &[0, 1, 2], 3).unwrap();
    let most_similar_cluster =
        get_most_similar_cluster(&my_trace, &clusters, Criterion::EdgesOrSyscalls, Hamming)
            .unwrap();

    assert_eq!(most_similar_cluster.clone(), clusters[1]);
    assert_eq!(
        most_similar_cluster.traces()[0].name(),
        "trace_2".to_string()
    );
}

#[test]
fn most_similar_cluster_edges_or_syscalls_closest_syscalls() {
    // [Criterion::EdgesOrSyscalls] should care about the smallest distance of the two components.
    // Here, cluster 0 has a smaller edge-wise distance than cluster 1, but cluster 1 has an
    // even smaller syscall-wise distance.
    let phase_one_traces = vec![
        Trace::build("trace_1", &[], &[2], 4, &[0, 1], 3).unwrap(),
        Trace::build("trace_2", &[], &[1, 2], 4, &[1, 2], 3).unwrap(),
        Trace::build("trace_3", &[], &[0], 4, &[0], 3).unwrap(),
    ];
    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOnly, Hamming, 0, 0);
    assert_eq!(clusters.len(), 3);
    assert_eq!(clusters[0].traces().len(), 1);
    assert_eq!(clusters[0].traces()[0].name(), "trace_1".to_string());
    assert_eq!(clusters[1].traces().len(), 1);
    assert_eq!(clusters[1].traces()[0].name(), "trace_2".to_string());
    assert_eq!(clusters[2].traces().len(), 1);
    assert_eq!(clusters[2].traces()[0].name(), "trace_3".to_string());

    let my_trace = Trace::build("my_trace", &[], &[0, 1, 2], 4, &[1, 2], 3).unwrap();
    let most_similar_cluster =
        get_most_similar_cluster(&my_trace, &clusters, Criterion::EdgesOrSyscalls, Hamming)
            .unwrap();

    assert_eq!(most_similar_cluster.clone(), clusters[1]);
    assert_eq!(
        most_similar_cluster.traces()[0].name(),
        "trace_2".to_string()
    );
}

#[test]
fn most_similar_cluster_edges_and_syscalls_edge_diffs() {
    // [Criterion::EdgesAndSyscalls] should minimize *both* components, with the edge component
    // taking priority. For instance, if there are multiple candidates for the edge criterion, the
    // one with the smallest syscall-wise distance will be selected.
    let phase_one_traces = vec![
        Trace::build("trace_1", &[], &[0, 2], 4, &[0, 2], 3).unwrap(),
        Trace::build("trace_2", &[], &[0, 1], 4, &[0, 1], 3).unwrap(),
        Trace::build("trace_3", &[], &[1, 2], 4, &[0, 1, 2], 3).unwrap(),
        Trace::build("trace_4", &[], &[0], 4, &[0, 1, 2], 3).unwrap(),
    ];

    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOnly, Hamming, 0, 0);

    assert_eq!(clusters.len(), 4);
    assert_eq!(clusters[0].traces().len(), 1);
    assert_eq!(clusters[0].traces()[0].name(), "trace_1".to_string());
    assert_eq!(clusters[1].traces().len(), 1);
    assert_eq!(clusters[1].traces()[0].name(), "trace_2".to_string());
    assert_eq!(clusters[2].traces().len(), 1);
    assert_eq!(clusters[2].traces()[0].name(), "trace_3".to_string());
    assert_eq!(clusters[3].traces().len(), 1);
    assert_eq!(clusters[3].traces()[0].name(), "trace_4".to_string());

    let new_trace = Trace::build("trace_5", &[], &[0, 1, 2, 3], 4, &[0, 1, 2], 3).unwrap();

    let most_similar_cluster =
        get_most_similar_cluster(&new_trace, &clusters, Criterion::EdgesAndSyscalls, Hamming)
            .unwrap();
    assert_eq!(most_similar_cluster.traces().len(), 1);
    assert_eq!(
        most_similar_cluster.traces()[0].name(),
        "trace_3".to_string()
    );
}

#[test]
fn most_similar_cluster_edges_and_syscalls_syscall_diffs() {
    // [Criterion::EdgesAndSyscalls] should minimize *both* components, with the edge component
    // taking priority. For instance, if there are multiple candidates for the edge criterion, the
    // one with the smallest syscall-wise distance will be selected.
    let phase_one_traces = vec![
        Trace::build("trace_1", &[], &[0, 2], 4, &[0, 2], 3).unwrap(),
        Trace::build("trace_2", &[], &[0, 1, 2], 4, &[0, 1], 3).unwrap(),
        Trace::build("trace_3", &[], &[1, 2], 4, &[1, 2], 3).unwrap(),
        Trace::build("trace_4", &[], &[0], 4, &[0, 1, 2], 3).unwrap(),
    ];

    let clusters = cluster_traces!(&phase_one_traces, Criterion::EdgesOnly, Hamming, 0, 0);

    assert_eq!(clusters.len(), 4);
    assert_eq!(clusters[0].traces().len(), 1);
    assert_eq!(clusters[0].traces()[0].name(), "trace_1".to_string());
    assert_eq!(clusters[1].traces().len(), 1);
    assert_eq!(clusters[1].traces()[0].name(), "trace_2".to_string());
    assert_eq!(clusters[2].traces().len(), 1);
    assert_eq!(clusters[2].traces()[0].name(), "trace_3".to_string());
    assert_eq!(clusters[3].traces().len(), 1);
    assert_eq!(clusters[3].traces()[0].name(), "trace_4".to_string());

    let new_trace = Trace::build("trace_5", &[], &[0, 1, 2, 3], 4, &[0, 1, 2], 3).unwrap();

    let most_similar_cluster =
        get_most_similar_cluster(&new_trace, &clusters, Criterion::EdgesAndSyscalls, Hamming)
            .unwrap();
    assert_eq!(most_similar_cluster.traces().len(), 1);
    assert_eq!(
        most_similar_cluster.traces()[0].name(),
        "trace_2".to_string()
    );
}
