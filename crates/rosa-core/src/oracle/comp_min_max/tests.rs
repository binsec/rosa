use super::*;

use crate::distance_metric::hamming::Hamming;

#[test]
fn empty_cluster() {
    let trace = Trace::build("my_trace", &[], &[0, 1, 2], 3, &[0, 1, 2], 3).unwrap();
    let cluster = Cluster::build("my_cluster", &[]).unwrap();
    assert_eq!(
        CompMinMax
            .decide(&trace, &cluster, Criterion::EdgesOnly, Hamming)
            .expect_err("oracle should fail")
            .message,
        format!("cluster {} is empty.", cluster.id())
    );

    assert_eq!(
        CompMinMax
            .decide(&trace, &cluster, Criterion::SyscallsOnly, Hamming)
            .expect_err("oracle should fail")
            .message,
        format!("cluster {} is empty.", cluster.id())
    );
}

#[test]
fn mismatched_trace_and_cluster_sizes() {
    let trace = Trace::build("my_trace", &[], &[0], 3, &[0], 3).unwrap();
    let cluster_trace_1 = Trace::build("cluster_trace_1", &[], &[0], 2, &[0], 3).unwrap();
    let cluster_trace_2 = Trace::build("cluster_trace_2", &[], &[0], 2, &[0], 3).unwrap();
    let cluster = Cluster::build(
        "my_cluster",
        &[cluster_trace_1.clone(), cluster_trace_2.clone()],
    )
    .unwrap();

    assert_eq!(
        CompMinMax
            .decide(&trace, &cluster, Criterion::EdgesOnly, Hamming)
            .expect_err("oracle should fail")
            .message,
        format!(
            "oracle: trace {} has shape ({}, {}), but cluster {} has shape ({}, {}).",
            trace.id(),
            trace.shape().0,
            trace.shape().1,
            cluster.id(),
            cluster.shape().unwrap().0,
            cluster.shape().unwrap().1,
        )
    );

    let cluster_trace_1 = Trace::build("cluster_trace_1", &[], &[0], 3, &[0], 2).unwrap();
    let cluster_trace_2 = Trace::build("cluster_trace_2", &[], &[0], 3, &[0], 2).unwrap();
    let cluster = Cluster::build(
        "my_cluster",
        &[cluster_trace_1.clone(), cluster_trace_2.clone()],
    )
    .unwrap();
    assert_eq!(
        CompMinMax
            .decide(&trace, &cluster, Criterion::EdgesOnly, Hamming)
            .expect_err("oracle should fail")
            .message,
        format!(
            "oracle: trace {} has shape ({}, {}), but cluster {} has shape ({}, {}).",
            trace.id(),
            trace.shape().0,
            trace.shape().1,
            cluster.id(),
            cluster.shape().unwrap().0,
            cluster.shape().unwrap().1,
        )
    );
}

#[test]
fn standard_rosa_backdoor() {
    // This is a classic backdoor scenario: the trace has system calls that the cluster (which
    // contains a single trace) does not have.
    let trace = Trace::build(
        "my_trace",
        &[],
        &[0, 10, 239, 429, 1092, 3, 18],
        u16::MAX as usize,
        &[0, 12, 39, 100, 202],
        400,
    )
    .unwrap();
    let cluster = Cluster::build(
        "my_cluster",
        &[Trace::build(
            "cluster_trace",
            &[],
            &[0, 12, 14, 3, 18, 202, 1010, 1982, 143],
            u16::MAX as usize,
            &[0, 12, 39, 202],
            400,
        )
        .unwrap()],
    )
    .unwrap();

    let decision = CompMinMax
        .decide(&trace, &cluster, Criterion::SyscallsOnly, Hamming)
        .expect("oracle should succeed");

    assert!(decision.is_backdoor);
    assert_eq!(decision.reason, DecisionReason::Syscalls);
    assert_eq!(
        decision.discriminants,
        Discriminants {
            trace_edges: vec![10, 239, 429, 1092],
            cluster_edges: vec![12, 14, 143, 202, 1010, 1982],
            trace_syscalls: vec![100],
            cluster_syscalls: vec![],
        }
    );
}

#[test]
fn standard_rosa_non_backdoor() {
    // This is a classic non-backdoor scenario: the trace has the same system calls as the cluster.
    let trace = Trace::build(
        "my_trace",
        &[],
        &[0, 10, 239, 429, 1092, 3, 18],
        u16::MAX as usize,
        &[0, 12, 39, 100],
        400,
    )
    .unwrap();
    let cluster = Cluster::build(
        "my_cluster",
        &[Trace::build(
            "cluster_trace",
            &[],
            &[0, 12, 14, 3, 18, 202, 1010, 1982, 143],
            u16::MAX as usize,
            &[0, 12, 39, 100],
            400,
        )
        .unwrap()],
    )
    .unwrap();

    let decision = CompMinMax
        .decide(&trace, &cluster, Criterion::SyscallsOnly, Hamming)
        .expect("oracle should succeed");

    assert!(!decision.is_backdoor);
    assert_eq!(decision.reason, DecisionReason::Syscalls);
    assert_eq!(
        decision.discriminants,
        Discriminants {
            trace_edges: vec![10, 239, 429, 1092],
            cluster_edges: vec![12, 14, 143, 202, 1010, 1982],
            trace_syscalls: vec![],
            cluster_syscalls: vec![],
        }
    );
}

#[test]
fn edges_only_backdoor() {
    let trace = Trace::build(
        "my_trace",
        &[],
        &[0, 10, 100, 1000],
        u16::MAX as usize,
        &[0, 1, 2, 3],
        400,
    )
    .unwrap();
    let cluster = Cluster::build(
        "my_cluster",
        &[Trace::build(
            "cluster_trace",
            &[],
            &[0, 10, 100, 1001],
            u16::MAX as usize,
            &[0],
            400,
        )
        .unwrap()],
    )
    .unwrap();

    let decision = CompMinMax
        .decide(&trace, &cluster, Criterion::EdgesOnly, Hamming)
        .expect("oracle should succeed");

    assert!(decision.is_backdoor);
    assert_eq!(decision.reason, DecisionReason::Edges);
    assert_eq!(
        decision.discriminants,
        Discriminants {
            trace_edges: vec![1000],
            cluster_edges: vec![1001],
            trace_syscalls: vec![1, 2, 3],
            cluster_syscalls: vec![],
        }
    );
}

#[test]
fn edges_only_non_backdoor() {
    let trace = Trace::build(
        "my_trace",
        &[],
        &[0, 10, 100, 1000],
        u16::MAX as usize,
        &[0, 1, 2, 3],
        400,
    )
    .unwrap();
    let cluster = Cluster::build(
        "my_cluster",
        &[Trace::build(
            "cluster_trace",
            &[],
            &[0, 10, 100, 1000],
            u16::MAX as usize,
            &[0],
            400,
        )
        .unwrap()],
    )
    .unwrap();

    let decision = CompMinMax
        .decide(&trace, &cluster, Criterion::EdgesOnly, Hamming)
        .expect("oracle should succeed");

    assert!(!decision.is_backdoor);
    assert_eq!(decision.reason, DecisionReason::Edges);
    assert_eq!(
        decision.discriminants,
        Discriminants {
            trace_edges: vec![],
            cluster_edges: vec![],
            trace_syscalls: vec![1, 2, 3],
            cluster_syscalls: vec![],
        }
    );
}

// TODO: other criteria
// TODO: multi-trace clusters
