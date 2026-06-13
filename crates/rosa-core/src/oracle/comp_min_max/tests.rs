use super::*;

use crate::distance_metric::hamming::Hamming;

#[test]
fn empty_trace() {
    let trace = Trace::from("my_trace", &[], &[], 0, &[], 0);
    let cluster = Cluster::build(
        "my_cluster",
        &[Trace::from(
            "cluster_trace",
            &[],
            &[0, 1, 2],
            3,
            &[0, 1, 2],
            3,
        )],
    )
    .unwrap();

    assert_eq!(
        CompMinMax
            .decide(&trace, &cluster, Criterion::SyscallsOnly, Hamming)
            .expect_err("oracle should fail")
            .message,
        format!("trace {} is malformed: no edges.", trace.id())
    );

    let trace = Trace::from("my_trace", &[], &[0], 1, &[], 0);
    assert_eq!(
        CompMinMax
            .decide(&trace, &cluster, Criterion::SyscallsOnly, Hamming)
            .expect_err("oracle should fail")
            .message,
        format!("trace {} is malformed: no syscalls.", trace.id())
    );
}

#[test]
fn empty_cluster() {
    let trace = Trace::from("my_trace", &[], &[0, 1, 2], 3, &[0, 1, 2], 3);
    let cluster = Cluster::build("my_cluster", &[]).unwrap();
    assert_eq!(
        CompMinMax
            .decide(&trace, &cluster, Criterion::EdgesOnly, Hamming)
            .expect_err("oracle should fail")
            .message,
        format!(
            "minimum edge distance for trace {} and cluster {} not found: cluster empty.",
            trace.id(),
            cluster.id()
        )
    );

    assert_eq!(
        CompMinMax
            .decide(&trace, &cluster, Criterion::SyscallsOnly, Hamming)
            .expect_err("oracle should fail")
            .message,
        format!(
            "minimum syscall distance for trace {} and cluster {} not found: cluster empty.",
            trace.id(),
            cluster.id()
        )
    );
}

#[test]
fn mismatched_trace_and_cluster_sizes() {
    let trace = Trace::from("my_trace", &[], &[0], 3, &[0], 3);
    let cluster_trace_1 = Trace::from("cluster_trace_1", &[], &[0], 2, &[0], 3);
    let cluster_trace_2 = Trace::from("cluster_trace_2", &[], &[0], 2, &[0], 3);
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
            "trace {} of cluster {} has edge size {}, but candidate trace {} has edge size {}.",
            cluster_trace_2.id(),
            cluster.id(),
            cluster_trace_2.edges.len(),
            trace.id(),
            trace.edges.len()
        )
    );

    let cluster_trace_1 = Trace::from("cluster_trace_1", &[], &[0], 3, &[0], 2);
    let cluster_trace_2 = Trace::from("cluster_trace_2", &[], &[0], 3, &[0], 2);
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
            "trace {} of cluster {} has syscall size {}, \
                but candidate trace {} has syscall size {}.",
            cluster_trace_2.id(),
            cluster.id(),
            cluster_trace_2.syscalls.len(),
            trace.id(),
            trace.syscalls.len()
        )
    );
}

#[test]
fn standard_rosa_backdoor() {
    // This is a classic backdoor scenario: the trace has system calls that the cluster (which
    // contains a single trace) does not have.
    let trace = Trace::from(
        "my_trace",
        &[],
        &[0, 10, 239, 429, 1092, 3, 18],
        u16::MAX as usize,
        &[0, 12, 39, 100, 202],
        400,
    );
    let cluster = Cluster::build(
        "my_cluster",
        &[Trace::from(
            "cluster_trace",
            &[],
            &[0, 12, 14, 3, 18, 202, 1010, 1982, 143],
            u16::MAX as usize,
            &[0, 12, 39, 202],
            400,
        )],
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
    let trace = Trace::from(
        "my_trace",
        &[],
        &[0, 10, 239, 429, 1092, 3, 18],
        u16::MAX as usize,
        &[0, 12, 39, 100],
        400,
    );
    let cluster = Cluster::build(
        "my_cluster",
        &[Trace::from(
            "cluster_trace",
            &[],
            &[0, 12, 14, 3, 18, 202, 1010, 1982, 143],
            u16::MAX as usize,
            &[0, 12, 39, 100],
            400,
        )],
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
    let trace = Trace::from(
        "my_trace",
        &[],
        &[0, 10, 100, 1000],
        u16::MAX as usize,
        &[0, 1, 2, 3],
        400,
    );
    let cluster = Cluster::build(
        "my_cluster",
        &[Trace::from(
            "cluster_trace",
            &[],
            &[0, 10, 100, 1001],
            u16::MAX as usize,
            &[0],
            400,
        )],
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
    let trace = Trace::from(
        "my_trace",
        &[],
        &[0, 10, 100, 1000],
        u16::MAX as usize,
        &[0, 1, 2, 3],
        400,
    );
    let cluster = Cluster::build(
        "my_cluster",
        &[Trace::from(
            "cluster_trace",
            &[],
            &[0, 10, 100, 1000],
            u16::MAX as usize,
            &[0],
            400,
        )],
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
