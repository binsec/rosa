use super::*;
use crate::distance_metric::hamming::Hamming;

#[test]
fn same_cluster_syscall_diffs() {
    let phase_one_traces = vec![
        Trace::build("trace_1", &[], &[0, 2], 4, &[0, 2], 3).unwrap(),
        Trace::build("trace_2", &[], &[0, 1, 2], 4, &[0, 1], 3).unwrap(),
        Trace::build("trace_3", &[], &[1, 2], 4, &[1, 2], 3).unwrap(),
        Trace::build("trace_4", &[], &[0], 4, &[0, 1, 2], 3).unwrap(),
    ];

    let clusters = cluster_traces(&phase_one_traces, Criterion::EdgesOnly, Hamming, 0, 0).unwrap();

    assert_eq!(clusters.len(), 4);
    assert_eq!(clusters[0].traces.len(), 1);
    assert_eq!(clusters[0].traces[0].name(), "trace_1".to_string());
    assert_eq!(clusters[1].traces.len(), 1);
    assert_eq!(clusters[1].traces[0].name(), "trace_2".to_string());
    assert_eq!(clusters[2].traces.len(), 1);
    assert_eq!(clusters[2].traces[0].name(), "trace_3".to_string());
    assert_eq!(clusters[3].traces.len(), 1);
    assert_eq!(clusters[3].traces[0].name(), "trace_4".to_string());

    let new_trace = Trace::build("trace_5", &[], &[0, 1, 2, 3], 4, &[0, 1, 2], 3).unwrap();

    let most_similar_cluster =
        get_most_similar_cluster(&new_trace, &clusters, Criterion::EdgesAndSyscalls, Hamming)
            .unwrap();
    assert_eq!(most_similar_cluster.traces.len(), 1);
    assert_eq!(most_similar_cluster.traces[0].name(), "trace_2".to_string());
}

#[test]
fn same_cluster_edge_diffs() {
    let phase_one_traces = vec![
        Trace::build("trace_1", &[], &[0, 2], 4, &[0, 2], 3).unwrap(),
        Trace::build("trace_2", &[], &[0, 1], 4, &[0, 1], 3).unwrap(),
        Trace::build("trace_3", &[], &[1, 2], 4, &[0, 1, 2], 3).unwrap(),
        Trace::build("trace_4", &[], &[0], 4, &[0, 1, 2], 3).unwrap(),
    ];

    let clusters = cluster_traces(&phase_one_traces, Criterion::EdgesOnly, Hamming, 0, 0).unwrap();

    assert_eq!(clusters.len(), 4);
    assert_eq!(clusters[0].traces.len(), 1);
    assert_eq!(clusters[0].traces[0].name(), "trace_1".to_string());
    assert_eq!(clusters[1].traces.len(), 1);
    assert_eq!(clusters[1].traces[0].name(), "trace_2".to_string());
    assert_eq!(clusters[2].traces.len(), 1);
    assert_eq!(clusters[2].traces[0].name(), "trace_3".to_string());
    assert_eq!(clusters[3].traces.len(), 1);
    assert_eq!(clusters[3].traces[0].name(), "trace_4".to_string());

    let new_trace = Trace::build("trace_5", &[], &[0, 1, 2, 3], 4, &[0, 1, 2], 3).unwrap();

    let most_similar_cluster =
        get_most_similar_cluster(&new_trace, &clusters, Criterion::EdgesAndSyscalls, Hamming)
            .unwrap();
    assert_eq!(most_similar_cluster.traces.len(), 1);
    assert_eq!(most_similar_cluster.traces[0].name(), "trace_3".to_string());
}
