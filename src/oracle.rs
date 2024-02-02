use crate::{
    clustering::Cluster,
    criterion::Criterion,
    decision::{Decision, DecisionReason},
    distance_metric::DistanceMetric,
    trace::Trace,
};

#[derive(Copy, Clone)]
pub enum Oracle {
    CompMinMax,
}

impl Oracle {
    pub fn from_str(oracle: &str) -> Option<Self> {
        match oracle {
            "comp_min_max" => Some(Self::CompMinMax),
            _ => None,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Self::CompMinMax => "comp_min_max",
        }
    }

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
        is_backdoor,
        reason,
    }
}
