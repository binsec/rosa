//! Criteria to determine which component of a runtime trace should be taken into account
//!
//! Since runtime traces have two components (CFG edges and syscalls), there are multiple ways to
//! take either (or both) into account, for example when computing the similarity between two
//! traces. This is materialized through a **criterion**.

use std::{fmt, str};

use serde::{Deserialize, Serialize};

use crate::error::RosaError;

/// A criterion to describe which component(s) of the runtime trace are taken into account.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum Criterion {
    /// Only the edge component of the runtime trace is taken into account.
    #[serde(rename = "edges-only")]
    EdgesOnly,
    /// Only the syscall component of the runtime trace is taken into account.
    #[serde(rename = "syscalls-only")]
    SyscallsOnly,
    /// Either the edge or the syscall component of the runtime trace is taken into account.
    /// The meaning of this criterion depends on the application; in general, you should think of
    /// it as a _logical OR_ between [Criterion::EdgesOnly] and [Criterion::SyscallsOnly].
    #[serde(rename = "edges-or-syscalls")]
    EdgesOrSyscalls,
    /// Both the edge and the syscall components of the runtime trace are taken into account.
    /// The meaning of this criterion depends on the application; in general, you should think of
    /// it as a _logical AND_ between [Criterion::EdgesOnly] and [Criterion::SyscallsOnly].
    #[serde(rename = "edges-and-syscalls")]
    EdgesAndSyscalls,
}

impl fmt::Display for Criterion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::EdgesOnly => "edges-only",
                Self::SyscallsOnly => "syscalls-only",
                Self::EdgesOrSyscalls => "edges-or-syscalls",
                Self::EdgesAndSyscalls => "edges-and-syscalls",
            }
        )
    }
}

impl str::FromStr for Criterion {
    type Err = RosaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "edges-only" => Ok(Self::EdgesOnly),
            "syscalls-only" => Ok(Self::SyscallsOnly),
            "edges-or-syscalls" => Ok(Self::EdgesOrSyscalls),
            "edges-and-syscalls" => Ok(Self::EdgesAndSyscalls),
            unknown => fail!("invalid criterion '{}'.", unknown),
        }
    }
}
