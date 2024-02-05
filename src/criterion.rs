use std::{fmt, str};

use serde::{Deserialize, Serialize};

use crate::error::RosaError;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum Criterion {
    EdgesOnly,
    SyscallsOnly,
    EdgesOrSyscalls,
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
