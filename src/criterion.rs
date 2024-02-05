use std::fmt;

#[derive(Clone, Copy)]
pub enum Criterion {
    EdgesOnly,
    SyscallsOnly,
    EdgesOrSyscalls,
    EdgesAndSyscalls,
}

impl Criterion {
    pub fn from_str(criterion: &str) -> Option<Self> {
        match criterion {
            "edges-only" => Some(Criterion::EdgesOnly),
            "syscalls-only" => Some(Criterion::SyscallsOnly),
            "edges-or-syscalls" => Some(Criterion::EdgesOrSyscalls),
            "edges-and-syscalls" => Some(Criterion::EdgesAndSyscalls),
            _ => None,
        }
    }
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
