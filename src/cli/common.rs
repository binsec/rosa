//! Common functions and elements used by various binaries in the ROSA toolchain.

use clap::ValueEnum;

/// The component to analyze.
#[derive(Clone, ValueEnum)]
pub enum Component {
    /// Only take edges into account.
    Edges,
    /// Only take system calls into account.
    Syscalls,
}

// Reset SIGPIPE, so that the output of may be piped to other stuff.
// See https://stackoverflow.com/q/65755853/.
pub fn reset_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}
