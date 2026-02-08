#![deny(missing_docs)]
#![doc(test(attr(deny(warnings))))]
// TODO: add crate-level README
#![doc = include_str!("../../../README.md")]

pub mod clustering;
pub mod config;
pub mod distance_metric;
pub mod fuzzer;
pub mod oracle;
pub mod trace;

#[macro_use]
#[allow(unused_macros)]
pub mod logging;

/// Reset SIGPIPE, so that the output of may be piped to other stuff.
/// See <https://stackoverflow.com/q/65755853/>.
pub fn reset_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}
