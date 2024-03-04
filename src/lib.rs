//! Runtime trace Oracle-based Selection Algorithm for backdoor detection.
//!
//! This crate is the core of the ROSA backdoor detection tool; it's the backend for the actual CLI
//! backdoor detection tool `rosa`, as well as other diagnostic tools.
#![deny(missing_docs)]
#![doc(test(attr(deny(warnings))))]

#[macro_use]
pub mod error;

pub mod clustering;
pub mod config;
pub mod criterion;
pub mod decision;
pub mod distance_metric;
pub mod fuzzer;
pub mod oracle;
pub mod trace;
