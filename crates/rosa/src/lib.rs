#![deny(missing_docs)]
#![doc(test(attr(deny(warnings))))]
// TODO: maybe add a crate-specific README here.
#![doc = include_str!("../../../README.md")]

#[macro_use]
pub mod error;

pub mod clustering;
pub mod criterion;
pub mod distance_metric;
pub mod oracle;
pub mod trace;
