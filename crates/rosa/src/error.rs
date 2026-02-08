//! ROSA-related errors and error macros.

use std::{error, fmt};

/// A ROSA error.
#[derive(Debug, Clone)]
pub struct RosaError {
    /// The line where the error was produced.
    pub line: u32,
    /// The file where the error was produced.
    pub file: String,
    /// The error message.
    pub message: String,
}

impl error::Error for RosaError {}
impl fmt::Display for RosaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Produce a [RosaError] on a given line, in a given file.
#[macro_export]
macro_rules! error {
    ( $( $arg:expr ),+ ) => {{
        RosaError {
            message: format!($( $arg ),+),
            file: file!().to_string(),
            line: line!(),
        }
    }};
}

/// Produce a [RosaError] wrapped in an [Err].
#[macro_export]
macro_rules! fail {
    ( $( $arg:expr ),+ ) => {{
        Err(error!($( $arg ),+))
    }};
}
