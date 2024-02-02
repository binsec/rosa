use std::{error, fmt};

use colored::Colorize;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct RosaError {
    pub function: String,
    pub line: u32,
    pub file: String,
    pub message: String,
}

impl error::Error for RosaError {}
impl fmt::Display for RosaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", error_message!(self.file, self.line, self.message))
    }
}

macro_rules! error {
    ( $( $arg:expr ),+ ) => {{
        RosaError {
            message: format!($( $arg ),+),
            function: module_path!().to_string(),
            file: file!().to_string(),
            line: line!(),
        }
    }};
}

macro_rules! fail {
    ( $( $arg:expr ),+ ) => {{
        Err(error!($( $arg ),+))
    }};
}
