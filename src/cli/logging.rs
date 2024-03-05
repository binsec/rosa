//! Logging macros.
//!
//! These are use to pretty-print messages to the terminal. They are used by all the CLI binaries.

/// Format a generic ROSA message (prefixed by ROSA's identifier).
macro_rules! rosa_message {
    ( $( $arg:tt )* ) => {
        {
            format!(
                "[{}]  {}",
                "rosa".bold().italic().truecolor(255, 135, 135),
                format!($( $arg )*)
            )
        }
    }
}

/// Format a verbose ROSA message.
macro_rules! verbose_message {
    ( $( $arg:tt )* ) => {
        {
            rosa_message!(
                "{}",
                format!("{}", format!($( $arg )*)).dimmed()
            )
        }
    }
}

/// Format an information message (the "default" message kind).
macro_rules! info_message {
    ( $( $arg:tt )* ) => {
        {
            rosa_message!(
                "{}",
                format!("{}", format!($( $arg )*)).bold()
            )
        }
    }
}

/// Format a warning message.
macro_rules! warning_message {
    ( $( $arg:tt )* ) => {
        {
            rosa_message!(
                "{}",
                format!("WARNING: {}", format!($( $arg )*)).bold().truecolor(255, 111, 0)
            )
        }
    }
}

/// Format an error message.
macro_rules! error_message {
    ( $file:expr, $line:expr, $message:expr ) => {{
        rosa_message!(
            "{}\n        ↳ in {}:{}",
            format!("ERROR: {}", $message).bold().red(),
            $file,
            $line
        )
    }};
}

/// Print an information message (terminated by a newline).
macro_rules! println_info {
    ( $( $arg:tt )* ) => {
        {
            eprintln!("{}", info_message!($( $arg )*))
        }
    }
}

/// Print a verbose message (terminated by a newline).
macro_rules! println_verbose {
    ( $( $arg:tt )* ) => {
        {
            eprintln!("{}", verbose_message!($( $arg )*))
        }
    }
}

/// Print a warning message (terminated by a newline).
macro_rules! println_warning {
    ( $( $arg:tt )* ) => {
        {
            eprintln!("{}", warning_message!($( $arg )*))
        }
    }
}

/// Print an error message (terminated by a newline).
macro_rules! println_error {
    ( $error:expr ) => {{
        eprintln!(
            "{}",
            error_message!($error.file, $error.line, $error.message)
        )
    }};
}
