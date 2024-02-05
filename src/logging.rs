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

macro_rules! debug_message {
    ( $( $arg:tt )* ) => {
        {
            rosa_message!(
                "{}",
                format!("DEBUG: {}", format!($( $arg )*)).dimmed()
            )
        }
    }
}

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

macro_rules! println_info {
    ( $( $arg:tt )* ) => {
        {
            eprintln!("{}", info_message!($( $arg )*))
        }
    }
}

macro_rules! println_debug {
    ( $( $arg:tt )* ) => {
        {
            eprintln!("{}", debug_message!($( $arg )*))
        }
    }
}

macro_rules! println_error {
    ( $error:expr ) => {{
        eprintln!(
            "{}",
            error_message!($error.file, $error.line, $error.message)
        )
    }};
}
