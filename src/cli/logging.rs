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

macro_rules! println_verbose {
    ( $( $arg:tt )* ) => {
        {
            eprintln!("{}", verbose_message!($( $arg )*))
        }
    }
}

macro_rules! println_warning {
    ( $( $arg:tt )* ) => {
        {
            eprintln!("{}", warning_message!($( $arg )*))
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
