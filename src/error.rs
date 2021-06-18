pub use std::io::{Error as IoError, ErrorKind, Result as IoResult};

#[macro_export]
macro_rules! exit {
    ($($arg:tt)*) => {
       {
            eprint!("Error: ");
            eprintln!($($arg)*);
            std::process::exit(1)
       }
    };
}

pub trait ToIoResult<T> {
    fn io_rst(self, kind: ErrorKind, msg: &str) -> IoResult<T>;
}

impl<T, E> ToIoResult<T> for Result<T, E> {
    fn io_rst(self, kind: ErrorKind, msg: &str) -> IoResult<T> {
        match self {
            Ok(data) => Ok(data),
            Err(_) => Err(IoError::new(kind, msg)),
        }
    }
}

pub trait ThrowError<T> {
    fn unwrap_exit(self) -> T;
}

impl<T> ThrowError<T> for IoResult<T> {
    fn unwrap_exit(self) -> T {
        match self {
            Ok(data) => data,
            Err(err) => exit!("{:?}", err),
        }
    }
}
