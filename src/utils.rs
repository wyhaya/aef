use std::fmt::{Debug, Display};

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

pub trait ThrowError<D: Display, E, F: FnOnce() -> D, T> {
    fn unwrap_exit(self, f: F) -> T;
}

impl<D: Display, E: Debug, F: FnOnce() -> D, T> ThrowError<D, E, F, T> for Result<T, E> {
    fn unwrap_exit(self, f: F) -> T {
        self.unwrap_or_else(|err| exit!("{} {:?}", f(), err))
    }
}
