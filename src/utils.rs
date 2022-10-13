use std::fmt::{Debug, Display};
use std::fs::{self, File};
use std::path::{Path, PathBuf};

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

pub fn current_dir() -> PathBuf {
    std::env::current_dir().unwrap_exit(|| "Get working directory failed")
}

pub fn create_dir<P: AsRef<Path>>(p: P) {
    fs::create_dir_all(&p)
        .unwrap_exit(|| format!("Create directory failed '{}'", p.as_ref().display()));
}

pub fn create_file<P: AsRef<Path>>(p: P) -> File {
    let p = p.as_ref();
    if let Some(parent) = p.parent() {
        create_dir(parent);
    }
    File::create(&p).unwrap_exit(|| format!("Create file failed '{}'", p.display()))
}

pub fn open_file<P: AsRef<Path>>(p: P) -> File {
    File::open(&p).unwrap_exit(|| format!("Open fail failed '{}'", p.as_ref().display()))
}

pub trait ThrowOptionError<D: Display, F: FnOnce() -> D, T> {
    fn unwrap_exit(self, f: F) -> T;
}

impl<D: Display, F: FnOnce() -> D, T> ThrowOptionError<D, F, T> for Option<T> {
    fn unwrap_exit(self, f: F) -> T {
        match self {
            Some(data) => data,
            None => {
                exit!("{}", f());
            }
        }
    }
}

pub trait ThrowResultError<D: Display, E, F: FnOnce() -> D, T> {
    fn unwrap_exit(self, f: F) -> T;
}

impl<D: Display, E: Debug, F: FnOnce() -> D, T> ThrowResultError<D, E, F, T> for Result<T, E> {
    fn unwrap_exit(self, f: F) -> T {
        match self {
            Ok(data) => data,
            Err(err) => {
                exit!("{} {:?}", f(), err)
            }
        }
    }
}
