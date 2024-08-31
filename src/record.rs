use crate::aef::entry::FileType;
use crate::aef::path::{RelativePath, PLATFORM_PATH_SEP};
use std::io::{stdout, StdoutLock, Write};
use std::path::Path;

pub struct Record<'a> {
    stdout: StdoutLock<'a>,
}

impl<'a> Record<'a> {
    pub fn new() -> Self {
        Self {
            stdout: stdout().lock(),
        }
    }

    pub fn add(&mut self, t: FileType, p: &Path) {
        match t {
            FileType::File => {
                writeln!(self.stdout, "{}", p.display())
            }
            FileType::Directory => {
                writeln!(self.stdout, "{}{}", p.display(), PLATFORM_PATH_SEP)
            }
        }
        .expect("Unknown");
    }

    pub fn write(&mut self, t: FileType, p: &RelativePath) {
        match t {
            FileType::File => {
                writeln!(self.stdout, "{}", p)
            }
            FileType::Directory => {
                writeln!(self.stdout, "{}{}", p, PLATFORM_PATH_SEP)
            }
        }
        .expect("Unknown");
    }
}
