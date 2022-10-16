// Fork from: https://github.com/bbqsrc/box
// BoxPath: https://github.com/bbqsrc/box/blob/808560577930872c79be8953b5d2b9b88f70f8e3/box-format/src/path/mod.rs

use std::path::{Component, Path, PathBuf};
use std::{fmt, str};
use unic_normal::StrNormalForm;
use unic_ucd::GeneralCategory;

#[cfg(windows)]
pub const PLATFORM_PATH_SEP: &str = "\\";
#[cfg(not(windows))]
pub const PLATFORM_PATH_SEP: &str = "/";

const PATH_SEP: &str = "\x1f";

#[derive(Clone, Debug)]
pub struct RelativePath {
    inner: String,
}

#[derive(Debug)]
pub enum RelativePathError {
    Invalid,
    Empty,
}

impl RelativePath {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, RelativePathError> {
        let mut chunks = vec![];
        for component in path.as_ref().components() {
            match component {
                Component::Normal(os_str) => {
                    let s = os_str.to_str().ok_or(RelativePathError::Invalid)?;
                    if !Self::check_chunk(s) {
                        return Err(RelativePathError::Invalid);
                    }
                    chunks.push(s.nfc().collect::<String>());
                }
                Component::ParentDir => {
                    chunks.pop();
                }
                Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            }
        }
        if chunks.is_empty() {
            return Err(RelativePathError::Empty);
        }
        Ok(Self {
            inner: chunks.join(PATH_SEP),
        })
    }

    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, RelativePathError> {
        let s = str::from_utf8(bytes.as_ref()).map_err(|_| RelativePathError::Invalid)?;
        let path = s.replace(PATH_SEP, PLATFORM_PATH_SEP);
        Self::new(path)
    }

    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf::from(self.to_string())
    }

    fn check_chunk(chunk: &str) -> bool {
        let s = chunk.trim();
        if s.is_empty() {
            return false;
        }
        !s.chars().any(|c| {
            let cat = GeneralCategory::of(c);
            c == '\\' || cat == GeneralCategory::Control || (cat.is_separator() && c != ' ')
        })
    }
}

impl AsRef<[u8]> for RelativePath {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl fmt::Display for RelativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut iter = self.inner.split(PATH_SEP);
        if let Some(v) = iter.next() {
            f.write_str(v)?;
        }
        for v in iter {
            f.write_str(PLATFORM_PATH_SEP)?;
            f.write_str(v)?;
        }
        Ok(())
    }
}
