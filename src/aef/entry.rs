use super::path::RelativePath;
use super::Error;

#[derive(Debug, PartialEq, Eq)]
pub enum FileType {
    Directory,
    File,
}

impl FileType {
    fn into_byte(self) -> u8 {
        match self {
            Self::Directory => 0,
            Self::File => 1,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, Error> {
        let t = match byte {
            0 => Self::Directory,
            1 => Self::File,
            _ => return Err(Error::Entry),
        };
        Ok(t)
    }

    pub fn is_file(&self) -> bool {
        matches!(self, Self::File)
    }
}

// '0' means ignoring power permissions
const NONE_PERMISSIONS: u32 = 0;

#[derive(Debug)]
pub struct FileEntry {
    pub filetype: FileType,
    pub permissions: Option<u32>,
    pub path: RelativePath,
}

impl FileEntry {
    pub fn new(filetype: FileType, path: RelativePath, permissions: Option<u32>) -> Self {
        Self {
            filetype,
            path,
            permissions,
        }
    }

    pub fn into_vec(self) -> Vec<u8> {
        let path = self.path.as_ref();
        let mut data = Vec::with_capacity(1 + 4 + path.len());
        data.push(self.filetype.into_byte());
        data.extend_from_slice(&self.permissions.unwrap_or(NONE_PERMISSIONS).to_be_bytes());
        data.extend_from_slice(path);
        data
    }

    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, Error> {
        let min_len = 1 + 4 + 1;
        if bytes.len() < min_len {
            return Err(Error::Entry);
        }

        let filetype = FileType::from_byte(bytes[0])?;

        let permissions = match bytes[1..=4].try_into() {
            Ok(bytes) => {
                let n = u32::from_be_bytes(bytes);
                if n == NONE_PERMISSIONS {
                    None
                } else {
                    Some(n)
                }
            }
            Err(_) => unreachable!(),
        };

        let path = RelativePath::from_bytes(&bytes[5..]).map_err(Error::Path)?;

        Ok(Self {
            filetype,
            permissions,
            path,
        })
    }
}
