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
            _ => return Err(Error::Filetype),
        };
        Ok(t)
    }

    pub fn is_file(&self) -> bool {
        matches!(self, Self::File)
    }
}

#[derive(Debug)]
pub struct FileEntry {
    pub filetype: FileType,
    pub path: RelativePath,
}

impl FileEntry {
    pub fn new(filetype: FileType, path: RelativePath) -> Self {
        Self { filetype, path }
    }

    pub fn into_vec(self) -> Vec<u8> {
        let path = self.path.as_ref();
        let mut data = Vec::with_capacity(1 + path.len());
        data.push(self.filetype.into_byte());
        data.extend_from_slice(path);
        data
    }

    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, Error> {
        let t = bytes.first().ok_or(Error::Filetype)?;
        let path = RelativePath::from_bytes(&bytes[1..]).map_err(Error::Path)?;
        Ok(Self {
            filetype: FileType::from_byte(*t)?,
            path,
        })
    }
}
