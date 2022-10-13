use crate::compress::{DecodingWriter, EncodingReader};
use crate::crypto::{rand_salt, Cipher};
use scrypt::Params;
use std::ffi::OsStr;
use std::io::{BufReader, BufWriter, Error as IoError, ErrorKind, Read, Result as IoResult, Write};
use std::os::unix::prelude::OsStrExt;
use std::path::{Path, PathBuf};

pub const BUF_SIZE: usize = 8 * 1024;

#[derive(Debug)]
pub enum Error {
    Io(IoError),
    Aes,
    Filetype(u8),
    Incomplete,
}

#[derive(Debug)]
struct FileHeader {
    salt: [u8; 64],
    params: Params,
    compress: bool,
}

impl FileHeader {
    const IDENTIFY: &[u8; 4] = b"\xffAEF";
    const COMPRESS_OFF: u8 = 0;
    const COMPRESS_ON: u8 = 1;

    pub fn new(salt: [u8; 64], params: Params, compress: bool) -> Self {
        Self {
            salt,
            params,
            compress,
        }
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> IoResult<()> {
        w.write_all(&Self::IDENTIFY[..])?;
        w.write_all(&self.salt)?;
        w.write_all(&self.params.log_n().to_be_bytes())?;
        w.write_all(&self.params.r().to_be_bytes())?;
        w.write_all(&self.params.p().to_be_bytes())?;
        if self.compress {
            w.write_all(&[Self::COMPRESS_ON])?;
        } else {
            w.write_all(&[Self::COMPRESS_OFF])?;
        }
        w.flush()
    }

    pub fn read_from<R: Read>(r: &mut R) -> IoResult<Self> {
        let mut identify = [0; 4];
        r.read_exact(&mut identify)?;
        if &identify != Self::IDENTIFY {
            return Err(IoError::new(ErrorKind::Other, "Invalid identify"));
        }

        let mut salt = [0; 64];
        r.read_exact(&mut salt)?;
        let mut log_n_buf = [0; 1];
        r.read_exact(&mut log_n_buf)?;
        let mut r_buf = [0; 4];
        r.read_exact(&mut r_buf)?;
        let mut p_buf = [0; 4];
        r.read_exact(&mut p_buf)?;

        let params = Params::new(
            log_n_buf[0],
            u32::from_be_bytes(r_buf),
            u32::from_be_bytes(p_buf),
        )
        .map_err(|_| IoError::new(ErrorKind::Other, "Error scrypt params"))?;

        let mut c_buf = [0; 1];
        r.read_exact(&mut c_buf)?;

        Ok(Self {
            salt,
            params,
            compress: c_buf[0] == Self::COMPRESS_ON,
        })
    }
}

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
            n => return Err(Error::Filetype(n)),
        };
        Ok(t)
    }

    pub fn is_file(&self) -> bool {
        matches!(self, Self::File)
    }
}

#[derive(Debug)]
pub struct FileEntry {
    filetype: FileType,
    path: PathBuf,
}

impl FileEntry {
    fn new(filetype: FileType, path: &Path) -> Self {
        Self {
            filetype,
            path: path.to_path_buf(),
        }
    }

    fn into_vec(self) -> Vec<u8> {
        let path = self.path.as_os_str().as_bytes();
        let mut data = Vec::with_capacity(1 + path.len());
        data.push(self.filetype.into_byte());
        data.extend_from_slice(path);
        data
    }

    fn from_vec(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() < 2 {
            return Err(Error::Incomplete);
        }
        Ok(Self {
            filetype: FileType::from_byte(bytes[0])?,
            path: Path::new(OsStr::from_bytes(&bytes[1..])).to_path_buf(),
        })
    }

    pub fn filetype(&self) -> &FileType {
        &self.filetype
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub struct Encoder<W: Write> {
    output: BufWriter<W>,
    cipher: Cipher,
    compress: Option<u32>,
}

pub struct Decoder<R: Read> {
    input: BufReader<R>,
    cipher: Cipher,
    compress: bool,
}

impl<W: Write> Encoder<W> {
    pub fn new(
        output: W,
        password: &str,
        params: Params,
        compress: Option<u32>,
    ) -> Result<Self, Error> {
        let salt = rand_salt();
        let mut output = BufWriter::with_capacity(BUF_SIZE, output);
        FileHeader::new(salt, params, compress.is_some())
            .write_to(&mut output)
            .map_err(Error::Io)?;
        let cipher = Cipher::new(password, &salt, &params);
        Ok(Self {
            output,
            cipher,
            compress,
        })
    }

    pub fn append_directory(&mut self, path: &Path) -> Result<(), Error> {
        let entry = FileEntry::new(FileType::Directory, path);
        self.cipher
            .write_chunk(&mut self.output, &entry.into_vec())?;
        Ok(())
    }

    pub fn append_file<R: Read>(&mut self, path: &Path, input: &mut R) -> Result<(), Error> {
        let entry = FileEntry::new(FileType::File, path);
        self.cipher
            .write_chunk(&mut self.output, &entry.into_vec())?;

        let mut reader = EncodingReader::new(input, &self.compress);

        let mut buf = [0; BUF_SIZE];
        loop {
            let n = reader.read(&mut buf).map_err(Error::Io)?;
            if n == 0 {
                self.cipher.write_chunk(&mut self.output, &[])?;
                return Ok(());
            } else {
                self.cipher.write_chunk(&mut self.output, &buf[..n])?;
            }
        }
    }
}

impl<R: Read> Decoder<R> {
    pub fn new(input: R, password: &str) -> Result<Self, Error> {
        let mut input = BufReader::with_capacity(BUF_SIZE, input);
        let header = FileHeader::read_from(&mut input).map_err(Error::Io)?;
        let cipher = Cipher::new(password, &header.salt, &header.params);
        Ok(Self {
            input,
            cipher,
            compress: header.compress,
        })
    }

    pub fn read_entry(&mut self) -> Option<Result<FileEntry, Error>> {
        let rst = self.cipher.read_chunk(&mut self.input)?;
        let bytes = match rst {
            Ok(v) => v,
            Err(err) => return Some(Err(err)),
        };
        Some(FileEntry::from_vec(bytes))
    }

    pub fn read_data_to<W: Write>(&mut self, output: &mut W) -> Result<(), Error> {
        let mut writer = DecodingWriter::new(output, self.compress);

        loop {
            let opt = self.cipher.read_chunk(&mut self.input);
            match opt {
                Some(rst) => {
                    let bytes = rst?;
                    if bytes.is_empty() {
                        break;
                    }
                    if let Err(err) = writer.write(&bytes) {
                        return Err(Error::Io(err));
                    }
                }
                None => break,
            }
        }
        writer.flush().map_err(Error::Io)
    }
}
