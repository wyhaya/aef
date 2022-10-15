pub mod compress;
pub mod crypto;
pub mod entry;
pub mod header;
pub mod path;

use compress::{DecodingWriter, EncodingReader};
use crypto::{rand_salt, Cipher};
use entry::{FileEntry, FileType};
use header::FileHeader;
use path::{RelativePath, RelativePathError};
use scrypt::Params;
use std::io::{BufReader, BufWriter, Error as IoError, Read, Write};
use std::path::Path;

pub const BUF_SIZE: usize = 8 * 1024;

#[derive(Debug)]
pub enum Error {
    Io(IoError),
    Aes,
    Filetype,
    Path(RelativePathError),
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
        let path = RelativePath::new(path).map_err(Error::Path)?;
        let entry = FileEntry::new(FileType::Directory, path);
        self.cipher
            .write_chunk(&mut self.output, &entry.into_vec())?;
        Ok(())
    }

    pub fn append_file<R: Read>(&mut self, path: &Path, input: &mut R) -> Result<(), Error> {
        let path = RelativePath::new(path).map_err(Error::Path)?;
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
