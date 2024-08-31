use super::BUF_SIZE;
use brotli::enc::reader::CompressorReader;
use brotli::DecompressorWriter;
use std::io::{BufReader, BufWriter, Read, Result, Write};

pub const MIN_COMPRESS_LEVEL: u32 = 0;
pub const MAX_COMPRESS_LEVEL: u32 = 11;
pub const DEFAULT_COMPRESS_LEVEL: u32 = MIN_COMPRESS_LEVEL;

pub enum EncodingReader<R: Read> {
    None(BufReader<R>),
    Brotli(Box<CompressorReader<BufReader<R>>>),
}

impl<R: Read> EncodingReader<R> {
    pub fn new(r: R, compress: &Option<u32>) -> Self {
        let reader = BufReader::with_capacity(BUF_SIZE, r);
        match compress {
            None => Self::None(reader),
            // TODO: lgwin size
            Some(q) => Self::Brotli(Box::new(CompressorReader::new(reader, BUF_SIZE, *q, 22))),
        }
    }
}

impl<R: Read> Read for EncodingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::None(r) => r.read(buf),
            Self::Brotli(r) => r.read(buf),
        }
    }
}

pub enum DecodingWriter<W: Write> {
    None(BufWriter<W>),
    Brotli(Box<DecompressorWriter<BufWriter<W>>>),
}

impl<W: Write> DecodingWriter<W> {
    pub fn new(w: W, compressed: bool) -> Self {
        let writer = BufWriter::with_capacity(BUF_SIZE, w);
        match compressed {
            false => Self::None(writer),
            true => Self::Brotli(Box::new(DecompressorWriter::new(writer, BUF_SIZE))),
        }
    }
}

impl<W: Write> Write for DecodingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self {
            Self::None(w) => w.write(buf),
            Self::Brotli(w) => w.write(buf),
        }
    }
    fn flush(&mut self) -> Result<()> {
        match self {
            Self::None(w) => w.flush(),
            Self::Brotli(w) => w.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPRESSED: &'static [u8] = &[
        139, 255, 1, 0, 32, 0, 216, 0, 14, 92, 195, 73, 101, 54, 128, 11, 112, 88, 190, 109,
    ];

    #[test]
    fn encoding() {
        let mut reader = EncodingReader::new(&[0; 1024][..], &Some(1));
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, COMPRESSED);
    }

    #[test]
    fn decoding() {
        let mut data = Vec::new();
        {
            let mut writer = DecodingWriter::new(&mut data, true);
            writer.write_all(COMPRESSED).unwrap();
        }
        assert_eq!(data, [0; 1024]);
    }
}
