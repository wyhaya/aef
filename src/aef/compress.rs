use super::BUF_SIZE;
use brotli::enc::reader::CompressorReader;
use brotli::DecompressorWriter;
use std::io::{BufReader, BufWriter, Read, Result, Write};

pub enum EncodingReader<R: Read> {
    None(BufReader<R>),
    Brotli(CompressorReader<BufReader<R>>),
}

impl<R: Read> EncodingReader<R> {
    pub fn new(r: R, compress: &Option<u32>) -> Self {
        let reader = BufReader::with_capacity(BUF_SIZE, r);
        match compress {
            None => Self::None(reader),
            // TODO
            // lgwin size
            Some(q) => Self::Brotli(CompressorReader::new(reader, BUF_SIZE, *q, 22)),
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
    Brotli(DecompressorWriter<BufWriter<W>>),
}

impl<W: Write> DecodingWriter<W> {
    pub fn new(w: W, compressed: bool) -> Self {
        let writer = BufWriter::with_capacity(BUF_SIZE, w);
        match compressed {
            false => Self::None(writer),
            true => Self::Brotli(DecompressorWriter::new(writer, BUF_SIZE)),
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
