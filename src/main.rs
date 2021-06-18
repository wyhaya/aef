mod cli;
mod crypto;
mod error;
use crypto::{rand_salt, read_header, write_header, Cipher};
pub use error::*;
use std::io::{BufReader, BufWriter, Read, Write};

const BUG_SIZE: usize = 8 * 1024;

fn main() {
    let (password, params, input, output) = cli::parse();

    let mut reader = BufReader::with_capacity(BUG_SIZE, input);
    let mut writer = BufWriter::with_capacity(BUG_SIZE, output);

    match params {
        Some(params) => {
            let salt = rand_salt();
            let cipher = Cipher::new(&password, &salt, &params);
            write_header(&mut writer, &salt, &params).unwrap_exit();

            let mut buf = [0; BUG_SIZE];
            loop {
                match reader.read(&mut buf) {
                    Ok(n) => {
                        cipher.write_chunk(&buf[..n], &mut writer).unwrap_exit();
                        if n == 0 {
                            break;
                        }
                    }
                    Err(err) => exit!("{:?}", err),
                }
            }
        }
        None => {
            let (salt, params) = read_header(&mut reader).unwrap_exit();
            let cipher = Cipher::new(&password, &salt, &params);

            loop {
                match cipher.read_chunk(&mut reader) {
                    Ok(data) => {
                        if data.is_empty() {
                            break;
                        } else {
                            writer.write_all(&data).unwrap_exit();
                        }
                    }
                    Err(err) => exit!("{:?}", err),
                }
            }
        }
    }
}
