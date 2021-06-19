mod cli;
mod crypto;
mod error;
use crypto::{rand_salt, read_header, write_header, Cipher};
pub use error::*;
use std::io::{BufWriter, BufReader, Read, Write};

const IDENTIFY: &[u8; 4] = b"\xffAEF";
const BUG_SIZE: usize = 8 * 1024;

fn main() {
    let (password, force_encrypt, params, input, output) = cli::parse();

    let mut reader = BufReader::with_capacity(BUG_SIZE, input);
    let mut writer = BufWriter::with_capacity(BUG_SIZE, output);

    let mut identify = vec![0; IDENTIFY.len()];
    match reader.read(&mut identify) {
        Ok(n) => {
            if n < IDENTIFY.len() {
                identify.truncate(n);
            }
        }
        Err(err) => exit!("{:?}", err),
    }

    if identify == IDENTIFY && !force_encrypt { //we probably want to decrypt
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
    } else { //otherwise, encrypt
        let salt = rand_salt();
        let cipher = Cipher::new(&password, &salt, &params);
        write_header(&mut writer, &salt, &params).unwrap_exit();

        let mut buf = [0; BUG_SIZE];

        buf[..identify.len()].clone_from_slice(&identify);
        match reader.read(&mut buf[identify.len()..]) {
            Ok(n) => {
                cipher.write_chunk(&buf[..n+identify.len()], &mut writer).unwrap_exit();
            }
            Err(err) => exit!("{:?}", err),
        }

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
}
