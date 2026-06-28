mod aef;
mod cli;
mod utils;

use aef::{Chunk, Cipher, Error, FileHeader, ensure_eof, rand_salt};
use cli::{Input, Output, Password};
use std::fs;
use std::io::{Read, Write};
use utils::ThrowError;

fn main() {
    let (input, output, password, de, delete_input) = cli::parse();
    if de {
        decrypt(input, output, password)
    } else {
        encrypt(input, output, password)
    }
    .unwrap_or_else(|err| exit!("{:?}", err));

    if let Some(p) = delete_input {
        // TODO: Secure Erase
        fs::remove_file(p).unwrap_exit(|| "Failed to delete input file");
    }
}

fn decrypt(mut input: Input, mut output: Output, mut password: Password) -> Result<(), Error> {
    let FileHeader { salt, params } = FileHeader::read_from(&mut input).map_err(Error::Io)?;
    password.params = params;
    let header = FileHeader::new(salt, password.params.clone());
    let cipher = Cipher::new(&password, &header);
    let mut index = 0;
    loop {
        match cipher.read_chunk(&mut input, index)? {
            Chunk::Data(data) => {
                output.write_all(&data).map_err(Error::Io)?;
                index = index.checked_add(1).ok_or(Error::Decryption)?;
            }
            Chunk::End => {
                ensure_eof(&mut input)?;
                break;
            }
        }
    }
    Ok(())
}

fn encrypt(mut input: Input, mut output: Output, password: Password) -> Result<(), Error> {
    let salt = rand_salt();
    let header = FileHeader::new(salt, password.params.clone());
    let cipher = Cipher::new(&password, &header);
    header.write_to(&mut output).map_err(Error::Io)?;
    let mut buf = [0; 32 * 1024];
    let mut index = 0;
    loop {
        let n = input.read(&mut buf).map_err(Error::Io)?;
        if n == 0 {
            return cipher.write_chunk(&mut output, index, Vec::new());
        }
        cipher.write_chunk(&mut output, index, buf[..n].to_vec())?;
        index = index.checked_add(1).ok_or(Error::Encryption)?;
    }
}
