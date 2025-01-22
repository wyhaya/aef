mod aef;
mod cli;
mod utils;

use aef::{rand_salt, Cipher, Error, FileHeader};
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
    let cipher = Cipher::new(&password, salt);
    loop {
        let rst = cipher.read_chunk(&mut input);
        match rst {
            Some(Ok(data)) => {
                output.write_all(&data).map_err(Error::Io)?;
            }
            Some(Err(err)) => return Err(err),
            None => break,
        }
    }
    Ok(())
}

fn encrypt(mut input: Input, mut output: Output, password: Password) -> Result<(), Error> {
    let salt = rand_salt();
    let cipher = Cipher::new(&password, salt);
    FileHeader::new(salt, password.params.clone())
        .write_to(&mut output)
        .map_err(Error::Io)?;
    let mut buf = [0; 32 * 1024];
    loop {
        let n = input.read(&mut buf).map_err(Error::Io)?;
        if n == 0 {
            return cipher.write_chunk(&mut output, Vec::new());
        }
        cipher.write_chunk(&mut output, buf[..n].to_vec())?;
    }
}
