use crate::aef::Error;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::Rng;
use scrypt::{scrypt, Params};
use std::io::{ErrorKind, Read, Write};

pub const SCRYPT_LOG_N: u8 = 20;
pub const SCRYPT_R: u32 = 8;
pub const SCRYPT_P: u32 = 1;

fn rand_nonce() -> [u8; 12] {
    let mut buf = [0; 12];
    rand::thread_rng().fill(&mut buf);
    buf
}

pub fn rand_salt() -> [u8; 64] {
    let mut buf = [0; 64];
    rand::thread_rng().fill(&mut buf);
    buf
}

pub struct Cipher {
    aes: Aes256Gcm,
}

impl Cipher {
    pub fn new(password: &str, salt: &[u8; 64], params: &Params) -> Self {
        let mut key = [0; 32];
        scrypt(password.as_bytes(), salt, params, &mut key).expect("scrypt");
        Self {
            aes: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key)),
        }
    }

    pub fn write_chunk<W: Write>(&self, w: &mut W, data: &[u8]) -> Result<(), Error> {
        assert!(data.len() as u16 + 16 <= u16::max_value());

        if data.is_empty() {
            w.write_all(&0_u16.to_be_bytes()).map_err(Error::Io)?;
            return w.flush().map_err(Error::Io);
        }

        let nonce = rand_nonce();
        let encrypted = self
            .aes
            .encrypt(Nonce::from_slice(&nonce), data)
            .map_err(|_| Error::Aes)?;

        // Chunk length
        let len = encrypted.len() as u16;
        w.write_all(&len.to_be_bytes()).map_err(Error::Io)?;

        // Nonce
        w.write_all(&nonce).map_err(Error::Io)?;

        // Encrypted data
        w.write_all(&encrypted).map_err(Error::Io)?;

        w.flush().map_err(Error::Io)
    }

    pub fn read_chunk<R: Read>(&self, r: &mut R) -> Option<Result<Vec<u8>, Error>> {
        // TODO: Remain 1 byte
        let mut len = [0; 2];
        if let Err(err) = r.read_exact(&mut len) {
            if err.kind() == ErrorKind::UnexpectedEof {
                return None;
            }
            return Some(Err(Error::Io(err)));
        }
        let len = u16::from_be_bytes(len);
        if len == 0 {
            return Some(Ok(Vec::new()));
        }

        let mut nonce = [0; 12];
        if let Err(err) = r.read_exact(&mut nonce) {
            return Some(Err(Error::Io(err)));
        }

        let mut encrypted = vec![0; len as usize];
        if let Err(err) = r.read_exact(&mut encrypted) {
            return Some(Err(Error::Io(err)));
        }

        let rst = self
            .aes
            .decrypt(Nonce::from_slice(&nonce), &encrypted[..])
            .map_err(|_| Error::Aes);
        Some(rst)
    }
}
