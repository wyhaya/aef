use crate::{ErrorKind, IDENTIFY, IoResult, ToIoResult};
use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Key, Nonce,
};
use rand::Rng;
pub use scrypt::{scrypt, Params};
use std::io::{Read, Write};

pub const SCRYPT_LOG_N: u8 = 15;
pub const SCRYPT_R: u32 = 8;
pub const SCRYPT_P: u32 = 1;

pub fn rand_salt() -> [u8; 64] {
    let mut buf = [0; 64];
    rand::thread_rng().fill(&mut buf);
    buf
}

pub fn rand_nonce() -> [u8; 12] {
    let mut buf = [0; 12];
    rand::thread_rng().fill(&mut buf);
    buf
}

pub fn write_header<W: Write>(w: &mut W, salt: &[u8; 64], params: &Params) -> IoResult<()> {
    w.write_all(&IDENTIFY[..])?;
    w.write_all(salt)?;
    w.write_all(&params.log_n().to_be_bytes())?;
    w.write_all(&params.r().to_be_bytes())?;
    w.write_all(&params.p().to_be_bytes())?;
    Ok(())
}

pub fn read_header<R: Read>(r: &mut R) -> IoResult<([u8; 64], Params)> {
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
    .io_rst(ErrorKind::Other, "Error scrypt params")?;

    Ok((salt, params))
}

pub struct Cipher {
    aes: Aes256Gcm,
}

impl Cipher {
    pub fn new(password: &str, salt: &[u8; 64], params: &Params) -> Self {
        let mut key = [0; 32];
        scrypt(password.as_bytes(), salt, params, &mut key).unwrap();
        Self {
            aes: Aes256Gcm::new(Key::from_slice(&key)),
        }
    }

    pub fn write_chunk<W: Write>(&self, data: &[u8], w: &mut W) -> IoResult<()> {
        assert!(data.len() as u16 + 16 <= u16::max_value());

        if data.is_empty() {
            w.write_all(&0_u16.to_be_bytes())?;
            return Ok(());
        }

        let nonce = rand_nonce();
        let encrypted = self.aes.encrypt(Nonce::from_slice(&nonce), data).io_rst(
            ErrorKind::InvalidData,
            "AES-256-GCM encryption/decryption failed",
        )?;
        // Chunk length
        let len = encrypted.len() as u16;
        w.write_all(&len.to_be_bytes())?;
        // Nonce
        w.write_all(&nonce)?;
        // Encrypted data
        w.write_all(&encrypted)?;

        Ok(())
    }

    pub fn read_chunk<R: Read>(&self, r: &mut R) -> IoResult<Vec<u8>> {
        let mut len = [0; 2];
        r.read_exact(&mut len)?;
        let len = u16::from_be_bytes(len);
        if len == 0 {
            return Ok(Vec::new());
        }

        let mut nonce = [0; 12];
        r.read_exact(&mut nonce)?;
        let mut encrypted = vec![0; len as usize];
        r.read_exact(&mut encrypted)?;

        let data = self
            .aes
            .decrypt(Nonce::from_slice(&nonce), &encrypted[..])
            .io_rst(
                ErrorKind::InvalidData,
                "AES-256-GCM encryption/decryption failed",
            )?;
        Ok(data)
    }
}
