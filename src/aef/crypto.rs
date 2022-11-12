use super::Error;
use rand::{rngs::OsRng, Rng};
use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN,
};
use ring::error::Unspecified;
use scrypt::{scrypt, Params};
use std::io::{ErrorKind, Read, Write};
use zeroize::ZeroizeOnDrop;

pub const SCRYPT_LOG_N: u8 = 20;
pub const SCRYPT_R: u32 = 8;
pub const SCRYPT_P: u32 = 1;

pub const SALT_LEN: usize = 64;

fn rand_nonce() -> [u8; NONCE_LEN] {
    let mut buf = [0; 12];
    OsRng.fill(&mut buf);
    buf
}

pub fn rand_salt() -> [u8; SALT_LEN] {
    let mut buf = [0; 64];
    OsRng.fill(&mut buf);
    buf
}

struct ChunkNonce([u8; NONCE_LEN]);

impl ChunkNonce {
    fn new(nonce: [u8; NONCE_LEN]) -> Self {
        Self(nonce)
    }
}

impl NonceSequence for ChunkNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.0))
    }
}

#[derive(ZeroizeOnDrop)]
pub struct Cipher {
    key: [u8; 32],
}

impl Cipher {
    pub fn new(password: &str, salt: &[u8; SALT_LEN], params: &Params) -> Self {
        let mut key = [0; 32];
        scrypt(password.as_bytes(), salt, params, &mut key).expect("scrypt");
        Self { key }
    }

    fn key(&self) -> UnboundKey {
        UnboundKey::new(&AES_256_GCM, &self.key).unwrap()
    }

    fn encrypt(&self, nonce: [u8; NONCE_LEN], data: &mut Vec<u8>) -> Result<(), Error> {
        let mut sealing = SealingKey::new(self.key(), ChunkNonce::new(nonce));
        sealing
            .seal_in_place_append_tag(Aad::empty(), data)
            .map_err(|_| Error::Aes)
    }

    fn decrypt<'a>(
        &self,
        nonce: [u8; NONCE_LEN],
        data: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        let mut opening = OpeningKey::new(self.key(), ChunkNonce::new(nonce));
        opening
            .open_in_place(Aad::empty(), data)
            .map_err(|_| Error::Aes)
    }

    pub fn write_chunk<W: Write>(&self, w: &mut W, mut data: Vec<u8>) -> Result<(), Error> {
        assert!(data.len() as u16 + 16 <= u16::max_value());

        if data.is_empty() {
            w.write_all(&0_u16.to_be_bytes()).map_err(Error::Io)?;
            return w.flush().map_err(Error::Io);
        }

        let nonce = rand_nonce();
        self.encrypt(nonce, &mut data).map_err(|_| Error::Aes)?;

        // Chunk length
        let len = data.len() as u16;
        w.write_all(&len.to_be_bytes()).map_err(Error::Io)?;

        // Nonce
        w.write_all(&nonce).map_err(Error::Io)?;

        // Encrypted data
        w.write_all(&data).map_err(Error::Io)?;

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

        let mut data = vec![0; len as usize];
        if let Err(err) = r.read_exact(&mut data) {
            return Some(Err(Error::Io(err)));
        }

        let rst = self
            .decrypt(nonce, &mut data)
            .map(|data| data.to_vec())
            .map_err(|_| Error::Aes);

        Some(rst)
    }
}

#[cfg(test)]
mod tests {}
