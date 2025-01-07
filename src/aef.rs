use crate::cli::Password;
use crate::utils::ThrowError;
use argon2::{Algorithm, Argon2, Params, Version};
use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN,
};
use ring::rand::{SecureRandom, SystemRandom};
use std::fmt::Debug;
use std::io::{Error as IoError, ErrorKind, Read, Result as IoResult, Write};
use zeroize::Zeroize;

const AEF_IDENTIFY: &[u8; 4] = b"\xffAEF";
const AEF_VERSION: u32 = 0x00000001;

pub const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;

const ARGON2_ALGORITHM: Algorithm = Algorithm::Argon2id;
const ARGON2_VERSION: Version = Version::V0x13;
pub const DEFAULT_ARGON2_M: u32 = 256 * 1024;
pub const DEFAULT_ARGON2_T: u32 = 32;
pub const DEFAULT_ARGON2_P: u32 = 4;

pub enum Error {
    Io(IoError),
    Encryption,
    Decryption,
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => writeln!(f, "IO error {:?}", err),
            Self::Encryption => writeln!(f, "Encryption error"),
            Self::Decryption => writeln!(f, "Decryption error"),
        }
    }
}

#[derive(Debug)]
pub struct FileHeader {
    pub salt: [u8; SALT_LEN],
    pub params: Params,
}

impl FileHeader {
    pub fn new(salt: [u8; SALT_LEN], params: Params) -> Self {
        Self { salt, params }
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> IoResult<()> {
        w.write_all(&AEF_IDENTIFY[..])?;
        w.write_all(&AEF_VERSION.to_be_bytes())?;
        w.write_all(&self.salt)?;
        w.write_all(&self.params.m_cost().to_be_bytes())?;
        w.write_all(&self.params.t_cost().to_be_bytes())?;
        w.write_all(&self.params.p_cost().to_be_bytes())?;
        w.flush()
    }

    pub fn read_from<R: Read>(r: &mut R) -> IoResult<Self> {
        let mut identify = [0; 4];
        r.read_exact(&mut identify)?;
        if &identify != AEF_IDENTIFY {
            return Err(IoError::new(ErrorKind::Other, "Invalid aef identify"));
        }

        let mut version = [0; 4];
        r.read_exact(&mut version)?;
        if u32::from_be_bytes(version) != AEF_VERSION {
            return Err(IoError::new(ErrorKind::Other, "Invalid aef version"));
        }

        let mut salt = [0; SALT_LEN];
        r.read_exact(&mut salt)?;

        let mut buf = [0; 4];
        r.read_exact(&mut buf)?;
        let m = u32::from_be_bytes(buf);
        r.read_exact(&mut buf)?;
        let t = u32::from_be_bytes(buf);
        r.read_exact(&mut buf)?;
        let p = u32::from_be_bytes(buf);

        Ok(Self {
            salt,
            params: argon2_params(m, t, p),
        })
    }
}

fn rand_bytes(bytes: &mut [u8]) {
    SystemRandom::new()
        .fill(bytes)
        .unwrap_exit(|| "Failed to generate random bytes");
}

fn rand_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0; NONCE_LEN];
    rand_bytes(&mut nonce);
    nonce
}

pub fn rand_salt() -> [u8; SALT_LEN] {
    let mut salt = [0; SALT_LEN];
    rand_bytes(&mut salt);
    salt
}

pub fn argon2_params(m: u32, t: u32, p: u32) -> Params {
    Params::new(m, t, p, Some(KEY_LEN)).unwrap_exit(|| "Invalid Argon2 parameters")
}

fn argon2_hash(password: &str, params: Params, salt: [u8; SALT_LEN]) -> [u8; KEY_LEN] {
    let mut out = [0; KEY_LEN];
    let argon = Argon2::new(ARGON2_ALGORITHM, ARGON2_VERSION, params);
    argon
        .hash_password_into(password.as_bytes(), &salt, &mut out)
        .unwrap_exit(|| "Failed to argon2id hash password");
    out
}

struct RandNonce {
    nonce: [u8; 12],
}

impl RandNonce {
    fn new(bytes: [u8; NONCE_LEN]) -> Self {
        Self { nonce: bytes }
    }
}

impl NonceSequence for RandNonce {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.nonce))
    }
}

#[derive(Debug)]
pub struct Cipher {
    key: [u8; KEY_LEN],
}

impl Drop for Cipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Cipher {
    pub fn new(password: &Password, salt: [u8; SALT_LEN]) -> Self {
        let key = argon2_hash(&password.password, password.params.clone(), salt);
        Self { key }
    }

    fn key(&self) -> UnboundKey {
        UnboundKey::new(&AES_256_GCM, &self.key).unwrap_exit(|| "Failed to create unbound key")
    }

    fn encrypt(&self, nonce: [u8; NONCE_LEN], data: &mut Vec<u8>) -> Result<(), Error> {
        let nonce = RandNonce::new(nonce);
        let mut sealing = SealingKey::new(self.key(), nonce);
        sealing
            .seal_in_place_append_tag(Aad::empty(), data)
            .map_err(|_| Error::Encryption)
    }

    fn decrypt<'a>(
        &self,
        nonce: [u8; NONCE_LEN],
        data: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        let nonce = RandNonce::new(nonce);
        let mut opening = OpeningKey::new(self.key(), nonce);
        opening
            .open_in_place(Aad::empty(), data)
            .map_err(|_| Error::Decryption)
    }

    pub fn write_chunk<W: Write>(&self, w: &mut W, mut data: Vec<u8>) -> Result<(), Error> {
        if data.is_empty() {
            w.write_all(&0_u16.to_be_bytes()).map_err(Error::Io)?;
            return w.flush().map_err(Error::Io);
        }

        let nonce = rand_nonce();
        self.encrypt(nonce, &mut data)
            .map_err(|_| Error::Encryption)?;

        let len = data.len() as u16;
        w.write_all(&len.to_be_bytes()).map_err(Error::Io)?;

        w.write_all(&nonce).map_err(Error::Io)?;

        w.write_all(&data).map_err(Error::Io)?;

        w.flush().map_err(Error::Io)
    }

    pub fn read_chunk<R: Read>(&self, r: &mut R) -> Option<Result<Vec<u8>, Error>> {
        let mut len = [0; 2];
        if let Err(err) = r.read_exact(&mut len) {
            if err.kind() == ErrorKind::UnexpectedEof {
                return None;
            }
            return Some(Err(Error::Io(err)));
        }
        let len = u16::from_be_bytes(len);
        if len == 0 {
            return None;
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
            .map_err(|_| Error::Decryption);

        Some(rst)
    }
}

#[cfg(test)]
mod tests {}
