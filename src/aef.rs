use crate::cli::Password;
use crate::utils::ThrowError;
use argon2::{Algorithm, Argon2, Params, Version};
use ring::aead::{
    AES_256_GCM, Aad, BoundKey, NONCE_LEN, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey,
};
use ring::rand::{SecureRandom, SystemRandom};
use std::fmt::Debug;
use std::io::{Error as IoError, ErrorKind, Read, Result as IoResult, Write};
use zeroize::Zeroize;

const AEF_IDENTIFY: &[u8; 4] = b"\xffAEF";
const AEF_VERSION: u32 = 0x00000002;
const HEADER_LEN: usize = 36;
const TAG_LEN: usize = 16;
const CHUNK_DATA: u8 = 0;
const CHUNK_END: u8 = 1;

pub const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;

const ARGON2_ALGORITHM: Algorithm = Algorithm::Argon2id;
const ARGON2_VERSION: Version = Version::V0x13;
pub const DEFAULT_ARGON2_M: u32 = 256 * 1024;
pub const DEFAULT_ARGON2_T: u32 = 64;
pub const DEFAULT_ARGON2_P: u32 = 4;

pub enum Error {
    Io(IoError),
    Encryption,
    Decryption,
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => writeln!(f, "IO error {err:?}"),
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
        w.write_all(&self.to_bytes())?;
        w.flush()
    }

    fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut bytes = [0; HEADER_LEN];
        bytes[..4].copy_from_slice(AEF_IDENTIFY);
        bytes[4..8].copy_from_slice(&AEF_VERSION.to_be_bytes());
        bytes[8..24].copy_from_slice(&self.salt);
        bytes[24..28].copy_from_slice(&self.params.m_cost().to_be_bytes());
        bytes[28..32].copy_from_slice(&self.params.t_cost().to_be_bytes());
        bytes[32..36].copy_from_slice(&self.params.p_cost().to_be_bytes());
        bytes
    }

    pub fn read_from<R: Read>(r: &mut R) -> IoResult<Self> {
        let mut identify = [0; 4];
        r.read_exact(&mut identify)?;
        if &identify != AEF_IDENTIFY {
            return Err(IoError::other("Invalid aef identify"));
        }

        let mut version = [0; 4];
        r.read_exact(&mut version)?;
        if u32::from_be_bytes(version) != AEF_VERSION {
            return Err(IoError::other("Invalid aef version"));
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
    header: [u8; HEADER_LEN],
}

impl Drop for Cipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Cipher {
    pub fn new(password: &Password, header: &FileHeader) -> Self {
        let key = argon2_hash(&password.password, password.params.clone(), header.salt);
        Self {
            key,
            header: header.to_bytes(),
        }
    }

    fn key(&self) -> UnboundKey {
        UnboundKey::new(&AES_256_GCM, &self.key).unwrap_exit(|| "Failed to create unbound key")
    }

    fn aad(&self, index: u64, kind: u8, len: u16) -> Vec<u8> {
        let mut aad = Vec::with_capacity(HEADER_LEN + 11);
        aad.extend_from_slice(&self.header);
        aad.extend_from_slice(&index.to_be_bytes());
        aad.push(kind);
        aad.extend_from_slice(&len.to_be_bytes());
        aad
    }

    fn encrypt(&self, nonce: [u8; NONCE_LEN], aad: &[u8], data: &mut Vec<u8>) -> Result<(), Error> {
        let nonce = RandNonce::new(nonce);
        let mut sealing = SealingKey::new(self.key(), nonce);
        sealing
            .seal_in_place_append_tag(Aad::from(aad), data)
            .map_err(|_| Error::Encryption)
    }

    fn decrypt<'a>(
        &self,
        nonce: [u8; NONCE_LEN],
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        let nonce = RandNonce::new(nonce);
        let mut opening = OpeningKey::new(self.key(), nonce);
        opening
            .open_in_place(Aad::from(aad), data)
            .map_err(|_| Error::Decryption)
    }

    pub fn write_chunk<W: Write>(
        &self,
        w: &mut W,
        index: u64,
        mut data: Vec<u8>,
    ) -> Result<(), Error> {
        let kind = if data.is_empty() {
            CHUNK_END
        } else {
            CHUNK_DATA
        };
        let len = u16::try_from(data.len() + TAG_LEN).map_err(|_| Error::Encryption)?;
        let nonce = rand_nonce();
        self.encrypt(nonce, &self.aad(index, kind, len), &mut data)
            .map_err(|_| Error::Encryption)?;

        w.write_all(&[kind]).map_err(Error::Io)?;
        w.write_all(&len.to_be_bytes()).map_err(Error::Io)?;
        w.write_all(&nonce).map_err(Error::Io)?;
        w.write_all(&data).map_err(Error::Io)?;
        w.flush().map_err(Error::Io)
    }

    pub fn read_chunk<R: Read>(&self, r: &mut R, index: u64) -> Result<Chunk, Error> {
        let mut kind = [0];
        read_record_exact(r, &mut kind)?;
        if kind[0] != CHUNK_DATA && kind[0] != CHUNK_END {
            return Err(Error::Decryption);
        }

        let mut len = [0; 2];
        read_record_exact(r, &mut len)?;
        let len = u16::from_be_bytes(len);
        if len < TAG_LEN as u16 {
            return Err(Error::Decryption);
        }

        let mut nonce = [0; 12];
        read_record_exact(r, &mut nonce)?;

        let mut data = vec![0; len as usize];
        read_record_exact(r, &mut data)?;

        let data = self.decrypt(nonce, &self.aad(index, kind[0], len), &mut data)?;
        match kind[0] {
            CHUNK_DATA if !data.is_empty() => Ok(Chunk::Data(data.to_vec())),
            CHUNK_END if data.is_empty() => Ok(Chunk::End),
            _ => Err(Error::Decryption),
        }
    }
}

fn read_record_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), Error> {
    r.read_exact(buf).map_err(|err| {
        if err.kind() == ErrorKind::UnexpectedEof {
            Error::Decryption
        } else {
            Error::Io(err)
        }
    })
}

pub enum Chunk {
    Data(Vec<u8>),
    End,
}

pub fn ensure_eof<R: Read>(r: &mut R) -> Result<(), Error> {
    let mut byte = [0];
    match r.read(&mut byte) {
        Ok(0) => Ok(()),
        Ok(_) => Err(Error::Decryption),
        Err(err) => Err(Error::Io(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password() -> Password {
        Password {
            password: "test password".into(),
            params: argon2_params(8, 1, 1),
        }
    }

    fn cipher() -> Cipher {
        let password = password();
        let header = FileHeader::new([7; SALT_LEN], password.params.clone());
        Cipher::new(&password, &header)
    }

    fn record(cipher: &Cipher, index: u64, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        cipher
            .write_chunk(&mut output, index, data.to_vec())
            .unwrap();
        output
    }

    #[test]
    fn round_trip_and_authenticated_end() {
        let cipher = cipher();
        let mut encrypted = record(&cipher, 0, b"payload");
        encrypted.extend(record(&cipher, 1, b""));
        let mut input = encrypted.as_slice();

        assert!(matches!(
            cipher.read_chunk(&mut input, 0).unwrap(),
            Chunk::Data(data) if data == b"payload"
        ));
        assert!(matches!(
            cipher.read_chunk(&mut input, 1).unwrap(),
            Chunk::End
        ));
        ensure_eof(&mut input).unwrap();
    }

    #[test]
    fn rejects_reordered_chunks() {
        let cipher = cipher();
        let first = record(&cipher, 0, b"first");
        let second = record(&cipher, 1, b"second");
        assert!(cipher.read_chunk(&mut second.as_slice(), 0).is_err());
        assert!(cipher.read_chunk(&mut first.as_slice(), 1).is_err());
    }

    #[test]
    fn rejects_truncation_and_missing_end() {
        let cipher = cipher();
        let data = record(&cipher, 0, b"payload");
        let truncated = &data[..data.len() - 1];
        let mut truncated_input = truncated;
        assert!(cipher.read_chunk(&mut truncated_input, 0).is_err());
        assert!(cipher.read_chunk(&mut [].as_ref(), 1).is_err());
    }

    #[test]
    fn rejects_tampering_and_trailing_data() {
        let cipher = cipher();
        let mut data = record(&cipher, 0, b"payload");
        let last = data.len() - 1;
        data[last] ^= 1;
        assert!(cipher.read_chunk(&mut data.as_slice(), 0).is_err());

        let trailing = [1];
        assert!(ensure_eof(&mut trailing.as_slice()).is_err());
    }
}
