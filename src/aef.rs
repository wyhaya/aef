use crate::cli::Password;
use crate::utils::ThrowError;
use argon2::{Algorithm, Argon2, Params, Version};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
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

pub struct Cipher {
    key: LessSafeKey,
    header: [u8; HEADER_LEN],
}

impl Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cipher")
            .field("key", &"<redacted>")
            .field("header", &self.header)
            .finish()
    }
}

impl Cipher {
    pub fn new(password: &Password, header: &FileHeader) -> Self {
        let mut key_bytes = argon2_hash(&password.password, password.params.clone(), header.salt);
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &key_bytes)
                .unwrap_exit(|| "Failed to create unbound key"),
        );
        key_bytes.zeroize();
        Self {
            key,
            header: header.to_bytes(),
        }
    }

    fn nonce(index: u64) -> Nonce {
        let mut nonce = [0; NONCE_LEN];
        nonce[NONCE_LEN - size_of::<u64>()..].copy_from_slice(&index.to_be_bytes());
        Nonce::assume_unique_for_key(nonce)
    }

    fn aad(&self, index: u64, kind: u8, len: u16) -> Vec<u8> {
        let mut aad = Vec::with_capacity(HEADER_LEN + 11);
        aad.extend_from_slice(&self.header);
        aad.extend_from_slice(&index.to_be_bytes());
        aad.push(kind);
        aad.extend_from_slice(&len.to_be_bytes());
        aad
    }

    fn encrypt(&self, index: u64, aad: &[u8], data: &mut Vec<u8>) -> Result<(), Error> {
        self.key
            .seal_in_place_append_tag(Self::nonce(index), Aad::from(aad), data)
            .map_err(|_| Error::Encryption)
    }

    fn decrypt<'a>(
        &self,
        index: u64,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        self.key
            .open_in_place(Self::nonce(index), Aad::from(aad), data)
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
        self.encrypt(index, &self.aad(index, kind, len), &mut data)
            .map_err(|_| Error::Encryption)?;

        w.write_all(&[kind]).map_err(Error::Io)?;
        w.write_all(&len.to_be_bytes()).map_err(Error::Io)?;
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

        let mut data = vec![0; len as usize];
        read_record_exact(r, &mut data)?;

        let data = self.decrypt(index, &self.aad(index, kind[0], len), &mut data)?;
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

    fn cipher() -> Cipher {
        let password = Password {
            password: "test password".into(),
            params: argon2_params(8, 1, 1),
        };
        let header = FileHeader::new([7; SALT_LEN], password.params.clone());
        Cipher::new(&password, &header)
    }

    fn encrypt_chunk(cipher: &Cipher, index: u64, plaintext: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        cipher
            .write_chunk(&mut output, index, plaintext.to_vec())
            .unwrap();
        output
    }

    fn assert_rejected(cipher: &Cipher, encrypted: &[u8], index: u64) {
        let mut input = encrypted;
        assert!(matches!(
            cipher.read_chunk(&mut input, index),
            Err(Error::Decryption)
        ));
    }

    mod nonce_and_format {
        use super::*;

        #[test]
        fn nonce_is_big_endian_chunk_index() {
            assert_eq!(Cipher::nonce(0).as_ref(), &[0; NONCE_LEN]);
            assert_eq!(
                Cipher::nonce(0x0102_0304_0506_0708).as_ref(),
                &[0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
            );
            assert_eq!(
                Cipher::nonce(u64::MAX).as_ref(),
                &[0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255]
            );
        }

        #[test]
        fn chunk_format_does_not_store_nonce() {
            let encrypted = encrypt_chunk(&cipher(), 0, b"payload");
            let expected_len = 1 + 2 + b"payload".len() + TAG_LEN;
            assert_eq!(encrypted.len(), expected_len);
        }
    }

    mod round_trip {
        use super::*;

        #[test]
        fn multiple_chunks_and_authenticated_end() {
            let cipher = cipher();
            let mut encrypted = encrypt_chunk(&cipher, 0, b"first");
            encrypted.extend(encrypt_chunk(&cipher, 1, b"second"));
            encrypted.extend(encrypt_chunk(&cipher, 2, b""));
            let mut input = encrypted.as_slice();

            for (index, expected) in [b"first".as_slice(), b"second"].into_iter().enumerate() {
                assert!(matches!(
                    cipher.read_chunk(&mut input, index as u64).unwrap(),
                    Chunk::Data(data) if data == expected
                ));
            }
            assert!(matches!(
                cipher.read_chunk(&mut input, 2).unwrap(),
                Chunk::End
            ));
            ensure_eof(&mut input).unwrap();
        }

        #[test]
        fn empty_file() {
            let cipher = cipher();
            let encrypted = encrypt_chunk(&cipher, 0, b"");
            let mut input = encrypted.as_slice();

            assert!(matches!(
                cipher.read_chunk(&mut input, 0).unwrap(),
                Chunk::End
            ));
            ensure_eof(&mut input).unwrap();
        }
    }

    mod authentication_failures {
        use super::*;

        #[test]
        fn wrong_index() {
            let cipher = cipher();
            let encrypted = encrypt_chunk(&cipher, 1, b"payload");
            assert_rejected(&cipher, &encrypted, 0);
        }

        #[test]
        fn reordered_chunks() {
            let cipher = cipher();
            let first = encrypt_chunk(&cipher, 0, b"first");
            let second = encrypt_chunk(&cipher, 1, b"second");
            assert_rejected(&cipher, &second, 0);
            assert_rejected(&cipher, &first, 1);
        }

        #[test]
        fn truncated_chunk() {
            let cipher = cipher();
            let mut encrypted = encrypt_chunk(&cipher, 0, b"payload");
            encrypted.pop();
            assert_rejected(&cipher, &encrypted, 0);
        }

        #[test]
        fn tampered_ciphertext() {
            let cipher = cipher();
            let mut encrypted = encrypt_chunk(&cipher, 0, b"payload");
            *encrypted.last_mut().unwrap() ^= 1;
            assert_rejected(&cipher, &encrypted, 0);
        }

        #[test]
        fn missing_end_chunk() {
            assert_rejected(&cipher(), &[], 1);
        }

        #[test]
        fn trailing_data() {
            assert!(ensure_eof(&mut [1].as_slice()).is_err());
        }
    }
}
