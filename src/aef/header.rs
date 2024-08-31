use super::crypto::{SALT_LEN, SCRYPT_KEY_LEN};
use scrypt::Params;
use std::io::{Error as IoError, ErrorKind, Read, Result as IoResult, Write};

const IDENTIFY: &[u8; 4] = b"\xffAEF";
const COMPRESS_OFF: u8 = 0;
const COMPRESS_ON: u8 = 1;

#[derive(Debug)]
pub struct FileHeader {
    pub salt: [u8; SALT_LEN],
    pub params: Params,
    pub compress: bool,
}

impl FileHeader {
    pub fn new(salt: [u8; SALT_LEN], params: Params, compress: bool) -> Self {
        Self {
            salt,
            params,
            compress,
        }
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> IoResult<()> {
        w.write_all(&IDENTIFY[..])?;
        w.write_all(&self.salt)?;
        w.write_all(&self.params.log_n().to_be_bytes())?;
        w.write_all(&self.params.r().to_be_bytes())?;
        w.write_all(&self.params.p().to_be_bytes())?;
        if self.compress {
            w.write_all(&[COMPRESS_ON])?;
        } else {
            w.write_all(&[COMPRESS_OFF])?;
        }
        w.flush()
    }

    pub fn read_from<R: Read>(r: &mut R) -> IoResult<Self> {
        let mut identify = [0; 4];
        r.read_exact(&mut identify)?;
        if &identify != IDENTIFY {
            return Err(IoError::new(ErrorKind::Other, "Invalid identify"));
        }

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
            SCRYPT_KEY_LEN,
        )
        .map_err(|_| IoError::new(ErrorKind::Other, "Error scrypt params"))?;

        let mut c_buf = [0; 1];
        r.read_exact(&mut c_buf)?;

        Ok(Self {
            salt,
            params,
            compress: c_buf[0] == COMPRESS_ON,
        })
    }
}
