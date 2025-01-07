use crate::aef::{argon2_params, DEFAULT_ARGON2_M, DEFAULT_ARGON2_P, DEFAULT_ARGON2_T};
use crate::utils::ThrowError;
use argon2::Params;
use clap::Parser;
use std::fs::File;
use std::io::{stdin, stdout, Read, Result, Stdin, Stdout, Write};
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[clap(version, about)]
struct Args {
    /// File | Stdin
    #[clap(short, long)]
    input: Option<String>,

    /// File | Stdout
    #[clap(short, long)]
    output: Option<String>,

    /// Set password
    #[clap(short, long)]
    password: Option<String>,

    /// Decrypt file
    #[clap(short, long)]
    decrypt: bool,

    /// Argon2: memory size in 1 KiB blocks. Between 8 * `argon2_p` and (2^32)-1
    #[clap(long, name = "M", default_value_t = DEFAULT_ARGON2_M)]
    argon2_m: u32,

    /// Argon2: number of iterations. Between 1 and (2^32)-1
    #[clap(long, name = "T", default_value_t = DEFAULT_ARGON2_T)]
    argon2_t: u32,

    /// Argon2: degree of parallelism. Between 1 and (2^24)-1
    #[clap(long, name = "P", default_value_t = DEFAULT_ARGON2_P)]
    argon2_p: u32,
}

#[derive(Debug)]
pub enum Input {
    Stdin(Stdin),
    File(File),
}

#[derive(Debug)]
pub enum Output {
    Stdout(Stdout),
    File(LazyFile),
}

impl Read for Input {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::Stdin(io) => io.read(buf),
            Self::File(io) => io.read(buf),
        }
    }
}

impl Write for Output {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self {
            Self::Stdout(io) => io.write(buf),
            Self::File(io) => io.get_mut().write(buf),
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<()> {
        match self {
            Self::Stdout(io) => io.flush(),
            Self::File(io) => io.get_mut().flush(),
        }
    }
}

impl Input {
    fn from_path(path: String) -> Self {
        File::open(&path)
            .map(Input::File)
            .unwrap_exit(|| format!("Failed to open file '{}'", path))
    }
}

impl Output {
    fn from_path(path: String) -> Self {
        Output::File(LazyFile::Path(path))
    }
}

#[derive(Debug)]
pub enum LazyFile {
    Path(String),
    File(File),
}

impl LazyFile {
    fn get_mut(&mut self) -> &mut File {
        match self {
            Self::Path(path) => {
                let file = File::create_new(&path)
                    .unwrap_exit(|| format!("Failed to create file '{}'", path));
                *self = Self::File(file);
                self.get_mut()
            }
            Self::File(file) => file,
        }
    }
}

pub struct Password {
    pub password: String,
    pub params: Params,
}

impl Drop for Password {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

pub fn parse() -> (Input, Output, Password, bool) {
    let args = Args::parse();

    let params = argon2_params(args.argon2_m, args.argon2_t, args.argon2_p);
    let password = args.password.unwrap_or_else(|| {
        let mut read = dialoguer::Password::new().with_prompt("Password");
        if !args.decrypt {
            read = read
                .with_confirmation("Confirm password", "Passwords mismatching, please re-enter");
        }
        read.interact().unwrap_exit(|| "Read password")
    });
    let password = Password { password, params };

    let input = args
        .input
        .map(Input::from_path)
        .unwrap_or_else(|| Input::Stdin(stdin()));

    let output = args
        .output
        .map(Output::from_path)
        .unwrap_or_else(|| Output::Stdout(stdout()));

    (input, output, password, args.decrypt)
}
