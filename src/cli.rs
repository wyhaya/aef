use crate::aef::compress::{DEFAULT_COMPRESS_LEVEL, MAX_COMPRESS_LEVEL, MIN_COMPRESS_LEVEL};
use crate::aef::crypto::{
    DEFAULT_SCRYPT_LOG_N, DEFAULT_SCRYPT_P, DEFAULT_SCRYPT_R, SCRYPT_KEY_LEN,
};
use crate::exit;
use crate::utils::{create_dir, create_file, open_file, ThrowOptionError, ThrowResultError};
use clap::Parser;
use dialoguer::Password;
use scrypt::Params;
use std::fs::File;
use std::io::{stdin, stdout, Read, Result, Stdin, Stdout, Write};
use std::path::{Path, PathBuf};

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

    /// Set compression level [0 - 11]
    #[clap(short, long, value_name = "LEVEL")]
    compress: Option<Option<u32>>,

    /// Set scrypt params
    #[clap(long, default_value_t = DEFAULT_SCRYPT_LOG_N)]
    scrypt_log_n: u8,

    /// Set scrypt params
    #[clap(long, default_value_t = DEFAULT_SCRYPT_R)]
    scrypt_r: u32,

    /// Set scrypt params
    #[clap(long, default_value_t = DEFAULT_SCRYPT_P)]
    scrypt_p: u32,
}

pub enum RunType {
    Encrypt {
        params: Params,
        input: String,
        output: Output,
        output_path: Option<PathBuf>,
        password: String,
        compress: Option<u32>,
    },
    Decrypt {
        input: Input,
        output: PathBuf,
        password: String,
    },
}

#[derive(Debug)]
pub enum Output {
    Stdout(Stdout),
    File(File),
}

impl Write for Output {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self {
            Self::Stdout(io) => io.write(buf),
            Self::File(io) => io.write(buf),
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<()> {
        match self {
            Self::Stdout(io) => io.flush(),
            Self::File(io) => io.flush(),
        }
    }
}

#[derive(Debug)]
pub enum Input {
    Stdin(Stdin),
    File(File),
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

pub fn parse() -> RunType {
    let args = Args::parse();

    let password = args.password.unwrap_or_else(|| {
        let mut read = Password::new();
        read.with_prompt("Password");
        if !args.decrypt {
            read.with_confirmation("Confirm password", "Passwords mismatching, please re-enter");
        }
        read.interact().unwrap_exit(|| "Read password")
    });

    match args.decrypt {
        false => {
            let params = Params::new(
                args.scrypt_log_n,
                args.scrypt_r,
                args.scrypt_p,
                SCRYPT_KEY_LEN,
            )
            .unwrap_or_else(|_| {
                exit!(
                    "Invalid scrypt params '{} {} {}'",
                    args.scrypt_log_n,
                    args.scrypt_r,
                    args.scrypt_p
                )
            });

            let input = args.input.unwrap_exit(|| "Must specify the '-i' option");

            let (output, output_path) = args
                .output
                .map(|p| {
                    let path = Path::new(&p).to_path_buf();
                    if path.exists() {
                        exit!("'{}' already exists", p);
                    }
                    (Output::File(create_file(&p)), Some(path))
                })
                .unwrap_or_else(|| (Output::Stdout(stdout()), None));

            let compress = args.compress.map(|n| {
                let level = n.unwrap_or(DEFAULT_COMPRESS_LEVEL);
                MAX_COMPRESS_LEVEL.min(level).max(MIN_COMPRESS_LEVEL)
            });

            RunType::Encrypt {
                params,
                input,
                output,
                output_path,
                password,
                compress,
            }
        }
        true => {
            let input = args
                .input
                .map(|p| Input::File(open_file(p)))
                .unwrap_or_else(|| Input::Stdin(stdin()));

            let output = args
                .output
                .map(PathBuf::from)
                .map(|p| {
                    if p.exists() {
                        if !p.is_dir() {
                            exit!("The '-o' option must be a directory");
                        }
                    } else {
                        create_dir(&p);
                    }
                    p
                })
                .unwrap_exit(|| "Must specify the '-o' option");

            RunType::Decrypt {
                input,
                output,
                password,
            }
        }
    }
}
