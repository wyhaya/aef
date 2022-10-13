use crate::crypto::{SCRYPT_LOG_N, SCRYPT_P, SCRYPT_R};
use crate::exit;
use crate::utils::{create_dir, create_file, open_file, ThrowOptionError, ThrowResultError};
use clap::Parser;
use scrypt::Params;
use std::io::{stdin, stdout, Read, Write};
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
    #[clap(short, long)]
    compress: Option<u32>,

    /// Set scrypt params
    #[clap(long, default_value_t = SCRYPT_LOG_N)]
    scrypt_log_n: u8,

    /// Set scrypt params
    #[clap(long, default_value_t = SCRYPT_R)]
    scrypt_r: u32,

    /// Set scrypt params
    #[clap(long, default_value_t = SCRYPT_P)]
    scrypt_p: u32,
}

pub enum RunType {
    Encrypt {
        params: Params,
        input: String,
        output: Box<dyn Write>,
        output_path: Option<PathBuf>,
        password: String,
        compress: Option<u32>,
    },
    Decrypt {
        input: Box<dyn Read>,
        output: PathBuf,
        password: String,
    },
}

pub fn parse() -> RunType {
    let args = Args::parse();

    let password = args.password.unwrap_or_else(|| {
        rpassword::prompt_password("Password: ").unwrap_exit(|| "Read password")
    });

    match args.decrypt {
        false => {
            let params = Params::new(args.scrypt_log_n, args.scrypt_r, args.scrypt_p)
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
                    let f = create_file(&p);
                    (Box::new(f) as Box<dyn Write>, Some(path))
                })
                .unwrap_or_else(|| (Box::new(stdout()), None));

            let compress = args.compress.map(|n| 11.min(n).max(0));

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
                .map(|p| {
                    let file = open_file(p);
                    Box::new(file) as Box<dyn Read>
                })
                .unwrap_or_else(|| Box::new(stdin()));

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
