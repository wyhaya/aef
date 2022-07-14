use crate::{
    crypto::{Params, SCRYPT_LOG_N, SCRYPT_P, SCRYPT_R},
    exit, ThrowError,
};
use clap::Parser;
use std::fs::File;
use std::io::{stdin, stdout, Read, Write};
use std::path::Path;

#[derive(Parser, Debug)]
#[clap(version, about)]
struct Args {
    /// File | Stdin
    #[clap(short, long)]
    input: Option<String>,

    /// File | Stdout
    #[clap(short, long)]
    output: Option<String>,

    /// Password
    #[clap(short, long)]
    password: Option<String>,

    /// Decrypt file
    #[clap(short, long)]
    decrypt: bool,

    /// Scrypt params
    #[clap(long, default_value_t = SCRYPT_LOG_N)]
    scrypt_log_n: u8,

    /// Scrypt params
    #[clap(long, default_value_t = SCRYPT_R)]
    scrypt_r: u32,

    /// Scrypt params
    #[clap(long, default_value_t = SCRYPT_P)]
    scrypt_p: u32,
}

pub fn parse() -> (String, Option<Params>, Box<dyn Read>, Box<dyn Write>) {
    let args = Args::parse();

    let parsms = match args.decrypt {
        true => None,
        false => Some(
            Params::new(args.scrypt_log_n, args.scrypt_r, args.scrypt_p).unwrap_or_else(|_| {
                exit!(
                    "Invalid scrypt params '{} {} {}'",
                    args.scrypt_log_n,
                    args.scrypt_r,
                    args.scrypt_p
                )
            }),
        ),
    };

    let password = args
        .password
        .unwrap_or_else(|| rpassword::prompt_password("Password: ").unwrap_exit());

    let input = args
        .input
        .map(|p| Box::new(File::open(p).unwrap_exit()) as Box<dyn Read>)
        .unwrap_or_else(|| Box::new(stdin()));

    let output = args
        .output
        .map(|p| {
            if Path::new(&p).exists() {
                exit!("{} already exists", p);
            }
            Box::new(File::create(p).unwrap_exit()) as Box<dyn Write>
        })
        .unwrap_or_else(|| Box::new(stdout()));

    (password, parsms, input, output)
}
