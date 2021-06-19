use crate::{
    crypto::{Params, SCRYPT_LOG_N, SCRYPT_P, SCRYPT_R},
    exit, ThrowError,
};
use clap::{crate_name, crate_version, App, Arg};
use std::io::{stdin, stdout, Read, Write};
use std::path::Path;
use std::{fs::File, str::FromStr};

pub fn parse() -> (String, bool, Params, Box<dyn Read>, Box<dyn Write>) {
    let app = App::new(crate_name!())
        .version(crate_version!())
        .arg(Arg::with_name("INPUT").required(true).help("<PATH> | -"))
        .arg(Arg::with_name("OUTPUT").required(true).help("<PATH> | -"))
        .arg(
            Arg::with_name("force-encrypt")
                .short("f")
                .long("force-encrypt")
                .help(&format!("Encrypt even if {} format is recognized", crate_name!()))
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .value_name("PASSWORD"),
        )
        .arg(
            Arg::with_name("scrypt")
                .short("s")
                .long("scrypt")
                .max_values(3)
                .min_values(3)
                .value_name("[LOG_N] [R] [P]"),
        )
        .get_matches();

    let params = {
        let (log_n, r, p) = app
            .values_of("scrypt")
            .map(|val| val.collect::<Vec<&str>>())
            .map(|val| (number(val[0]), number(val[1]), number(val[2])))
            .unwrap_or((SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P));
        Params::new(log_n, r, p)
            .unwrap_or_else(|_| exit!("Invalid scrypt params '{} {} {}'", log_n, r, p))
    };

    let password = match app.value_of("password") {
        Some(s) => s.to_string(),
        None => rpassword::read_password_from_tty(Some("Password: ")).unwrap_exit(),
    };

    let input = app
        .value_of("INPUT")
        .and_then(|s| if s == "-" { None } else { Some(s) })
        .map(|s| Box::new(File::open(s).unwrap_exit()) as Box<dyn Read>)
        .unwrap_or_else(|| Box::new(stdin()));

    let output = app
        .value_of("OUTPUT")
        .and_then(|s| if s == "-" { None } else { Some(s) })
        .map(|s| {
            if Path::new(s).exists() {
                exit!("{} already exists", s);
            }
            Box::new(File::create(s).unwrap_exit()) as Box<dyn Write>
        })
        .unwrap_or_else(|| Box::new(stdout()));

    (password, app.is_present("force-encrypt"), params, input, output)
}

fn number<T: FromStr>(val: &str) -> T {
    val.parse::<T>()
        .unwrap_or_else(|_| exit!("Cannot parse '{}' to '{}'", val, std::any::type_name::<T>()))
}
