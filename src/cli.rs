use crate::crypto::Params;
use crate::exit;
use clap::{crate_name, crate_version, App, Arg};

const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

pub fn parse() -> (String, Option<Params>) {
    let app = App::new(crate_name!())
        .version(crate_version!())
        .usage(format!("<STDOUT> | {} > <STDOUT>", crate_name!()).as_str())
        .arg(
            Arg::with_name("decrypt")
                .short("d")
                .long("decrypt")
                .conflicts_with("scrypt"),
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

    let password = || match app.value_of("password") {
        Some(s) => s.to_string(),
        None => rpassword::read_password_from_tty(Some("Password: "))
            .unwrap_or_else(|err| exit!("Failed to read password: {:?}", err)),
    };

    if app.is_present("decrypt") {
        return (password(), None);
    }

    let (log_n, r, p) = app
        .values_of("scrypt")
        .map(|val| val.collect::<Vec<&str>>())
        .map(|val| {
            (
                val[0]
                    .parse::<u8>()
                    .unwrap_or_else(|_| exit!("Cannot parse '{}' to u8", val[0])),
                val[1]
                    .parse::<u32>()
                    .unwrap_or_else(|_| exit!("Cannot parse '{}' to u32", val[1])),
                val[2]
                    .parse::<u32>()
                    .unwrap_or_else(|_| exit!("Cannot parse '{}' to u32", val[2])),
            )
        })
        .unwrap_or((SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P));

    let params = Params::new(log_n, r, p)
        .unwrap_or_else(|_| exit!("Invalid scrypt params '{} {} {}'", log_n, r, p));

    (password(), Some(params))
}
