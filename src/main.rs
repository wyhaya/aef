mod aef;
mod cli;
mod compress;
pub mod crypto;
mod utils;
use aef::{Decoder, Encoder};
use cli::RunType;
use path_clean::PathClean;
use std::path::Path;
use utils::{create_dir, create_file, current_dir, open_file, ThrowOptionError, ThrowResultError};
use walkdir::WalkDir;

fn main() {
    match cli::parse() {
        RunType::Encrypt {
            params,
            input,
            output,
            output_path,
            password,
            compress,
        } => {
            let cur = current_dir();
            let empty = Path::new("");
            let input = Path::new(&input);
            let prefix = match input.is_dir() {
                true => input,
                false => input
                    .parent()
                    .unwrap_exit(|| format!("Get input parent failed '{}'", input.display())),
            };
            let absolute = output_path.map(|p| cur.join(p));

            let mut aef =
                Encoder::new(output, &password, params, compress).unwrap_exit(|| "aef encoder");

            for rst in WalkDir::new(input) {
                let entry = rst.unwrap_exit(|| "Entry error");

                // Eliminate the output file
                if let Some(absolute) = &absolute {
                    let entry = cur.join(entry.path());
                    if absolute == &entry {
                        continue;
                    }
                }

                let suffix = entry
                    .path()
                    .strip_prefix(&prefix)
                    .unwrap_exit(|| format!("Strip prefix failed {}", entry.path().display()));

                if suffix == empty {
                    continue;
                }

                if entry.file_type().is_dir() {
                    aef.append_directory(suffix)
                        .unwrap_exit(|| format!("Append directory '{}'", suffix.display()));
                } else {
                    let mut file = open_file(entry.path());
                    aef.append_file(suffix, &mut file)
                        .unwrap_exit(|| format!("Append file '{}'", suffix.display()));
                }
            }
        }
        RunType::Decrypt {
            input,
            output,
            password,
        } => {
            let output = output.clean();
            let mut aef = Decoder::new(input, &password).unwrap_exit(|| "aef decoder");

            loop {
                let entry = match aef.read_entry() {
                    Some(rst) => rst.unwrap_exit(|| "Read file entry"),
                    None => break,
                };
                let dist = output.join(entry.path()).clean();
                if dist.starts_with(&output) {
                    if entry.filetype().is_file() {
                        let mut f = create_file(&dist);
                        aef.read_data_to(&mut f).unwrap_exit(|| {
                            format!("Read entry data failed '{}'", entry.path().display())
                        });
                    } else {
                        create_dir(dist);
                    }
                } else {
                    exit!("Dangerous path '{}'", dist.display());
                }
            }
        }
    };
}
