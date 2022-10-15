mod aef;
mod cli;
mod utils;
use aef::entry::FileEntry;
use aef::{Decoder, Encoder};
use cli::RunType;
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
            let input = Path::new(&input);
            let (prefix, skip) = match input.is_dir() {
                true => (input, 1),
                false => (
                    input
                        .parent()
                        .unwrap_exit(|| format!("Get input parent failed '{}'", input.display())),
                    0,
                ),
            };
            let absolute = output_path.map(|p| cur.join(p));

            let mut aef =
                Encoder::new(output, &password, params, compress).unwrap_exit(|| "aef encoder");

            for rst in WalkDir::new(input).into_iter().skip(skip) {
                let entry = rst.unwrap_exit(|| "Entry error");

                // Eliminate the output file
                if let Some(absolute) = &absolute {
                    let entry = cur.join(entry.path());
                    if absolute == &entry {
                        dbg!("skip");
                        continue;
                    }
                }

                let suffix = entry
                    .path()
                    .strip_prefix(&prefix)
                    .unwrap_exit(|| format!("Strip prefix failed {}", entry.path().display()));

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
            let mut aef = Decoder::new(input, &password).unwrap_exit(|| "aef decoder");

            loop {
                let FileEntry { filetype, path } = match aef.read_entry() {
                    Some(rst) => rst.unwrap_exit(|| "Read file entry"),
                    None => break,
                };
                let dist = output.join(path.to_path_buf());
                if filetype.is_file() {
                    let mut f = create_file(&dist);
                    aef.read_data_to(&mut f)
                        .unwrap_exit(|| format!("Read entry data failed '{}'", path));
                } else {
                    create_dir(dist);
                }
            }
        }
    };
}
