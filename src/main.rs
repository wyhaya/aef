mod aef;
mod cli;
mod utils;
use aef::entry::{FileEntry, FileType};
use aef::{Decoder, Encoder};
mod record;
use cli::RunType;
use record::Record;
use std::path::Path;
use utils::{
    create_dir, create_file, cur_dir, get_permissions, open_file, set_permissions,
    ThrowOptionError, ThrowResultError,
};
use walkdir::WalkDir;

fn main() {
    let mut record = Record::new();

    match cli::parse() {
        RunType::Encrypt {
            params,
            input,
            output,
            output_path,
            password,
            compress,
        } => {
            let cur = cur_dir();
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

            let mut aef = Encoder::new(output, &password, params, compress).unwrap_exit(|| "");

            for entry in WalkDir::new(input)
                .into_iter()
                .skip(skip)
                .map(|rst| rst.unwrap_exit(|| "Read directory error"))
            {
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

                let permissions = get_permissions(entry.path());

                if entry.path().is_dir() {
                    record.add(FileType::Directory, suffix);
                    aef.append_directory(suffix, permissions)
                        .unwrap_exit(|| format!("Add directory '{}'", suffix.display()));
                } else {
                    record.add(FileType::File, suffix);
                    let mut file = open_file(entry.path());
                    aef.append_file(suffix, permissions, &mut file)
                        .unwrap_exit(|| format!("Add file '{}'", suffix.display()));
                }
            }
        }
        RunType::Decrypt {
            input,
            output,
            password,
        } => {
            let mut aef = Decoder::new(input, &password).unwrap_exit(|| "");

            loop {
                let FileEntry {
                    filetype,
                    path,
                    permissions,
                } = match aef.read_entry() {
                    Some(rst) => rst.unwrap_exit(|| "Read data failed"),
                    None => break,
                };
                let dist = output.join(path.to_path_buf());
                if filetype.is_file() {
                    record.write(FileType::File, &path);
                    let mut f = create_file(&dist);
                    aef.read_data_to(&mut f)
                        .unwrap_exit(|| format!("Read data failed '{}'", path));
                } else {
                    record.write(FileType::Directory, &path);
                    create_dir(&dist);
                }
                if let Some(mode) = permissions {
                    set_permissions(dist, mode);
                }
            }
        }
    };
}
