
# aef [![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/wyhaya/aef/ci.yml?style=flat-square&branch=main)](https://github.com/wyhaya/aef/actions) [![Crates.io](https://img.shields.io/crates/v/aef.svg?style=flat-square)](https://crates.io/crates/aef)

`aef` is an encrypted file archiver, it uses `AES-256-GCM` to fully encrypt data and `Argon2id` to prevent brute force data cracking.

> [!WARNING]  
> * aef has not undergone any security check
> * Disruptive changes may occur prior to `1.0`

## Install

[Download](https://github.com/wyhaya/aef/releases) the binary from the release page

Or use `cargo` to install

```bash
cargo install aef
```

## Usage


```bash
# Encrypt
aef -i ./your.file -o ./your.file.aef

# Decrypt
aef -i ./your.file.aef -o ./your.file -d
```

#### Password

By default you will enter your password in the terminal, if you don't want to enter it manually you can use the `-p` option.

```bash
aef -i ./file -o ./dist.aef -p 123456
```

### Pipeline

aef support transmission through `Pipeline`, you can use it in combination with commands like `tar`.

```bash
# Encrypt
tar -czf - your.file | aef -o ./your-file.tgz.aef -p 123456

# Decrypt
aef -i ./your-file.tgz.aef -p 123456 | tar -xzf -
```

#### Help

```bash
aef --help
```

```bash
Usage: aef [OPTIONS]

Options:
  -i, --input <INPUT>                File | Stdin
  -o, --output <OUTPUT>              File | Stdout
  -p, --password <PASSWORD>          Set password
  -d, --decrypt                      Decrypt file
  ...
  -h, --help                         Print help
  -V, --version                      Print version
```
