
# aef [![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/wyhaya/aef/ci.yml?style=flat-square&branch=main)](https://github.com/wyhaya/aef/actions) [![Crates.io](https://img.shields.io/crates/v/aef.svg?style=flat-square)](https://crates.io/crates/aef)

`aef` is an encrypted file archiver, it uses `AES-256-GCM` to fully encrypt data and ` scrypt ` to prevent brute force data cracking. It also allows the use of `Brotli` to reduce the size of archived files.

> [!WARNING]  
> * aef has not undergone any security check
> * Disruptive changes may occur prior to `1.0`

## Features

* Use `AES-256-GCM` for complete data encryption
* Use `scrypt` to prevent brute force cracking
* Use `brotli` compression file <sup>Optional<sup>
* Support cross-platform `Linux` `macOS` `Windows`
* Support the encryption `directory` and `file`
* Support file permissions <sup>Unix<sup>

## Install

[Download](https://github.com/wyhaya/aef/releases) the binary from the release page

Or use `cargo` to install

```bash
cargo install aef
```

## Usage

#### Encryption

```bash
aef -i ./files/ -o ./dist.aef
```

#### Decryption

```bash
aef -i ./dist.aef -o ./files/ -d
```

#### Password
By default you will enter your password in the terminal, if you don't want to enter it manually you can use the `-p` option

```bash
aef -i ./files/ -o ./dist.aef -p 123456
```

#### Compress

`aef` support the use of `brotli` to compress files, you can use the `-c` option to specify the compression level

```bash
# Compress at the fastest speed
aef -i ./files -o ./dist.aef -c

# Adjust the compress quality
aef -i ./files -o ./dist.aef -c 8
```

* Fastest: `-c 0` 
* Best: `-c 11`

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
  -c, --compress [<LEVEL>]           Set compression level [0 - 11]
      --scrypt-log-n <SCRYPT_LOG_N>  Set scrypt params [default: 20]
      --scrypt-r <SCRYPT_R>          Set scrypt params [default: 8]
      --scrypt-p <SCRYPT_P>          Set scrypt params [default: 1]
  -h, --help                         Print help
  -V, --version                      Print version
```
