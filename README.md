
# aef [![GitHub Workflow Status](https://img.shields.io/github/workflow/status/wyhaya/aef/Build?style=flat-square)](https://github.com/wyhaya/aef/actions) [![Crates.io](https://img.shields.io/crates/v/aef.svg?style=flat-square)](https://crates.io/crates/aef)

Command line tool for encrypting files

## Features

* Use `AES-256-GCM` for complete data encryption
* Use `scrypt` to prevent brute force cracking
* Use `brotli` compression file
* Support the encryption `directory` and `file`

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

* Fastest: `-c 0` 
* Best: `-c 11`

```bash
aef -i ./files -o ./dist.aef -c 0
```

#### Pipe

If `input/output` is not specified, aef will `read/write` from `stdin/stdout`.

## Format

* todo
