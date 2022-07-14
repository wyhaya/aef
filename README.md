
# aef [![GitHub Workflow Status](https://img.shields.io/github/workflow/status/wyhaya/aef/Build?style=flat-square)](https://github.com/wyhaya/aef/actions) [![Crates.io](https://img.shields.io/crates/v/aef.svg?style=flat-square)](https://crates.io/crates/aef)

Util for file encryption

## Features

* Encryption with `AES-256-GCM`
* Use `scrypt` to prevent brute force cracking
* Support for `pipeline` operations

## Install

[Download](https://github.com/wyhaya/aef/releases) the binary from the release page

Or use `cargo` to install

```bash
cargo install aef
```

## Use

Encryption

```bash
aef -i ./your.file -o ./your.aef
```

Decryption

```bash
aef -i ./yout.aef -o ./your.file -d
```

By default you will enter your password in the terminal, if you don't want to enter it manually you can use the `-p` option

```bash
aef -i ./your.file -o ./your.aef -p 123456
```

Pipeline operation

> If `input/output` is not specified, aef will `read/write` from `stdin/stdout`.

```bash
# Read from `stdin` and output to `stdout`
cat your.file | aef > your.aef

# Read from `file` and output to `stdout`
aef -i your.aef -d | > your.file

# Read from stdin and output to file
cat your.file | aef -o ./your.aef 
```

## Example

Used in conjunction with the `tar` command

Encryption

```bash
tar -cf - ./dir | aef -o ./your.aef
```

Decryption

```bash
aef -i ./your.aef -d | tar -xf -
```

---
