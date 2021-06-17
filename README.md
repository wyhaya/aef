
# aef

[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/wyhaya/aef/Build?style=flat-square)](https://github.com/wyhaya/aef/actions)
[![Crates.io](https://img.shields.io/crates/v/aef.svg?style=flat-square)](https://crates.io/crates/aef)
[![LICENSE](https://img.shields.io/crates/l/aef.svg?style=flat-square)](https://github.com/wyhaya/aef/blob/master/LICENSE)

Util for file encryption

## Features

* Encryption with `AES-256-GCM`
* Use `scrypt` to prevent brute force cracking
* Using linux pipeline operations

## Install

[Download](https://github.com/wyhaya/aef/releases) the binary from the release page

Or use `cargo` to install

```bash
cargo install aef
```

## Use

Encryption

```bash
cat your.file | aef > your.aef
```

Decryption

```bash
cat your.aef | aef -d > your.file
```

By default you will enter your password in the terminal, if you don't want to enter it manually you can use the `-p` option

```bash
cat your.file | aef -p 123456 > your.aef
```

---