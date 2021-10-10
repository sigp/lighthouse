# rust-psutil

[![crates.io](https://img.shields.io/crates/v/psutil.svg)](https://crates.io/crates/psutil)
[![docs.rs](https://docs.rs/psutil/badge.svg)](https://docs.rs/psutil)
![Minimum rustc version](https://img.shields.io/badge/rustc-1.39+-green.svg)
[![Matrix](https://img.shields.io/badge/matrix-%23rust--psutil-blue.svg)](https://matrix.to/#/#rust-psutil:matrix.org)

A process and system monitoring library for Rust, heavily inspired by the [psutil] module for Python.

Note about versioning: rust-psutil prematurely hit version 1.0, so even though it has passed 1.0, it is still going through a lot of changes and the API may be relatively unstable.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
psutil = "3.2.1"
```

Or to only use certain submodules:

```toml
[dependencies]
psutil = { version = "3.2.1", default-features = false, features = ["cpu", "process"] }
```

## Platform Support

Currently, only Linux and macOS are supported, but support is planned for all major platforms.

[platform-support.md](./platform-support.md) details the implementation level of each platform.

## Apps using rust-psutil

- [procrec](https://github.com/gh0st42/procrec)

## Related projects

- Rust
  - [hiem](https://github.com/heim-rs/heim)
  - [rust-battery](https://github.com/svartalf/rust-battery)
  - [sys-info-rs](https://github.com/FillZpp/sys-info-rs)
  - [sysinfo](https://github.com/GuillaumeGomez/sysinfo)
  - [systemstat](https://github.com/myfreeweb/systemstat)
- [gopsutil](https://github.com/shirou/gopsutil)
- [psutil]

[psutil]: https://github.com/giampaolo/psutil
