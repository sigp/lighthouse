# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Types of changes**:
>
> - **Added**: for new features.
> - **Changed**: for changes in existing functionality.
> - **Deprecated**: for soon-to-be removed features.
> - **Removed**: for now removed features.
> - **Fixed**: for any bug fixes.
> - **Security**: in case of vulnerabilities.

## [Unreleased]

## [v3.2.1] - 2021-04-11

### Fix

- [disk] add missing `pub mod os;` to `disk/mod.rs`

## [v3.2.0] - 2020-09-26

### Added

- Make all public types serde Serializable and Deserializable

### Fix

- significantly reduce compile times by switching from snafu to thiserror
- [process][macos] fix macos process kinfo "Cannot allocate memory" errors

## [v3.1.0] - 2020-05-10

### Added

- [process][linux] implement some oneshot functions

### Fix

- [process] fix process CPU percent calculation when using the ProcessCollector

## [v3.0.1] - 2020-02-12

### Fix

- fix compilation if the sensors feature is not enabled

## [v3.0.0] - 2020-02-10

### Added

- [disk] implement DiskIoCountersCollector::disk_io_counters
- [process] make `ProcessCollector` more efficient
- [process][linux] implement `cpu_times.iowait`
- [sensors][linux] implement `thermal_zone` temperatures

### Changed

- Switch from io::Error to a custom error type
- [cpu][linux] change `cpu_times{_percent}.{steal,guest,guest_nice}` to `Option`s
- [process] status parsing now returns a ParseStatusError
- [process][linux] change `cpu_times.iowait` from `Duration` to `Option<Duration>`
- [process][linux] change `process.environ` return type from `io::Result` to `ProcessResult`

### Fix

- fix several 'overflow when subtracting durations' panics
- [cpu][linux] fix calculation of cpu_percent, CpuTimes.total, and CpuTimesPercent.total
- [disk][linux] unescape partition mountpoint escape sequences

### Removed

- [host] remove runnable, total_runnable, and last_pid from LoadAvg

## [v2.0.0] - 2020-02-04

### Added

- [macos] get macos to compile
- [cpu][all] implement cpu_count and cpu_count_physical
- [cpu][macos] implement cpu_times, cpu_times_percent, and cpu_percent
- [disk][unix] implement disk_usage
- [disk][unix] implement partitions
- [host][linux] implement boot_time
- [host] add Info
- [host][unix] implement Info
- [memory][macos] implement virtual_memory and swap_memory
- [network][macos] implement io counters
- [process] add ProcessCollector
- [process][unix] implement all signal methods
- [process][macos] implement Process::new
- [process][macos] implement process.name
- [process][macos] implement processes and pids
- [process][macos] implement Process.cpu_percent
- [process][macos] implement Process.cpu_times
- [process][macos] implement Process.memory_percent
- [process][macos] implement Process.memory_info
- [process][linux] implement pids
- [process][linux] implement pid_exists
- [process][linux] implement Process.cpu_percent
- [process][linux] implement Process.cpu_times
- [process][linux] implement Process.memory_percent
- [process][linux] implement Process.memory_info
- [process][linux] implement Process.uids
- [process][linux] implement Process.gids
- [process][linux] implement Process.send_signal
- [process][linux] implement Process.is_replaced
- [process][linux] implement Process.replace
- [process][linux] implement Process.parent
- [sensors][linux] implement temperatures

### Changed

- Overhaul the API
- [cpu] replace cpu_percent functions with CpuPercentCollector
- [disk] rename disk_io_counters_{perdisk,per_partition}

### Removed

- Remove interval duration argument from various cpu percent functions
- Remove nowrap argument from collectors
- Remove reset method from collectors
- Remove inodes from DiskUsage
- Remove standalone CpuTimesPercent functions in favor of CpuTimesPercentCollector

### Fixed

- [memory][linux] fix swap percent calculation

## [v1.7.0] - 2019-08-01

### Changed

- Remove `psutil::system` and replace with `psutil::{cpu, memory, host}`

### Removed

- Remove `getpid()`, `getppid()`, `Process.from_pidfile()`, `write_pidfile()`, and `read_pidfile()`

[Unreleased]: https://github.com/rust-psutil/rust-psutil/compare/v3.2.0...HEAD
[v3.2.0]: https://github.com/rust-psutil/rust-psutil/compare/v3.1.0...v3.2.0
[v3.1.0]: https://github.com/rust-psutil/rust-psutil/compare/v3.0.1...v3.1.0
[v3.0.1]: https://github.com/rust-psutil/rust-psutil/compare/v3.0.0...v3.0.1
[v3.0.0]: https://github.com/rust-psutil/rust-psutil/compare/v2.0.0...v3.0.0
[v2.0.0]: https://github.com/rust-psutil/rust-psutil/compare/v1.7.0...v2.0.0
[v1.7.0]: https://github.com/rust-psutil/rust-psutil/compare/v1.6.0...v1.7.0
