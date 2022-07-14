<!-- markdownlint-disable blanks-around-headings blanks-around-lists no-duplicate-heading -->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## [Unreleased] - ReleaseDate
### Fixed
- [PR#42](https://github.com/rust-minidump/minidump-writer/pull/42) resolved [#41](https://github.com/rust-minidump/minidump-writer/issues/41) by capping the VM read of task memory to avoid a syscall failure, as well as made it so that if an error does occur when reading the module's file path, the module is still written to the minidump, as the file path is less important than the UUID.

## [0.2.1] - 2022-05-25
### Added
- [PR#32](https://github.com/rust-minidump/minidump-writer/pull/32) resolved [#23](https://github.com/rust-minidump/minidump-writer/issues/23) by adding support for the thread names stream on MacOS.

## [0.2.0] - 2022-05-23
### Added
- [PR#21](https://github.com/rust-minidump/minidump-writer/pull/21) added an initial implementation for `x86_64-apple-darwin` and `aarch64-apple-darwin`

## [0.1.0] - 2022-04-26
### Added
- Initial release, including basic support for `x86_64-unknown-linux-gnu/musl` and `x86_64-pc-windows-msvc`

<!-- next-url -->
[Unreleased]: https://github.com/rust-minidump/minidump-writer/compare/0.2.1...HEAD
[0.2.1]: https://github.com/rust-minidump/minidump-writer/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/rust-minidump/minidump-writer/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/rust-minidump/minidump-writer/releases/tag/0.1.0
