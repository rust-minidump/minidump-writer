<div align="center">

# `minidump-writer`

**Rust rewrite of Breakpad's minidump_writer (client)**

[![Rust CI](https://github.com/rust-minidump/minidump-writer/actions/workflows/ci.yml/badge.svg)](https://github.com/rust-minidump/minidump-writer/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/minidump-writer.svg)](https://crates.io/crates/minidump-writer)
[![docs.rs](https://docs.rs/minidump-writer/badge.svg)](https://docs.rs/minidump-writer)

</div>

This project is currently being very actively brought up from nothing, and is really ultimately many separate client implementations for different platforms.

## Usage / Examples

### Linux

```rust
fn write_minidump(crash_context: crash_context::CrashContext) {
    // At a minimum, the crashdump writer needs to know the process and thread that the crash occurred in
    let mut writer = minidump_writer::minidump_writer::MinidumpWriter::new(crash_context.pid, crash_context.tid);

    // If provided with a full [crash_context::CrashContext](https://docs.rs/crash-context/latest/crash_context/struct.CrashContext.html),
    // the crash will contain more info on the crash cause, such as the signal
    writer.set_crash_context(minidump_writer::crash_context::CrashContext { inner: crash_context });

    // Here we could add more context or modify how the minidump is written, eg
    // Add application specific memory blocks to the minidump
    //writer.set_app_memory()
    // Sanitize stack memory before it is written to the minidump by replacing
    // non-pointer values with a sentinel value
    //writer.sanitize_stack();

    let mut minidump_file = std::fs::File::create("example_dump.mdmp").expect("failed to create file");
    writer.dump(&mut minidump_file).expect("failed to write minidump");
}
```

### Windows

```rust
fn write_minidump(crash_context: crash_context::CrashContext) {
    // Creates the Windows MinidumpWriter. This function handles both the case
    // of the crashing process being the same, or different, than the current
    // process
    let writer = minidump_writer::minidump_writer::MinidumpWriter::new(crash_context)?;

    let mut minidump_file = std::fs::File::create("example_dump.mdmp").expect("failed to create file");
    writer.dump(&mut minidump_file).expect("failed to write minidump");
}
```

### MacOS

```rust
fn write_minidump(crash_context: crash_context::CrashContext) {
    let mut writer = minidump_writer::minidump_writer::MinidumpWriter::new(crash_context)?;

    let mut minidump_file = std::fs::File::create("example_dump.mdmp").expect("failed to create file");
    writer.dump(&mut minidump_file).expect("failed to write minidump");
}
```

## Client Statuses

- ✅ Usable, but care should be taken in production environments
- ⚠️ Implemented (ie compiles), but untested and needs more work to be usable
- ⭕️ Unimplemented, but could be implemented in the future
- ❌ Unimplemented, and unlikely to ever be implemented

| Arch | unknown-linux-gnu | unknown-linux-musl | linux-android | pc-windows-msvc | apple-darwin | apple-ios
--- | --- | --- | --- | --- | --- | --- |
`x86_64` | ✅ | ✅ | ⚠️ | ✅ | ✅ | ⭕️ |
`i686` | ✅ | ✅ | ❌ | ⚠️ | ❌ | ❌ | ⭕️ |
`arm` | ⚠️ | ⚠️ | ⚠️ | ⭕️ | ❌ | ❌ |
`aarch64` | ⚠️ | ⚠️ | ⚠️ | ⭕️ | ✅ | ⭕️ |
`mips` | ⭕️ | ⭕️ | ❌ | ❌ | ❌ | ❌ |
`mips64` | ⭕️ | ⭕️ | ❌ | ❌ | ❌ | ❌ |
`powerpc` | ⭕️ | ⭕️ | ❌ | ❌ | ❌ | ❌ |
`powerpc64` | ⭕️ | ⭕️ | ❌ | ❌ | ❌ | ❌ |
