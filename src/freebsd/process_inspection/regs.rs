//! Register types returned by [`ProcessInspector`](super::ProcessInspector).
//!
//! These wrap the raw `libc` register structures (exposed as a public tuple
//! field) so the inspector interface stays stable if the underlying
//! representation changes.

use std::fmt;

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        /// General-purpose registers, as returned by `PT_GETREGS`.
        #[derive(Clone, Copy)]
        pub struct GenRegs(pub libc::reg);

        /// Floating-point registers, as returned by `PT_GETFPREGS`.
        #[derive(Clone, Copy)]
        pub struct FpRegs(pub libc::fpreg);
    }
}

impl fmt::Debug for GenRegs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to libc's Debug impl.
        self.0.fmt(f)
    }
}

impl fmt::Debug for FpRegs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to libc's Debug impl. The floating-point register save
        // area contains kernel-provided FXSAVE data which may include
        // padding bytes, but that only affects Debug output, not soundness.
        self.0.fmt(f)
    }
}
