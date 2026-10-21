bitflags::bitflags! {
    /// Memory protection and sharing permissions for a memory mapping.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct VmPermissions: u32 {
        /// Read permission
        const READ = 0b0001;
        /// Write permission
        const WRITE = 0b0010;
        /// Execute permission
        const EXECUTE = 0b0100;
        /// Private mapping (copy-on-write)
        const PRIVATE = 0b1000;
    }
}
