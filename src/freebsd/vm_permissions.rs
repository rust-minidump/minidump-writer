bitflags::bitflags! {
    /// Memory protection and sharing permissions for a memory mapping.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl Default for VmPermissions {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_permissions_flags() {
        assert!(VmPermissions::READ.contains(VmPermissions::READ));
        assert!(VmPermissions::WRITE.contains(VmPermissions::WRITE));
        assert!(VmPermissions::EXECUTE.contains(VmPermissions::EXECUTE));
        assert!(VmPermissions::PRIVATE.contains(VmPermissions::PRIVATE));
    }

    #[test]
    fn test_vm_permissions_combination() {
        let perm = VmPermissions::READ | VmPermissions::WRITE;
        assert!(perm.contains(VmPermissions::READ));
        assert!(perm.contains(VmPermissions::WRITE));
        assert!(!perm.contains(VmPermissions::EXECUTE));
        assert!(!perm.contains(VmPermissions::PRIVATE));
    }

    #[test]
    fn test_vm_permissions_empty() {
        assert!(VmPermissions::empty().is_empty());
    }
}
