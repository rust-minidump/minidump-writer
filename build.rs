fn main() {
    #![cfg(all(target_os = "windows"))]
    println!("cargo:rustc-link-lib=dylib=dbghelp");
}
