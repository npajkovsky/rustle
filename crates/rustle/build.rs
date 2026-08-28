#![allow(missing_docs)]

// On macOS every dylib must link libSystem. A no_std cdylib is built with
// -nodefaultlibs, so the std runtime doesn't pull it in — add it back
// explicitly. The std build already links it, so this is scoped to no_std.
fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let has_std = std::env::var("CARGO_FEATURE_STD").is_ok();
    if target_os == "macos" && !has_std {
        println!("cargo:rustc-link-lib=dylib=System");
    }
}
