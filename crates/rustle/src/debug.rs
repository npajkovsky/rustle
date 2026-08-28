//! Bring-up tracing via `write(2)`, for use while wiring the provider up.
//!
//! [`trace!`](crate::trace) formats a line straight to the loading process's
//! stderr (fd 2) using libc `write`, so it works in `no_std` with no allocator
//! and no dependencies. It is gated on the `debug` cargo feature and expands to
//! nothing when that feature is off.
//!
//! This is a developer aid only — real provider diagnostics belong on OpenSSL's
//! error stack via the `OSSL_FUNC_core_*` upcalls, not here.

#[cfg(feature = "debug")]
pub use imp::Stderr;

#[cfg(feature = "debug")]
mod imp {
    use core::ffi::c_void;
    use core::fmt::{self, Write};

    // POSIX write(2); resolved from the host process (libc / libSystem) that
    // loaded the provider.
    unsafe extern "C" {
        fn write(fd: i32, buf: *const c_void, count: usize) -> isize;
    }

    /// A [`core::fmt::Write`] sink that emits straight to stderr via `write(2)`.
    pub struct Stderr;

    impl Write for Stderr {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let mut rest = s.as_bytes();
            while !rest.is_empty() {
                // SAFETY: `rest` is a live slice; we pass its current pointer and
                // length, and write(2) reads at most `count` bytes from it.
                let n = unsafe { write(2, rest.as_ptr().cast::<c_void>(), rest.len()) };
                // A non-positive return means error or no progress: give up
                // rather than spin. Tracing failures are intentionally silent.
                let Ok(n) = usize::try_from(n) else {
                    return Err(fmt::Error);
                };
                if n == 0 {
                    return Err(fmt::Error);
                }
                rest = rest.get(n..).unwrap_or(&[]);
            }
            Ok(())
        }
    }
}

/// Print a formatted trace line to stderr. No-op unless the `debug` feature is
/// enabled. Same formatting syntax as `println!`.
#[cfg(feature = "debug")]
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {{
        use ::core::fmt::Write as _;
        // Writing a trace line is best-effort; ignore any error.
        let _ = ::core::writeln!($crate::debug::Stderr, $($arg)*);
    }};
}

/// Print a formatted trace line to stderr. No-op unless the `debug` feature is
/// enabled. Same formatting syntax as `println!`.
#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {{
        // Keep the arguments "used" so toggling the feature off never triggers
        // unused-variable warnings, but evaluate and emit nothing at runtime.
        if false {
            let _ = ::core::format_args!($($arg)*);
        }
    }};
}
