// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

unsafe extern "C" {
    fn abort() -> !;
}

/// Panic handler for `no_std` builds. The profiles set `panic = "abort"`, so a
/// panic must not unwind across the FFI boundary into the loading C process —
/// the only safe response is to terminate it. We defer to the C runtime's
/// `abort()` (raises `SIGABRT`), which is already present in the host process
/// that loaded the provider (libSystem on macOS, libc on Linux), keeping the
/// crate dependency-free.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: `abort` is the C standard-library function of the same name; it
    // takes no arguments, has no preconditions, and never returns.
    unsafe { abort() }
}

/// Stub exception-personality routine for `no_std` builds.
///
/// The prebuilt `core` carries unwinder tables that reference this symbol, so
/// the linker demands it even though `panic = "abort"` means unwinding never
/// runs. With std it is supplied by the standard library; without std we
/// provide an empty definition purely to satisfy the linker — it is never
/// actually called, so its body and signature are irrelevant.
#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {}
