// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operation contexts on the host process's C heap.
//!
//! A provider lives inside a C program, so contexts cross the FFI boundary
//! as malloc'd memory (the C reference uses `OPENSSL_zalloc`/`clear_free`
//! the same way). Routing every context through [`alloc`]/[`free`] keeps the
//! `no_std` build free of any Rust `alloc`-crate/global-allocator machinery,
//! and keeps OOM reportable: allocation failure surfaces as a null pointer
//! for the caller to return through the ABI, where `Box::new` would abort
//! the loading process.

mod libc {
    use core::ffi;

    unsafe extern "C" {
        pub(super) fn malloc(size: usize) -> *mut ffi::c_void;
        pub(super) fn free(ptr: *mut ffi::c_void);
    }
}

/// Move `value` into a fresh `malloc` allocation, returning null (and
/// discarding `value`) when the host allocator is out of memory.
///
/// Two kinds of `T` are rejected at compile time, since neither can be
/// reported through the null return: zero-sized ones, because `malloc(0)`
/// is implementation-defined, and ones aligned beyond 8, which is all
/// `malloc` guarantees — the write would be misaligned.
pub(crate) fn alloc<T>(value: T) -> *mut T {
    const { assert!(size_of::<T>() > 0 && align_of::<T>() <= 8) }
    // SAFETY: the allocation is sized and aligned for `T` (checked above),
    // and `write` initializes it before anyone reads it.
    unsafe {
        let ptr = libc::malloc(size_of::<T>()).cast::<T>();
        if !ptr.is_null() {
            ptr.write(value);
        }
        ptr
    }
}

/// Drop the `T` at `ptr` and release its allocation. No-op on null.
///
/// Scrubbing sensitive state is `T`'s policy, not this helper's: a type
/// approximating `OPENSSL_clear_free` semantics zeroes itself in `Drop`, and
/// splitting the drop from the release (below) leaves room to keep those
/// stores from being eliminated. That is best-effort, not a guarantee:
/// `black_box` is documented as such and disclaims cryptographic use, and
/// plain stores are weaker than `OPENSSL_cleanse`'s optimization-resistant
/// scrub.
///
/// # Safety
///
/// `ptr` must be null, or come from [`alloc::<T>`] and still hold a live `T`
/// (not yet freed).
pub(crate) unsafe fn free<T>(ptr: *mut T) {
    if ptr.is_null() {
        return;
    }

    // SAFETY: per the contract, `ptr` holds a live, initialized `T`.
    unsafe { ptr.drop_in_place() };

    // Must sit between the drop and the free: LLVM otherwise sees the
    // memory die in `free` and deletes any zeroing `Drop` did as dead
    // stores. `black_box` is an opaque potential reader of the allocation,
    // so those stores are not dead. Best-effort only — see above.
    core::hint::black_box(ptr);

    // SAFETY: the allocation no longer holds a live value.
    unsafe { libc::free(ptr.cast()) }
}
