# Context Memory

Operation contexts are allocated on the host process's C heap — an internal
`heap` module wrapping `malloc`/`free` — rather than with `Box`.

## Why not `Box`

`Box::new` aborts the process on allocation failure. That is a fair default
for an application, and the wrong one for a guest: the process it kills is
nginx or curl, which never opted in.

The provider ABI already has an answer here. `newctx` and `dupctx` return
`NULL`, OpenSSL raises `ERR_R_MALLOC_FAILURE`, and the application decides
what to do. `malloc` reports failure the same way, so the shim passes it
straight through.

The C heap also keeps the `no_std` build free of `#[global_allocator]`
machinery — the crate needs no `alloc` at all.

## Context constraints

The heap wrapper accepts only non-empty types with alignment up to 8:

```rust,ignore
const { assert!(size_of::<T>() > 0 && align_of::<T>() <= 8) }
```

Zero-sized allocations do not have portable `malloc` semantics and are not
useful operation contexts. Alignment guarantees vary by target, so the
conservative limit keeps every write valid on the supported platforms. A
context needing stronger alignment requires a different allocation path.

## Scrubbing sensitive state: best-effort

`freectx` runs the drop and the release as two separate steps, with a
`hint::black_box` between them:

```rust,ignore
pub(crate) unsafe fn free<T>(ptr: *mut T) {
    if ptr.is_null() {
        return;
    }
    unsafe { ptr.drop_in_place() };
    core::hint::black_box(ptr);
    unsafe { libc::free(ptr.cast()) }
}
```

Without the interposition, a `Drop` impl that zeroes its state is deleted
outright. LLVM sees the memory die in `free` and eliminates the stores as
dead. `black_box` is an opaque potential reader of the allocation, so the
stores are no longer dead and survive to that point.

This does work in practice. Compiling a 32-byte zeroing `Drop` at `-O` for
aarch64, the generated code without the `black_box` contains no stores at all
— just a tail call to `free`. With it, the 32 zero bytes are written before
the release.

### What this is not

It approximates `OPENSSL_clear_free`. It does not guarantee it, for three
reasons worth being explicit about:

1. **`black_box` is best-effort by construction.** Its documentation states
   that programs "cannot rely on `black_box` for *correctness*", that it
   "must not be relied upon to control critical program behavior", and that
   it "does not offer any guarantees for cryptographic or security
   purposes". That last sentence describes this exact use.
2. **Plain stores are weaker than `OPENSSL_cleanse`,** which is deliberately
   optimization-resistant.
3. **It is not the allocator choice that buys this.** The same drop/release
   split with the same `black_box` produces identical codegen against Rust's
   global allocator; a plain `Box` drop loses the zeroing just as `free`
   does. What matters is splitting the two steps, not which heap is
   underneath.

No type in the workspace implements `Drop` today, so this is a facility on
offer rather than something currently exercised. If you add one, treat the
scrub as defense in depth, not as a guarantee you can lean on.
