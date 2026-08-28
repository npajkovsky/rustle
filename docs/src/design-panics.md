# Panics and Lints

A Rust panic must never unwind across the FFI boundary into the loading C
process. Unwinding into frames that were not compiled to expect it is
undefined behaviour, and the process it corrupts belongs to someone else.

## `panic = "abort"`

Both profiles set it:

```toml
[profile.dev]
panic = "abort"

[profile.release]
panic = "abort"
```

Under `no_std`, the `abort` feature supplies the `#[panic_handler]`, which
calls the C runtime's `abort()` — already present in the host process that
loaded the module (libSystem on macOS, libc on Linux), so the crate stays
dependency-free:

```rust,ignore
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { abort() }
}
```

Aborting also frees the `no_std` build from needing an `eh_personality` lang
item — the crate provides an empty `rust_eh_personality` purely to satisfy
the linker, since `core`'s prebuilt unwinder tables reference the symbol even
though `panic = "abort"` means it never runs.

Terminating the host is a bad outcome. It is the *least* bad one available
once a panic has happened, which is why the lints below exist to stop one
happening at all.

## The lint set

Aborting is the backstop, not the plan. A broad workspace lint set pushes
toward code that has no reachable panic in the first place:

| Lint | Why |
|------|-----|
| `clippy::unwrap_used`, `expect_used`, `panic` | The three direct routes to aborting the host |
| `clippy::indexing_slicing` | `a[i]` panics; `get(i)` does not |
| `clippy::arithmetic_side_effects` | Overflow panics in debug builds |
| `clippy::undocumented_unsafe_blocks` | Every `unsafe` carries a `SAFETY:` justification |
| `clippy::multiple_unsafe_ops_per_block` | One unsafe operation per block, so each justification covers exactly one thing |
| `rust::unsafe_op_in_unsafe_fn` (deny) | An `unsafe fn` body is not implicitly an unsafe block |
| `rust::ffi_unwind_calls` | Calling an extern fn that could unwind back across FFI is the UB `panic = "abort"` exists to prevent |
| `clippy::std_instead_of_core`, `std_instead_of_alloc`, `alloc_instead_of_core` | Enforce the `no_std` rule: no reaching for `std`/`alloc` when `core` suffices |
| `rust::missing_docs`, `rustdoc::all` | The FFI contract is the documentation |

`clippy::pedantic` and `clippy::cargo` are on at `warn` as a whole, with
`cargo_common_metadata` allowed — that one is publish-readiness, not
hardening, and no repository URL is set yet.

These are warnings rather than denials. They are a gradient to argue with
when a specific site is genuinely fine, not a wall — but the argument should
end up in a comment.
