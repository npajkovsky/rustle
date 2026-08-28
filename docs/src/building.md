# Building and Verifying

## Crate features (`rustle`)

| Feature | Effect |
|---------|--------|
| *(default)* | `no_std`: only `core`, contexts on the C heap |
| `std` | Link the standard library (required by bc-rust, drops the panic handler) |
| `abort` | Provide the `no_std` `#[panic_handler]`; enable from the final `no_std` artifact, inert when `std` is on |
| `debug` | Bring-up tracing via `write(2)` to stderr; compiles to nothing when off |

`abort` is separate from the default on purpose. Only the *final* artifact in
a link may define a `#[panic_handler]`, so a crate that might be linked
alongside another `no_std` component must be able to leave it out.

`debug` is a developer aid for wiring a provider up — it writes straight to
fd 2 with libc `write`, needing no allocator and no dependencies. Real
provider diagnostics belong on OpenSSL's error stack via the
`OSSL_FUNC_core_*` upcalls.

## The invariants

`rustle` must always compile under **both** of its configurations. Checking
all of it:

```sh
cargo build -p rustle --no-default-features --features abort  # no_std
cargo build -p rustle --features std                          # std
cargo build -p bc-rust-provider                               # the module
cargo test                                                    # doctests + CLI KATs
cargo fmt --check
```

The `no_std` build is the one that breaks silently: `bc-rust-provider` pulls
in `std`, so building only the module will never tell you that `rustle`
stopped being `no_std`-clean.

On macOS, a `no_std` cdylib is built with `-nodefaultlibs`, so the build
script links `libSystem` back in explicitly — the `std` build already links
it, so that is scoped to `no_std`.

## Layout

```text
crates/rustle/             safe provider-ABI layer (lib; no_std by default)
crates/bc-rust-provider/   the loadable provider module (cdylib), zero unsafe
docs/                      this book
```

## Building this book

```sh
mdbook build docs
mdbook serve docs   # live-reloading preview on localhost:3000
```
