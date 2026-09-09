# Building and Verifying

## Crate features (`rustle`)

The `rustle-macros` proc-macro crate and its parser dependencies compile for
the build host. They require the host Rust standard library even when the
target build uses `no_std`; they are not linked into the provider module.

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

`rustle` must always compile under **both** of its configurations. The
`Makefile` at the workspace root drives everything a change has to pass:

```sh
make check
```

which is these steps, each also a target of its own:

| Step | Target |
|------|--------|
| `cargo build -p rustle --no-default-features --features abort` (`no_std`) | `build-no-std` |
| `cargo build -p rustle --features std` | `build-std` |
| `cargo build -p bc-rust-provider` (the module) | `module` |
| Build the C test programs without running them | `bulid-test` |
| `cargo fmt --check` | `rust-fmt-check` |
| `clang-format --dry-run --Werror` over the C test sources | `c-fmt-check` |
| `cargo test` — doctests + CLI KATs | `cargo-test` |
| `prove` over `test/recipes/` — C-side KATs | `c-test` |

`fmt-check` runs both formatting checks, and `make test` runs the last two
together. `PROFILE=release` builds and tests
against `target/release` instead; `PROVE_FLAGS` passes through to the TAP
harness. `make help` lists the rest.

The C formatting targets require clang-format; CI pins 22.1.8 for reproducible
results. Set `CLANG_FORMAT` when that binary is installed under a versioned or
non-standard name.

On macOS, the system `openssl` is LibreSSL and Homebrew keeps `openssl@3`
keg-only, so `pkg-config` finds no `libcrypto.pc` by default. Point it at the
keg — what CI does:

```sh
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
```

GitHub Actions runs the two formatting checks as a preflight job. The test job
depends on that job, so it runs `make test` only after both Rust and C
formatting are clean, and it fans out over Ubuntu and macOS on both x86_64 and
arm64 — so the Darwin-specific parts of the build (the `libSystem` link, the
module's `.dylib` name, the install-name rewrite) stay covered, and so does
each target triple's own codegen and calling convention across the provider's
FFI boundary. The matrix does not fail fast: one platform breaking still
reports the others. CI jobs run only in `openssl-projects/rustle`; runs in
forks skip preflight and its dependent test jobs. Pull requests from forks
targeting upstream remain eligible to run there.

To build and test against a configured OpenSSL build tree instead of the
system OpenSSL, pass its root once:

```sh
make OPENSSL_ROOT_DIR=/path/to/openssl check
```

This selects the build tree's `libcrypto.pc` for the C tests.
`OPENSSL_ROOT_DIR` is the public interface; the environment passed to
`pkg-config` is managed internally by the Makefile. Changing the selected
OpenSSL configuration, compiler flags, or module directory rebuilds the C
objects and relinks the test programs. An unchanged configuration preserves
incremental builds; switching roots does not require `make clean`.

The `no_std` build is the one that breaks silently: `bc-rust-provider` pulls
in `std`, so building only the module will never tell you that `rustle`
stopped being `no_std`-clean.

On macOS, a `no_std` cdylib is built with `-nodefaultlibs`, so the build
script links `libSystem` back in explicitly — the `std` build already links
it, so that is scoped to `no_std`.

## Why two test suites

A provider sits between two ecosystems, so it needs a test boundary on each
side. The Cargo suite keeps verification in the normal Rust workflow and sees
the module as a command-line user does. The C suite is an independent native
consumer of the provider ABI, which catches integration mistakes that a test
running only from the Rust side could share or overlook.

Neither suite substitutes for the other: together they check that the Rust
implementation builds as a Rust component and behaves as a C component once
loaded by OpenSSL.

`test/` is laid out the way OpenSSL lays out its own: a `testutil.h` public
header, the driver under `testutil/`, test programs named `*_test.c` beside
them, and the `prove` recipes under `recipes/`. libcrypto is found with
`pkg-config`; the top-level Makefile configures its search from
`OPENSSL_ROOT_DIR`.

Each test binary records libcrypto's directory as an rpath. On macOS, the
link step also rewrites an absolute libcrypto install name to its
`@rpath`-relative form; otherwise dyld would bypass that rpath when a custom
build still advertises its configured installation prefix.

### The prove harness

The driver already writes TAP, so there is nothing for a recipe to translate:
`test/recipes/` holds one recipe per test program, and a recipe `exec`s its
program so that the driver's output *is* the recipe's output — nothing
re-numbers or re-indents it, and the program's exit status is the recipe's.
What that buys over running the programs in a loop is a harness that reports
across programs and names the cases that failed, plus the flags worth having:
`-v` for every assertion, `-j` to run recipes in parallel.

```sh
make PROVE_FLAGS=-v c-test
```

A recipe takes the two paths it cannot work out — where the programs were
built, and where cargo put the cdylib — from `BC_RUST_TEST_DIR` and
`BC_RUST_MODULE`, set by `test/Makefile`, which is the only file that knows
the platform's name for the module. `test/perl/Rustle/Test.pm` falls back to
deriving both, so a single recipe also runs by hand:

```sh
prove -v test/recipes/02-test_evp_md.t
```

Adding a test program means adding it to `TEST_SRCS` in `test/Makefile` and
dropping a recipe beside the others; the recipe list is a wildcard.

When a failure needs picking apart, `make -C test run` runs the same programs
without the harness in the way, and a program run directly takes `-list`,
`-test N` and `-iter N` to narrow down to a single case.

## Layout

```text
Makefile                   top-level entry point (`make help`)
crates/rustle/             safe provider-ABI layer (lib; no_std by default)
crates/rustle-macros/      host-side method-presence attribute (proc-macro)
crates/bc-rust-provider/   the loadable provider module (cdylib), zero unsafe
test/                      C tests against the module, OpenSSL's test layout
test/recipes/              one prove recipe per test program
test/perl/                 what the recipes share
docs/                      this book
```

## Building this book

```sh
mdbook build docs
mdbook serve docs   # live-reloading preview on localhost:3000
```
