# Introduction

`rustle` is a pair of Rust crates for building OpenSSL 3.x/4.x [loadable
providers](https://docs.openssl.org/master/man7/provider/) — dynamically
loaded modules that supply cryptographic algorithm implementations to
libcrypto.

The workspace splits the problem in two, so that *speaking the provider ABI*
and *implementing cryptography* never live in the same crate:

| Crate | Role | Safety posture |
|-------|------|----------------|
| `crates/rustle` | Safe abstraction over the provider FFI | Contains every `unsafe` block in the workspace, behind safe APIs; `no_std` by default; zero dependencies |
| `crates/bc-rust-provider` | The loadable provider module (`cdylib`) | `#![forbid(unsafe_code)]`; crypto from bc-rust (BouncyCastle's Rust port) |

## Scope

Scope today is the **digest operation** (`OSSL_OP_DIGEST`). The MAC, KDF and
XOF operations exist upstream in `openssl-rs` and have not been carried over
yet.

## Where to go next

- [Getting Started](./getting-started.md) — build the module and drive it
  from the `openssl` CLI.
- [Registered Algorithms](./algorithms.md) — what the provider exposes, and
  why the alias lists matter.
- [Design](./design.md) — the crate split, context memory, and the panic
  posture.
- [Building and Verifying](./building.md) — the feature matrix and the
  invariants to check before committing.
