# Design

Four decisions shape the workspace, each with a chapter of its own:

- [The Crate Split](./design-split.md) — why the FFI layer and the crypto
  live in separate crates, and what a provider author actually writes.
- [Digest Vtables](./design-vtable.md) — how optional trait methods determine
  which OpenSSL callbacks enter a digest dispatch table.
- [Context Memory](./design-memory.md) — why operation contexts go on the
  host process's C heap instead of into a `Box`, and what can and cannot be
  promised about scrubbing them.
- [Panics and Lints](./design-panics.md) — why a panic must never unwind into
  the loading process, and the lint set that pushes toward not panicking in
  the first place.

The through-line is that a provider is a guest in someone else's process.
It is loaded into nginx, curl, or a language runtime that never consented to
Rust's failure modes. Aborting the host on an allocation failure, unwinding
across the FFI boundary, or handing the core a table that runs off its end
are all faults the *host* pays for. Each decision below trades some Rust
ergonomics for not doing that.
