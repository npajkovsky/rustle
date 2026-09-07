# Digest Vtables

The public `rustle::digest` API follows the Linux kernel's `#[vtable]`
approach: an attribute records which trait methods an implementation supplies,
and the adapter uses that information to construct the C dispatch table.
Optional OpenSSL functions stay ordinary methods on one digest trait.

## Method presence controls registration

```rust,ignore
use rustle::digest::{Digest, DigestAlgorithm, Output, Result};
use rustle::params::Params;

#[rustle::vtable]
impl Digest for MyDigest {
    fn newctx() -> Result<Self> { /* construct owned state */ }
    fn init(&mut self, params: Option<Params<'_>>) -> Result { /* reset */ }
    fn update(&mut self, input: &[u8]) -> Result { /* absorb */ }
    fn finalize(&mut self, out: &mut Output<'_>) -> Result { /* write */ }

    rustle::gettable_params! {
        // Algorithm parameter descriptors and handlers.
    }

    fn dupctx(&self) -> Result<Self> { /* duplicate state */ }
}
```

The streaming core and algorithm parameter methods are required. Duplication
and context setters are optional. `dupctx` is registered only when the
implementation supplies it; the trait does not require `Clone` or `Default`.
Context setter and descriptor methods must be implemented together, checked
when the dispatch constant is evaluated. The parameter macro generates both
methods from one declaration; omitting it omits both callbacks.

Initialization belongs to the implementation. The adapter does not replace
the context with a default value. Implementations that accept context
parameters can call `self.apply_ctx_params(params)` after resetting their
state. A null array means no parameters. The helper preserves first-match
lookup and ignores names that the descriptor table does not list.

The attribute generates `HAS_*` constants and a required marker that catches
forgotten implementation attributes. Direct method declarations and their
presence constants have matching conditional-compilation attributes. The
parameter macros cooperate by generating their own constants alongside the
methods: an outer attribute cannot see the expansion of a nested macro.
Other implementation-item macros are rejected rather than silently omitted;
a macro can instead generate an entire attributed implementation. Handwritten
presence overrides are rejected by the attribute.

## Keep the unsafe boundary inside rustle

The attribute generates safe Rust metadata, not C wrappers. The generic
adapters remain in rustle and all callbacks in a table share the same context
type. They return the opaque `DigestFunctions` type; raw dispatch fields and
callback constructors remain inaccessible to provider authors.

The builder packs present entries into a static array, followed by `END`.
An absent optional callback cannot leave an early terminator that hides later
callbacks. The backing array has spare terminators after its used portion;
OpenSSL stops at the first one. No runtime allocation builds the table.

Metadata controls registration but is not a memory-safety proof. Optional
methods retain safe failure defaults. Errors become C failure; they do not
panic or unwind into OpenSSL. Rustle allocates contexts with the C allocator
and supplies destruction automatically.

## Output and errors

`Output` borrows potentially uninitialized storage and tracks successful
writes. `write` copies bytes without reading the destination. `write_with`
checks space before invoking a callback and zero-initializes that region
before lending it as `&mut [u8]`. This lets existing safe crypto APIs write
into C buffers without assuming those buffers were initialized. Its cost is
one initialization pass over the requested output region.

Only successful writes advance the reported length. Finalization returns that
length through OpenSSL's output slot. There is no fixed digest-length
assumption in the adapter; the implementation chooses how much to write.
Errors distinguish unsupported operations, insufficient output space, and
invalid parameters. The adapter currently reports C failure without adding an
OpenSSL error-stack entry.

## bc-rust implementation

`BcDigest<H>` implements the trait once for all eight registered SHA2 and
SHA3 hashes. It uses explicit construction, reset, and duplication, and
finalizes through `write_with`. These hashes have no configurable
per-context state, so their tables omit context setters. This matches the
default provider's fixed-length digest interface.

## Current scope

The adapter supports the streaming core, algorithm parameters, duplication,
and static context setter descriptors. It does not yet expose one-shot
callbacks, context getters, squeeze, copyctx, or serialization. Those
operations require safe signatures and audited adapters, while reusing the
same method-presence detection. Dynamic descriptor selection and
one-shot-only implementations are also outside the current interface.

`rustle-macros` runs on the host, including for cross-compilation. Its parser
dependencies are build tooling and do not become runtime dependencies of the
`no_std` provider ABI layer. The implementation is independent of the
kernel source; the shared idea is described in the
[kernel vtable documentation](https://www.kernel.org/doc/rustdoc/latest/macros/attr.vtable.html).
