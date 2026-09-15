# Vtable

`#[rustle::vtable]` records which methods a trait implementation supplies.
`DigestAlgorithm<D>` uses that information to include optional callbacks in
an OpenSSL dispatch table. The attribute generates method-presence constants;
the dispatch builder supplies the function pointers.

## Recording method presence

The attribute is applied to both the trait and its implementations. For each
method declared in the trait, it adds a hidden `HAS_METHOD` boolean with a
default value of `false`. Method names are uppercased: `dupctx` becomes
`HAS_DUPCTX`.

On an implementation, every explicitly written method gets the corresponding
constant set to `true`. An omitted method inherits the trait's `false` value,
even though its default implementation remains callable. Presence describes
whether a method was supplied, not whether calling it would succeed.

For example, the relevant parts of an expansion look like this:

```rust,ignore
// Generated on the trait alongside fn dupctx(...):
#[doc(hidden)]
const HAS_DUPCTX: bool = false;
#[doc(hidden)]
const __VTABLE: ();

// Generated on an attributed impl that explicitly defines dupctx:
const HAS_DUPCTX: bool = true;
const __VTABLE: () = ();
```

The required `__VTABLE` marker makes an implementation that forgets the
attribute fail with a missing associated item. Within an attributed impl,
handwritten `__VTABLE` and `HAS_*` constants are rejected: method declarations
are the source of the generated metadata. Required trait methods still have
to be implemented under ordinary Rust trait rules.

## Conditional methods and nested macros

The attribute copies a method's `#[cfg]` and `#[cfg_attr]` attributes onto its
generated presence constant. When a conditional implementation method is
removed, its `true` override is removed too, leaving the trait's default.

An attribute macro sees implementation-item macro invocations before those
macros expand, so it cannot discover their generated methods directly.
Rustle's `gettable_params!`, `settable_ctx_params!`, and
`gettable_ctx_params!` cooperate with it: the attribute prefixes their input
with `@vtable`, telling them to emit presence constants alongside their
methods. Other implementation-item macros are rejected rather than silently
losing their methods from the presence metadata. A macro can instead generate
the entire attributed impl, making its methods visible to `#[vtable]`.

## Building the dispatch table

`DigestAlgorithm<D>` evaluates the presence constants while constructing its
associated dispatch array. Required callbacks are included unconditionally;
each optional callback contributes an entry only when its method is present:

```rust,ignore
if D::HAS_DUPCTX {
    Some(OSSL_DISPATCH::digest_dupctx(Self::dupctx))
} else {
    None
}
```

The builder packs the present entries into an array initialized with
`OSSL_DISPATCH::END`. Missing callbacks therefore leave no holes that could
prematurely terminate OpenSSL's traversal. The first unused slot terminates
the table; any remaining slots are also terminators. Construction happens at
compile time, without runtime allocation.

The same const evaluation checks required relationships between methods,
such as a context accessor and its descriptor. These checks belong to the
digest dispatch builder; the attribute itself only records presence.

The resulting table contains pointers to the adapters for the same `D` and is
exposed through the opaque `DigestFunctions` wrapper. `#[vtable]` does not
generate FFI adapters or a Rust trait-object vtable. Its metadata decides
which existing adapters are advertised; the adapters remain responsible for
the FFI boundary.
