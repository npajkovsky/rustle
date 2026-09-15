# Registered Algorithms

A provider serves one algorithm table per operation id. The core asks for
them through `query_operation`, which hands back the table for the id it was
given, or a null pointer for an operation this provider does not implement.

`bc-rust-provider` serves one table today.

## `OSSL_OP_DIGEST`

**bc-rust** hashes:

| Algorithm | Registered names |
|-----------|------------------|
| SHA2-224 | `SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4` |
| SHA2-256 | `SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1` |
| SHA2-384 | `SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2` |
| SHA2-512 | `SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3` |
| SHA3-224 | `SHA3-224:2.16.840.1.101.3.4.2.7` |
| SHA3-256 | `SHA3-256:2.16.840.1.101.3.4.2.8` |
| SHA3-384 | `SHA3-384:2.16.840.1.101.3.4.2.9` |
| SHA3-512 | `SHA3-512:2.16.840.1.101.3.4.2.10` |

All are registered with the property `provider=bc_rust`, so a fetch can be
pinned to this provider with `-propquery "?provider=bc_rust"`.

The table is the `DIGESTS` static in `bc-rust-provider`, reached by the core
through `ProviderDesc::digests`. Each entry pairs a name list with the
opaque `DigestFunctions` table `DigestAlgorithm::<H>::functions()` generates
for that hash. The table keeps all callbacks tied to that hash's context
type; provider code cannot combine callbacks from different implementations.

Method presence decides which optional callbacks each dispatch table contains.
These fixed-length hashes have no configurable context parameters, so they register context
parameters in neither direction — as the default provider's own fixed-length
digests do not. See [The Crate Split](./design-split.md#method-driven-dispatch).

### Serialized digest state

All registered digests support `EVP_MD_CTX_serialize` and
`EVP_MD_CTX_deserialize` on OpenSSL versions exposing those APIs. Query the
buffer size with a null output, then pass the allocated capacity through the
length slot when serializing. Initialize the destination with the same digest
algorithm before restoring. Serialization leaves the source computation
usable; a successful restore can continue absorbing input and finalize.
Rejected restores preserve the destination's previous state.

The blob is bc-rust's version-tagged `Suspendable` format, not a Rust memory
image or the OpenSSL default provider's serialization format. This provider
guarantees round trips with the same build and algorithm; it does not promise
interchange with other providers or compatibility across bc-rust upgrades.
bc-rust checks the library version tag and format-specific fields on restore;
acceptance of a version tag alone is not a cross-version guarantee.

Callers must retain the algorithm identity alongside the blob: SHA2 variants
within a state-size family do not encode that identity, so deserialization
cannot reliably reject a blob from the wrong variant. Blobs contain internal
hash state and buffered input and provide no authentication.

## Operations not served

`query_operation` returns a null pointer for every other operation id, which
the core reads as "this provider implements none of these".

## Adding an algorithm

An entry is a `const`-evaluated `OSSL_ALGORITHM`:

```rust,ignore
OSSL_ALGORITHM::new(
    c"SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1",
    PROPERTIES,
    DigestAlgorithm::<BcSha2_256>::functions(),
    c"bc-rust SHA-256",
),
```

The table must end with `OSSL_ALGORITHM::END`. That is checked at
`const`-evaluation time inside `Provider::from_desc`, so a missing terminator
is a compile error rather than an out-of-bounds read in the OpenSSL core.
