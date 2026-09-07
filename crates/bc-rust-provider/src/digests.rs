// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Adapter slotting bc-rust hashes into `rustle`'s safe [`Digest`] trait.
//!
//! bc-rust's [`Hash`] finalizers consume the hash value, while the provider
//! contract finalizes through a mutable context; [`BcDigest`] bridges that
//! with [`core::mem::take`] (finalize the current state, leave a fresh one).

use bouncycastle::core::traits::{Hash, HashAlgParams};
use bouncycastle::{sha2, sha3};
use rustle::digest::{Digest, Output, Result};
use rustle::params::Params;

/// A bc-rust hash behind the provider's [`Digest`] trait.
///
/// Works for any cloneable bc-rust hash: [`Hash`] supplies construction and
/// the streaming API, while [`HashAlgParams`] supplies the digest/block
/// lengths as consts.
pub struct BcDigest<H>(H);

#[rustle::vtable]
impl<H: Hash + HashAlgParams + Clone + 'static> Digest for BcDigest<H> {
    fn newctx() -> Result<Self> {
        Ok(Self(H::default()))
    }

    fn init(&mut self, _params: Option<Params<'_>>) -> Result {
        self.0 = H::default();
        Ok(())
    }

    // The values are per-`H`, but the table of names/types is not; the macro
    // puts it in one shared fn-local static.
    rustle::gettable_params! {
        c"blocksize": UNSIGNED_INTEGER => |p| p.set_size_t(H::BLOCK_LEN),
        c"size":      UNSIGNED_INTEGER => |p| p.set_size_t(H::OUTPUT_LEN),
    }

    fn update(&mut self, data: &[u8]) -> Result {
        self.0.do_update(data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut Output<'_>) -> Result {
        out.write_with(H::OUTPUT_LEN, |bytes| {
            core::mem::take(&mut self.0).do_final_out(bytes);
            Ok(())
        })
    }

    fn dupctx(&self) -> Result<Self> {
        Ok(Self(self.0.clone()))
    }
}

/// bc-rust's SHA2-224 as a provider digest.
pub type BcSha2_224 = BcDigest<sha2::SHA224>;
/// bc-rust's SHA2-256 as a provider digest.
pub type BcSha2_256 = BcDigest<sha2::SHA256>;
/// bc-rust's SHA2-384 as a provider digest.
pub type BcSha2_384 = BcDigest<sha2::SHA384>;
/// bc-rust's SHA2-512 as a provider digest.
pub type BcSha2_512 = BcDigest<sha2::SHA512>;

/// bc-rust's SHA3-224 as a provider digest.
pub type BcSha3_224 = BcDigest<sha3::SHA3_224>;
/// bc-rust's SHA3-256 as a provider digest.
pub type BcSha3_256 = BcDigest<sha3::SHA3_256>;
/// bc-rust's SHA3-384 as a provider digest.
pub type BcSha3_384 = BcDigest<sha3::SHA3_384>;
/// bc-rust's SHA3-512 as a provider digest.
pub type BcSha3_512 = BcDigest<sha3::SHA3_512>;
