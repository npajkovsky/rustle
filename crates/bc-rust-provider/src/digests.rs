//! Adapter slotting bc-rust hashes into `rustle`'s safe [`Digest`] trait.
//!
//! bc-rust's [`Hash`] finalizers consume the hash value, while the provider
//! contract finalizes through a mutable context; [`BcDigest`] bridges that
//! with [`core::mem::take`] (finalize the current state, leave a fresh one).

use bouncycastle::core::traits::{Hash, HashAlgParams};
use bouncycastle::{sha2, sha3};
use rustle::digest::Digest;

/// A bc-rust hash behind the provider's [`Digest`] trait.
///
/// Works for any bc-rust hash: [`Hash`] supplies the streaming API and the
/// `Default` that [`Digest`] and the `mem::take` finalize need, and
/// [`HashAlgParams`] supplies the digest/block lengths as consts.
#[derive(Clone, Default)]
pub struct BcDigest<H>(H);

impl<H: Hash + HashAlgParams + Clone> Digest for BcDigest<H> {
    const DIGEST_LEN: usize = H::OUTPUT_LEN;
    const BLOCK_LEN: usize = H::BLOCK_LEN;

    // The values are per-`H`, but the table of names/types is not; the macro
    // puts it in one shared fn-local static.
    rustle::gettable_params! {
        c"blocksize": UNSIGNED_INTEGER => |p| p.set_size_t(Self::BLOCK_LEN),
        c"size":      UNSIGNED_INTEGER => |p| p.set_size_t(Self::DIGEST_LEN),
    }

    fn update(&mut self, data: &[u8]) {
        self.0.do_update(data);
    }

    fn finalize(&mut self, out: &mut [u8]) {
        core::mem::take(&mut self.0).do_final_out(out);
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
