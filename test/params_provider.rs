// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-only provider exposing inline string parameters to the C tests.
//! Its dummy digest exists only to exercise the parameter callbacks.

#![forbid(unsafe_code)]

use rustle::bindings::OSSL_ALGORITHM;
use rustle::digest::{Digest, DigestAlgorithm};
use rustle::provider::{Provider, ProviderDesc};

#[derive(Clone, Default)]
struct TestDigest {
    _state: u8,
}

impl Digest for TestDigest {
    const DIGEST_LEN: usize = 1;
    const BLOCK_LEN: usize = 1;

    rustle::gettable_params! {
        c"size": UNSIGNED_INTEGER => |p| p.set_size_t(Self::DIGEST_LEN),
        c"blocksize": UNSIGNED_INTEGER => |p| p.set_size_t(Self::BLOCK_LEN),
        c"test-text": UTF8_STRING => |p| p.set_utf8_string("abc"),
        c"test-empty": UTF8_STRING => |p| p.set_utf8_string(""),
    }

    fn update(&mut self, _data: &[u8]) {}

    fn finalize(&mut self, out: &mut [u8]) {
        out.fill(0);
    }
}

static ALGORITHMS: [OSSL_ALGORITHM; 2] = [
    OSSL_ALGORITHM::new(
        c"RUSTLE-PARAMS-TEST",
        c"provider=rustle_params_test",
        DigestAlgorithm::<TestDigest>::functions(),
        c"Parameter test fixture; not a cryptographic digest",
    ),
    OSSL_ALGORITHM::END,
];

static PROVIDER: Provider = Provider::from_desc(ProviderDesc {
    name: c"rustle_params_test",
    version: c"0",
    buildinfo: c"test fixture",
    digests: &ALGORITHMS,
});

rustle::provider_init!(PROVIDER);
