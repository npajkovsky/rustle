/* Copyright The OpenSSL Project Authors. All Rights Reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Loading the module under test. Shared by the test programs so each one
 * only has to say which tests it registers.
 */
#ifndef TESTUTIL_PROVIDER_H
#define TESTUTIL_PROVIDER_H

#include <openssl/types.h>

/* Property query pinning every fetch to the module under test. */
#define PROPQ "provider=bc_rust"

/*
 * The module's base name and file extension, per platform. Rust names a
 * cdylib the way the platform does, and Windows has no "lib" prefix; the
 * base name is also what OSSL_PROVIDER_load() is given, since OpenSSL's DSO
 * layer appends the extension itself.
 */
#if defined(_WIN32) || defined(__CYGWIN__)
# define BC_RUST_MODULE "bc_rust"
# define BC_RUST_MODULE_EXT ".dll"
#elif defined(__APPLE__)
# define BC_RUST_MODULE "libbc_rust"
# define BC_RUST_MODULE_EXT ".dylib"
#else /* Linux, the BSDs, and anything else ELF */
# define BC_RUST_MODULE "libbc_rust"
# define BC_RUST_MODULE_EXT ".so"
#endif

/*
 * Load the module into a fresh private library context that carries no
 * default provider, so anything fetched with PROPQ can only have come from
 * the module under test.
 *
 * `modpath` is the path to the built module, or NULL for the default build
 * location. Its directory becomes the provider search path. Returns 1 on
 * success, 0 after reporting the failure.
 */
int bc_rust_load(const char *modpath, OSSL_LIB_CTX **libctx,
		 OSSL_PROVIDER **prov);

/* Release what bc_rust_load() produced. Safe on a partial/failed load. */
void bc_rust_unload(OSSL_LIB_CTX *libctx, OSSL_PROVIDER *prov);

#endif /* TESTUTIL_PROVIDER_H */
