/* Copyright The OpenSSL Project Authors. All Rights Reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * The bc_rust loader/correctness test, written against the test driver.
 *
 *   ./provider_test ../target/debug/libbc_rust.dylib
 *   ./provider_test -list
 *   ./provider_test -test 2 ../target/debug/libbc_rust.dylib
 *
 * Checks the provider itself: its identity params, and that the operations
 * it does not serve stay unresolvable through it. The EVP_MD tests are a
 * separate program, evp_md.
 *
 * Keep this as the worked example of how to use the driver.
 */
#include "testutil.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static OSSL_LIB_CTX *libctx;
static OSSL_PROVIDER *prov;

/* ------------------------------------------------------------------ */
/* Tests                                                              */
/* ------------------------------------------------------------------ */

static int test_provider_params(void)
{
	const char *name = NULL, *version = NULL, *build = NULL;
	OSSL_PARAM req[] = {
		OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, &name, 0),
		OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, &version, 0),
		OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, &build, 0),
		OSSL_PARAM_END
	};

	if (!TEST_true(OSSL_PROVIDER_get_params(prov, req)) || !TEST_ptr(name)
	    || !TEST_str_eq(name, "bc_rust") || !TEST_ptr(version))
		return 0;
	TEST_note("name=%s version=%s build=%s", name, version,
		  build != NULL ? build : "(none)");
	return 1;
}

/* Operations the provider does not serve must not resolve through it. */
static int test_unserved_operations(void)
{
	EVP_MAC *mac = EVP_MAC_fetch(libctx, "HMAC-SHA256", PROPQ);
	EVP_KDF *kdf = EVP_KDF_fetch(libctx, "HKDF", PROPQ);
	int ret;

	ret = TEST_ptr_null(mac) && TEST_ptr_null(kdf);
	EVP_MAC_free(mac);
	EVP_KDF_free(kdf);
	/* The failed fetches queued errors; they are expected. */
	ERR_clear_error();
	return ret;
}

/* ------------------------------------------------------------------ */
/* Framework hooks                                                    */
/* ------------------------------------------------------------------ */

int setup_tests(void)
{
	if (!bc_rust_load(test_argc > 1 ? test_argv[1] : NULL, &libctx, &prov))
		return 0;

	ADD_TEST(test_provider_params);
	ADD_TEST(test_unserved_operations);
	return 1;
}

void cleanup_tests(void)
{
	bc_rust_unload(libctx, prov);
}
