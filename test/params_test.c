/* Copyright The OpenSSL Project Authors. All Rights Reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

#include "testutil.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <string.h>

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *prov, *default_prov = NULL;
static OSSL_PROVIDER *params_prov;
static EVP_MD *params_md;
static const char *const propqueries[] = { "provider=default", PROPQ };

/* Each provider is tested with zero and normal data_size, always NULL data. */
static int test_size_query(int idx)
{
	OSSL_PARAM req[] = { OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
			     OSSL_PARAM_END };
	EVP_MD *md = NULL;
	int ret = 0;

	req[0].data_size = idx % 2 == 0 ? 0 : sizeof(size_t);
	TEST_note("%s: size query, data_size=%zu", propqueries[idx / 2],
		  req[0].data_size);
	if (!TEST_ptr(md = EVP_MD_fetch(libctx, "SHA2-256",
					propqueries[idx / 2])))
		goto err;
	if (!TEST_int_eq(EVP_MD_get_size(md), 32))
		goto err;

	/* Check both results even on failure, to expose an unchanged
	 * return_size. */
	ret = TEST_true(EVP_MD_get_params(md, req));
	ret &= TEST_size_t_eq(req[0].return_size, sizeof(size_t));
	ret &= TEST_ptr_null(req[0].data);
err:
	EVP_MD_free(md);
	return ret;
}

static int test_status_query(int idx)
{
	OSSL_PROVIDER *p = idx / 2 == 0 ? default_prov : prov;
	OSSL_PARAM req[] = { OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
			     OSSL_PARAM_END };
	int ret;

	req[0].data_size = idx % 2 == 0 ? 0 : sizeof(int);
	TEST_note("%s: status query, data_size=%zu", propqueries[idx / 2],
		  req[0].data_size);
	ret = TEST_true(OSSL_PROVIDER_get_params(p, req));
	ret &= TEST_size_t_eq(req[0].return_size, sizeof(int));
	ret &= TEST_ptr_null(req[0].data);
	return ret;
}

static int test_name_query(int idx)
{
	OSSL_PROVIDER *p = idx / 2 == 0 ? default_prov : prov;
	const char *name = NULL;
	OSSL_PARAM value[] = { OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, &name,
						   0),
			       OSSL_PARAM_END };
	OSSL_PARAM req[] = { OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
			     OSSL_PARAM_END };
	int ret;

	/* UTF8_PTR reports the string length, excluding NUL, not pointer size.
	 */
	if (!TEST_true(OSSL_PROVIDER_get_params(p, value)) || !TEST_ptr(name))
		return 0;
	req[0].data_size = idx % 2 == 0 ? 0 : sizeof(name);
	TEST_note("%s: name query, data_size=%zu", propqueries[idx / 2],
		  req[0].data_size);
	ret = TEST_true(OSSL_PROVIDER_get_params(p, req));
	ret &= TEST_size_t_eq(req[0].return_size, strlen(name));
	ret &= TEST_ptr_null(req[0].data);
	return ret;
}

static const struct {
	const char *name;
	const char *key;
	const char *value;
	size_t data_size;
	int bufferless;
	unsigned int data_type;
} string_cases[] = {
	{ "query", "test-text", "abc", 0, 1, OSSL_PARAM_UTF8_STRING },
	{ "query with size", "test-text", "abc", 4, 1, OSSL_PARAM_UTF8_STRING },
	{ "empty query", "test-empty", "", 0, 1, OSSL_PARAM_UTF8_STRING },
	{ "empty, zero capacity", "test-empty", "", 0, 0,
	  OSSL_PARAM_UTF8_STRING },
	{ "empty with NUL", "test-empty", "", 1, 0, OSSL_PARAM_UTF8_STRING },
	{ "short buffer", "test-text", "abc", 2, 0, OSSL_PARAM_UTF8_STRING },
	{ "exact text length", "test-text", "abc", 3, 0,
	  OSSL_PARAM_UTF8_STRING },
	{ "room for NUL", "test-text", "abc", 4, 0, OSSL_PARAM_UTF8_STRING },
	{ "spare capacity", "test-text", "abc", 8, 0, OSSL_PARAM_UTF8_STRING },
	{ "wrong type", "test-text", "abc", 8, 0, OSSL_PARAM_OCTET_STRING },
};

static int test_utf8_string(int idx)
{
	unsigned char actual[8], expected[8];
	OSSL_PARAM req[] = { OSSL_PARAM_END, OSSL_PARAM_END };
	OSSL_PARAM reference;
	int expected_ret, ret;

	TEST_note("set_utf8_string: %s", string_cases[idx].name);
	memset(actual, 0xa5, sizeof(actual));
	memset(expected, 0xa5, sizeof(expected));
	/* Set size explicitly to avoid the constructor's strlen shortcut. */
	req[0] = OSSL_PARAM_construct_utf8_string(string_cases[idx].key, NULL,
						  0);
	req[0].data = string_cases[idx].bufferless ? NULL : actual;
	req[0].data_size = string_cases[idx].data_size;
	req[0].data_type = string_cases[idx].data_type;
	reference = req[0];
	reference.data = string_cases[idx].bufferless ? NULL : expected;

	expected_ret =
		OSSL_PARAM_set_utf8_string(&reference, string_cases[idx].value);
	/* The short-buffer and wrong-type control calls may queue errors. */
	ERR_clear_error();
	ret = TEST_int_eq(EVP_MD_get_params(params_md, req), expected_ret);
	ret &= TEST_size_t_eq(req[0].return_size, reference.return_size);
	/* Compare all bytes, including NUL and the untouched buffer tail. */
	ret &= TEST_mem_eq(actual, sizeof(actual), expected, sizeof(expected));
	return ret;
}

int setup_tests(void)
{
	if (!bc_rust_load(test_argc > 1 ? test_argv[1] : NULL, &libctx, &prov))
		return 0;
	if (!TEST_ptr(default_prov = OSSL_PROVIDER_load(libctx, "default")))
		return 0;
	if (!TEST_ptr(params_prov =
			      OSSL_PROVIDER_load(libctx, PARAMS_PROVIDER_PATH))
	    || !TEST_ptr(params_md =
				 EVP_MD_fetch(libctx, "RUSTLE-PARAMS-TEST",
					      "provider=rustle_params_test")))
		return 0;

	ADD_ALL_TESTS(test_size_query, 2 * ARRAY_SIZE(propqueries));
	ADD_ALL_TESTS(test_status_query, 2 * ARRAY_SIZE(propqueries));
	ADD_ALL_TESTS(test_name_query, 2 * ARRAY_SIZE(propqueries));
	ADD_ALL_TESTS(test_utf8_string, ARRAY_SIZE(string_cases));
	return 1;
}

void cleanup_tests(void)
{
	EVP_MD_free(params_md);
	OSSL_PROVIDER_unload(params_prov);
	OSSL_PROVIDER_unload(default_prov);
	bc_rust_unload(libctx, prov);
}
