/* Copyright The OpenSSL Project Authors. All Rights Reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

#include "testutil.h"

#include "testutil/provider.h"

#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <string.h>

/*
 * Where cargo puts the module, and what it calls it. Rust names a cdylib
 * the platform's way: libbc_rust.dylib on macOS, libbc_rust.so on Linux and
 * the BSDs, bc_rust.dll on Windows -- note Windows has no "lib" prefix.
 *
 * The build system can override either macro; DEFAULT_MODULE_DIR exists so
 * a release build can point at target/release.
 */
#ifndef DEFAULT_MODULE_DIR
# define DEFAULT_MODULE_DIR "../target/debug"
#endif

#ifndef DEFAULT_MODULE
# define DEFAULT_MODULE DEFAULT_MODULE_DIR "/" BC_RUST_MODULE BC_RUST_MODULE_EXT
#endif

/*
 * Strip the last path component in place, leaving the directory. Stands in
 * for POSIX dirname(3), which does not exist on Windows, and accepts both
 * separators so a Windows path works wherever the test runs.
 *
 * Deliberately simpler than dirname(3): no trailing-separator collapsing
 * and no drive-letter handling beyond what falls out of splitting on '\\'.
 * It only has to find the directory a just-built module sits in.
 */
static void strip_last_component(char *path)
{
	char *sep = NULL, *p;

	for (p = path; *p != '\0'; p++)
		if (*p == '/' || *p == '\\')
			sep = p;

	if (sep == NULL) {
		/* No directory part: look in the current one. */
		path[0] = '.';
		path[1] = '\0';
	} else if (sep == path) {
		/* Root: keep the separator itself. */
		path[1] = '\0';
	} else {
		*sep = '\0';
	}
}

int bc_rust_load(const char *modpath, OSSL_LIB_CTX **libctx,
		 OSSL_PROVIDER **prov)
{
	char dir[2048];

	*libctx = NULL;
	*prov = NULL;

	if (modpath == NULL)
		modpath = DEFAULT_MODULE;
	/* Truncating the path would look like a missing module; say so. */
	if (!TEST_size_t_lt(strlen(modpath), sizeof(dir))) {
		TEST_note("module path too long: %s", modpath);
		return 0;
	}
	strcpy(dir, modpath);
	strip_last_component(dir);

	if (!TEST_ptr(*libctx = OSSL_LIB_CTX_new()))
		return 0;
	if (!TEST_true(OSSL_PROVIDER_set_default_search_path(*libctx, dir)))
		return 0;
	if (!TEST_ptr(*prov = OSSL_PROVIDER_load(*libctx, BC_RUST_MODULE))) {
		TEST_note("could not load %s from %s", BC_RUST_MODULE, dir);
		test_openssl_errors();
		return 0;
	}
	return 1;
}

void bc_rust_unload(OSSL_LIB_CTX *libctx, OSSL_PROVIDER *prov)
{
	if (prov != NULL)
		OSSL_PROVIDER_unload(prov);
	OSSL_LIB_CTX_free(libctx);
}
