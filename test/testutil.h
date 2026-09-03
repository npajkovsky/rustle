/* Copyright The OpenSSL Project Authors. All Rights Reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * A minimal stand-in for OpenSSL's test/testutil framework, laid out the
 * same way: this public header plus the driver under testutil/.
 *
 * Same shape as the real thing, ~10% of the code: a test file defines
 *
 *     static int test_thing(void) { ... return 1; }
 *     int setup_tests(void) { ADD_TEST(test_thing); return 1; }
 *
 * and links against testutil/driver.c, which supplies main(), the TAP output
 * and the TEST_* assertion macros. Optionally define
 *
 *     int  global_init(void);   -- run before anything else, 0 aborts
 *     void cleanup_tests(void); -- run after the last test
 *
 * both of which have weak no-op defaults in testutil/driver.c.
 *
 * A test function returns 1 for pass, 0 for fail, TEST_SKIP_CODE to skip.
 * Assertions do not abort: they print the failure and evaluate to 0, so the
 * usual idiom is
 *
 *     if (!TEST_ptr(md) || !TEST_mem_eq(out, outl, want, sizeof(want)))
 *             goto err;
 *
 * Output is TAP on stdout, diagnostics on stderr. Exit status is 0 when
 * every test passed, 1 otherwise.
 *
 * Command line: [-list] [-test N] [-iter N]
 * Any argument the driver does not recognise is left in test_argc/test_argv
 * for the test file to consume (see provider_test.c for a worked example).
 */
#ifndef TEST_H
#define TEST_H

#include <stddef.h>
#include <stdint.h>

#include "testutil/provider.h"

/* ------------------------------------------------------------------ */
/* Supplied by the test file                                          */
/* ------------------------------------------------------------------ */

/* Register the tests. Return 1 on success, 0 to print usage, -1 on error. */
int setup_tests(void);
/* Optional hooks; weak no-op defaults live in test.c. */
int global_init(void);
void cleanup_tests(void);

/* Unconsumed command line arguments, valid from setup_tests() onwards. */
extern int test_argc;
extern char **test_argv;

/* ------------------------------------------------------------------ */
/* Registration                                                       */
/* ------------------------------------------------------------------ */

#define ADD_TEST(fn) add_test(#fn, fn)
#define ADD_ALL_TESTS(fn, num) add_all_tests(#fn, fn, num, 1)
#define ADD_ALL_TESTS_NOSUBTEST(fn, num) add_all_tests(#fn, fn, num, 0)

void add_test(const char *name, int (*fn)(void));
void add_all_tests(const char *name, int (*fn)(int idx), int num, int subtest);

/* Return this from a test function to report it as skipped. */
#define TEST_SKIP_CODE 0xdead

/* printf-format checking on the failure reporters, as OpenSSL's
 * PRINTF_FORMAT does. */
#if defined(__GNUC__) || defined(__clang__)
# define TEST_PRINTF_FORMAT(f, a) __attribute__((format(printf, f, a)))
#else
# define TEST_PRINTF_FORMAT(f, a)
#endif

/* ------------------------------------------------------------------ */
/* Assertions                                                         */
/* ------------------------------------------------------------------ */

/*
 * Numeric comparisons, generated one function per (type, op) pair the way
 * OpenSSL's test/testutil.h does it: DECLARE_COMPARISONS here declares the
 * six operators for a type, DEFINE_COMPARISONS in testutil/driver.c defines
 * them. Adding a type is one line on each side.
 */
#define DECLARE_COMPARISON(type, name, opname)                                 \
	int test_##name##_##opname(const char *, int, const char *,            \
				   const char *, const type, const type);

#define DECLARE_COMPARISONS(type, name)                                        \
	DECLARE_COMPARISON(type, name, eq)                                     \
	DECLARE_COMPARISON(type, name, ne)                                     \
	DECLARE_COMPARISON(type, name, lt)                                     \
	DECLARE_COMPARISON(type, name, le)                                     \
	DECLARE_COMPARISON(type, name, gt)                                     \
	DECLARE_COMPARISON(type, name, ge)

DECLARE_COMPARISONS(int, int)
DECLARE_COMPARISONS(unsigned int, uint)
DECLARE_COMPARISONS(char, char)
DECLARE_COMPARISONS(unsigned char, uchar)
DECLARE_COMPARISONS(long, long)
DECLARE_COMPARISONS(unsigned long, ulong)
DECLARE_COMPARISONS(int64_t, int64_t)
DECLARE_COMPARISONS(uint64_t, uint64_t)
DECLARE_COMPARISONS(double, double)
DECLARE_COMPARISONS(size_t, size_t)

/*
 * Pointer comparisons against other pointers and null.
 * These functions return 1 if the test is true.
 * Otherwise, they return 0 and pretty-print diagnostics.
 * These should not be called directly, use the TEST_xxx macros instead.
 */
DECLARE_COMPARISON(void *, ptr, eq)
DECLARE_COMPARISON(void *, ptr, ne)
int test_ptr(const char *file, int line, const char *s, const void *p);
int test_ptr_null(const char *file, int line, const char *s, const void *p);

/*
 * Equality tests for strings where NULL is a legitimate value.
 * These calls return 1 if the two passed strings compare true.
 * Otherwise, they return 0 and pretty-print diagnostics.
 * These should not be called directly, use the TEST_xxx macros instead.
 */
DECLARE_COMPARISON(char *, str, eq)
DECLARE_COMPARISON(char *, str, ne)

/*
 * Same as above, but for strncmp.
 */
int test_strn_eq(const char *file, int line, const char *, const char *,
		 const char *a, const char *b, size_t n);
int test_strn_ne(const char *file, int line, const char *, const char *,
		 const char *a, const char *b, size_t n);

/*
 * Equality test for memory blocks where NULL is a legitimate value.
 * These calls return 1 if the two memory blocks compare true.
 * Otherwise, they return 0 and pretty-print diagnostics.
 * These should not be called directly, use the TEST_xxx macros instead.
 */
int test_mem_eq(const char *, int, const char *, const char *, const void *,
		size_t, const void *, size_t);
int test_mem_ne(const char *, int, const char *, const char *, const void *,
		size_t, const void *, size_t);

/*
 * Check a boolean result for being true or false.
 * They return 1 if the condition is true (i.e. the value is non-zero).
 * Otherwise, they return 0 and pretty-prints diagnostics using |s|.
 * These should not be called directly, use the TEST_xxx macros below instead.
 */
int test_true(const char *file, int line, const char *s, int b);
int test_false(const char *file, int line, const char *s, int b);

#define TEST_int_eq(a, b) test_int_eq(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_int_ne(a, b) test_int_ne(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_int_lt(a, b) test_int_lt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_int_le(a, b) test_int_le(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_int_gt(a, b) test_int_gt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_int_ge(a, b) test_int_ge(__FILE__, __LINE__, #a, #b, a, b)

#define TEST_uint_eq(a, b) test_uint_eq(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uint_ne(a, b) test_uint_ne(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uint_lt(a, b) test_uint_lt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uint_le(a, b) test_uint_le(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uint_gt(a, b) test_uint_gt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uint_ge(a, b) test_uint_ge(__FILE__, __LINE__, #a, #b, a, b)

#define TEST_char_eq(a, b) test_char_eq(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_char_ne(a, b) test_char_ne(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_char_lt(a, b) test_char_lt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_char_le(a, b) test_char_le(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_char_gt(a, b) test_char_gt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_char_ge(a, b) test_char_ge(__FILE__, __LINE__, #a, #b, a, b)

#define TEST_uchar_eq(a, b) test_uchar_eq(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uchar_ne(a, b) test_uchar_ne(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uchar_lt(a, b) test_uchar_lt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uchar_le(a, b) test_uchar_le(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uchar_gt(a, b) test_uchar_gt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uchar_ge(a, b) test_uchar_ge(__FILE__, __LINE__, #a, #b, a, b)

#define TEST_long_eq(a, b) test_long_eq(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_long_ne(a, b) test_long_ne(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_long_lt(a, b) test_long_lt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_long_le(a, b) test_long_le(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_long_gt(a, b) test_long_gt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_long_ge(a, b) test_long_ge(__FILE__, __LINE__, #a, #b, a, b)

#define TEST_ulong_eq(a, b) test_ulong_eq(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_ulong_ne(a, b) test_ulong_ne(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_ulong_lt(a, b) test_ulong_lt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_ulong_le(a, b) test_ulong_le(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_ulong_gt(a, b) test_ulong_gt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_ulong_ge(a, b) test_ulong_ge(__FILE__, __LINE__, #a, #b, a, b)

#define TEST_int64_t_eq(a, b) test_int64_t_eq(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_int64_t_ne(a, b) test_int64_t_ne(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_int64_t_lt(a, b) test_int64_t_lt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_int64_t_le(a, b) test_int64_t_le(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_int64_t_gt(a, b) test_int64_t_gt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_int64_t_ge(a, b) test_int64_t_ge(__FILE__, __LINE__, #a, #b, a, b)

#define TEST_uint64_t_eq(a, b)                                                 \
	test_uint64_t_eq(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uint64_t_ne(a, b)                                                 \
	test_uint64_t_ne(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uint64_t_lt(a, b)                                                 \
	test_uint64_t_lt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uint64_t_le(a, b)                                                 \
	test_uint64_t_le(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uint64_t_gt(a, b)                                                 \
	test_uint64_t_gt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_uint64_t_ge(a, b)                                                 \
	test_uint64_t_ge(__FILE__, __LINE__, #a, #b, a, b)

#define TEST_size_t_eq(a, b) test_size_t_eq(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_size_t_ne(a, b) test_size_t_ne(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_size_t_lt(a, b) test_size_t_lt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_size_t_le(a, b) test_size_t_le(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_size_t_gt(a, b) test_size_t_gt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_size_t_ge(a, b) test_size_t_ge(__FILE__, __LINE__, #a, #b, a, b)

#define TEST_double_eq(a, b) test_double_eq(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_double_ne(a, b) test_double_ne(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_double_lt(a, b) test_double_lt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_double_le(a, b) test_double_le(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_double_gt(a, b) test_double_gt(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_double_ge(a, b) test_double_ge(__FILE__, __LINE__, #a, #b, a, b)

#define TEST_ptr(a) test_ptr(__FILE__, __LINE__, #a, a)
#define TEST_ptr_null(a) test_ptr_null(__FILE__, __LINE__, #a, a)
#define TEST_ptr_eq(a, b) test_ptr_eq(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_ptr_ne(a, b) test_ptr_ne(__FILE__, __LINE__, #a, #b, a, b)

#define TEST_str_eq(a, b) test_str_eq(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_str_ne(a, b) test_str_ne(__FILE__, __LINE__, #a, #b, a, b)
#define TEST_strn_eq(a, b, n) test_strn_eq(__FILE__, __LINE__, #a, #b, a, b, n)
#define TEST_strn_ne(a, b, n) test_strn_ne(__FILE__, __LINE__, #a, #b, a, b, n)

#define TEST_mem_eq(a, m, b, n)                                                \
	test_mem_eq(__FILE__, __LINE__, #a, #b, a, m, b, n)
#define TEST_mem_ne(a, m, b, n)                                                \
	test_mem_ne(__FILE__, __LINE__, #a, #b, a, m, b, n)

#define TEST_true(a) test_true(__FILE__, __LINE__, #a, (a) != 0)
#define TEST_false(a) test_false(__FILE__, __LINE__, #a, (a) != 0)

/* ------------------------------------------------------------------ */
/* Diagnostics                                                        */
/* ------------------------------------------------------------------ */

#if defined(__GNUC__) || defined(__clang__)
# define TEST_PRINTF(f, a) __attribute__((format(printf, f, a)))
#else
# define TEST_PRINTF(f, a)
#endif

void test_diag(const char *prefix, const char *file, int line, const char *fmt,
	       ...) TEST_PRINTF(4, 5);
void test_note(const char *fmt, ...) TEST_PRINTF(1, 2);
/* Dump and clear the OpenSSL error queue (no-op if built -DTEST_NO_ERR). */
void test_openssl_errors(void);
void test_perror(const char *s);

#define TEST_error(...) test_diag("ERROR", __FILE__, __LINE__, __VA_ARGS__)
#define TEST_info(...) test_diag("INFO", __FILE__, __LINE__, __VA_ARGS__)
#define TEST_skip(...)                                                         \
	(test_diag("SKIP", __FILE__, __LINE__, __VA_ARGS__), TEST_SKIP_CODE)
#define TEST_note test_note

#if defined(__GNUC__) || defined(__clang__)
# define TEST_SAME_TYPE(a, b)                                                  \
	 __builtin_types_compatible_p(__typeof__(a), __typeof__(b))
/* &(x)[0] has x's type only for a pointer, and char[-1] does not compile. */
# define TEST_MUST_BE_ARRAY(x)                                                 \
	 (0 * sizeof(char[1 - 2 * TEST_SAME_TYPE((x), &(x)[0])]))
#else
# define TEST_MUST_BE_ARRAY(x) 0
#endif

#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]) + TEST_MUST_BE_ARRAY((x)))

#endif /* TEST_H */
