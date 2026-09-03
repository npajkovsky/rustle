# Copyright The OpenSSL Project Authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Build and run the C-side tests against the built provider module.
#
# libcrypto is found with pkg-config. Override if it is not on the default
# search path, e.g.:
#   make PKG_CONFIG_PATH=/path/to/openssl/lib/pkgconfig
#
# Each .c is compiled to its own .o, so a compilation-database generator
# (compiledb, bear) records one entry per translation unit -- linking several
# sources in one cc invocation collapses them into a single entry.

CC      ?= cc
PKGCONF ?= pkg-config
CARGO   ?= cargo
PROVE   ?= prove

# Extra flags for the module build, so a caller can pick a cargo profile;
# PROFILE below then has to name the matching target/ directory.
CARGO_FLAGS ?=
# Harness flags worth knowing: -v shows every assertion, -j runs the
# recipes in parallel.
PROVE_FLAGS ?=

OSSL_CFLAGS := $(shell $(PKGCONF) --cflags libcrypto)
OSSL_LIBS   := $(shell $(PKGCONF) --libs libcrypto)

CFLAGS ?= -O2 -g
CFLAGS += -DDEFAULT_MODULE_DIR=\"$(MODULE_DIR)\"
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wshadow -pedantic -std=c99
CFLAGS += -I. $(OSSL_CFLAGS)
# Emit a .d per object so a touched header rebuilds whatever includes it.
CFLAGS += -MMD -MP

# Rust names the cdylib the platform's way; Windows has no "lib" prefix.
UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
  MODULE := libbc_rust.dylib
else ifneq (,$(filter MINGW% MSYS% CYGWIN%,$(UNAME)))
  MODULE := bc_rust.dll
  EXE    := .exe
else
  # Linux, the BSDs, and anything else ELF.
  MODULE := libbc_rust.so
endif

# Where cargo puts the cdylib.
PROFILE    ?= debug
MODULE_DIR ?= ../target/$(PROFILE)

# Linked into every test program: the driver supplies main(), the helper
# loads the module under test.
COMMON_SRCS := testutil/driver.c testutil/provider.c

TEST_SRCS := provider_test.c evp_md_test.c
TESTS     := $(TEST_SRCS:%.c=%$(EXE))

SRCS := $(TEST_SRCS) $(COMMON_SRCS)
OBJS := $(SRCS:.c=.o)
DEPS := $(OBJS:.o=.d)

COMMON_OBJS := $(COMMON_SRCS:.c=.o)

# One prove recipe per test program. A recipe execs its program, so the
# driver's TAP reaches the harness unaltered; dropping in a new .t is enough.
RECIPES := $(sort $(wildcard recipes/*.t))

.PHONY: all module c-test test run clean
all: $(TESTS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Static pattern rule: the stem drops $(EXE), so each test links against its
# own object plus the common ones. Adding a test means adding it to TEST_SRCS.
$(TESTS): %$(EXE): %.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(OSSL_LIBS)

# The module under test. Its profile has to be the one MODULE_DIR names.
module:
	$(CARGO) build --manifest-path ../Cargo.toml -p bc-rust-provider $(CARGO_FLAGS)

# Run the suite under the TAP harness. This is the canonical way to run it,
# and what `make test` at the workspace root ends up calling. The recipes
# take both paths from the environment so that they hold no build knowledge
# of their own -- the fallbacks in perl/Rustle/Test.pm only cover running a
# recipe by hand.
c-test: $(TESTS) module
	BC_RUST_TEST_DIR='$(abspath .)' \
	BC_RUST_MODULE='$(abspath $(MODULE_DIR)/$(MODULE))' \
	$(PROVE) $(PROVE_FLAGS) $(RECIPES)

test: c-test

# The same programs without the harness: raw TAP, and a failure's
# diagnostics are not interleaved with the harness's summary. To debug one
# program, run it directly -- it takes -list, -test N and -iter N.
run: $(TESTS) module
	for t in $(TESTS); do ./$$t $(MODULE_DIR)/$(MODULE) || exit 1; done

clean:
	rm -f $(TESTS) $(OBJS) $(DEPS)
	rm -rf $(TESTS:%=%.dSYM)

-include $(DEPS)
