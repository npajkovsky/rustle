# Copyright The OpenSSL Project Authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Build and run the C-side tests against the built provider module.
#
# libcrypto is found with pkg-config. The top-level Makefile supplies the
# search path when OPENSSL_ROOT_DIR selects a custom OpenSSL build tree.
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
OSSL_LIBDIR := $(shell $(PKGCONF) --variable=libdir libcrypto)
OSSL_PCFILE := $(shell $(PKGCONF) --variable=pcfiledir libcrypto)/libcrypto.pc

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

# Bake the libcrypto location into each test binary at link time, so it
# needs no DYLD_LIBRARY_PATH/LD_LIBRARY_PATH to find it at runtime.
ifneq (,$(filter MINGW% MSYS% CYGWIN%,$(UNAME)))
  RPATH_LDFLAGS :=
else
  RPATH_LDFLAGS := -Wl,-rpath,$(OSSL_LIBDIR)
endif

# Where cargo puts the cdylib.
PROFILE    ?= debug
MODULE_DIR ?= ../target/$(PROFILE)

# Linked into every test program: the driver supplies main(), the helper
# loads the module under test.
COMMON_SRCS := testutil/driver.c testutil/provider.c

TEST_SRCS := provider_test.c evp_md_test.c params_test.c
TESTS     := $(TEST_SRCS:%.c=%$(EXE))

SRCS := $(TEST_SRCS) $(COMMON_SRCS)
OBJS := $(SRCS:.c=.o)
DEPS := $(OBJS:.o=.d)

COMMON_OBJS := $(COMMON_SRCS:.c=.o)

# One prove recipe per test program. A recipe execs its program, so the
# driver's TAP reaches the harness unaltered; dropping in a new .t is enough.
RECIPES := $(sort $(wildcard recipes/*.t))

.PHONY: all module params-provider c-test test run clean FORCE
all: $(TESTS)

# Snapshot global flags before target-specific additions can be inherited.
# Compare contents on every invocation, but change the timestamp only when
# configuration changes. All objects then rebuild and every binary relinks.
BUILD_CONFIG := CC=$(CC) CFLAGS=$(CFLAGS) PKGCONF=$(PKGCONF) OSSL_PCFILE=$(OSSL_PCFILE) OSSL_LIBS=$(OSSL_LIBS) RPATH_LDFLAGS=$(RPATH_LDFLAGS) MODULE_DIR=$(MODULE_DIR)
shell_quote = '$(subst ','"'"',$(1))'

.build-config: FORCE
	@printf '%s\n' $(call shell_quote,$(BUILD_CONFIG)) > $@.tmp
	@if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv -f $@.tmp $@; fi

$(OBJS): .build-config

# The inline-string setter is exercised by a test-only provider, built as a
# cdylib example of rustle. Production algorithms expose no inline strings.
params_test.o: CFLAGS += -DPARAMS_PROVIDER_PATH=\"$(abspath $(MODULE_DIR))/examples/$(subst bc_rust,params_provider,$(MODULE))\"
params_test$(EXE): | params-provider

params-provider:
	$(CARGO) build --manifest-path ../Cargo.toml -p rustle --example params_provider --features std $(CARGO_FLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Static pattern rule: the stem drops $(EXE), so each test links against its
# own object plus the common ones. Adding a test means adding it to TEST_SRCS.
$(TESTS): %$(EXE): %.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(OSSL_LIBS) $(RPATH_LDFLAGS)
ifeq ($(UNAME),Darwin)
	@crypto_install_name=$$(otool -L '$@' \
		| awk '/libcrypto.*[.]dylib/ { print $$1; exit }'); \
	case "$$crypto_install_name" in \
	/*) install_name_tool -change "$$crypto_install_name" \
		"@rpath/$$(basename "$$crypto_install_name")" '$@' ;; \
	esac
endif

# The module under test. Its profile has to be the one MODULE_DIR names.
module:
	$(CARGO) build --manifest-path ../Cargo.toml -p bc-rust-provider $(CARGO_FLAGS)

# Run the suite under the TAP harness. This is the canonical way to run it,
# and what `make test` at the workspace root ends up calling. The recipes
# take both paths from the environment so that they hold no build knowledge
# of their own -- the fallbacks in perl/Rustle/Test.pm only cover running a
# recipe by hand. Note libcrypto itself is *not* among those paths: each test
# binary already knows where to find it via the rpath baked in above.
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
	rm -f .build-config .build-config.tmp
	rm -rf $(TESTS:%=%.dSYM)

FORCE:

-include $(DEPS)
