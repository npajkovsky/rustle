# Copyright The OpenSSL Project Authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Top-level entry point.
#
#   make            build both rustle configurations and the module
#   make test       the two test suites: cargo's, and the C one under prove
#   make c-test     just the C suite, under the TAP harness
#   make check      everything a change has to pass before it is done
#   make help       list the targets
#
#   make PKG_CONFIG_PATH=/path/to/openssl/lib/pkgconfig test
#   make PROFILE=release c-test
#   make PROVE_FLAGS=-v c-test
#   make OPENSSL=/path/to/openssl cargo-test

CARGO  ?= cargo
MDBOOK ?= mdbook

# The cargo profile to build and test against. test/Makefile looks for the
# module under target/$(PROFILE), so the flag is derived from PROFILE rather
# than set on its own -- the two cannot then disagree.
PROFILE ?= debug
ifeq ($(PROFILE),release)
  CARGO_FLAGS ?= --release
else
  CARGO_FLAGS ?=
endif

# Everything test/Makefile needs from up here. PROVE_FLAGS is passed through
# unset as well, so `make PROVE_FLAGS=-v c-test` reaches the harness.
SUBMAKE = $(MAKE) -C test PROFILE=$(PROFILE) CARGO='$(CARGO)' \
	CARGO_FLAGS='$(CARGO_FLAGS)' PROVE_FLAGS='$(PROVE_FLAGS)'

.PHONY: all build build-no-std build-std module bulid-test \
	test c-test cargo-test check fmt fmt-check clippy docs clean help

all: build

# ------------------------------------------------------------------ #
# Building                                                           #
# ------------------------------------------------------------------ #

# rustle has to compile in both of its configurations, and the no_std one is
# the half that breaks silently: bc-rust-provider pulls in std, so building
# only the module never reports that rustle stopped being no_std-clean.
build: build-no-std build-std module

build-no-std:
	$(CARGO) build -p rustle --no-default-features --features abort $(CARGO_FLAGS)

build-std:
	$(CARGO) build -p rustle --features std $(CARGO_FLAGS)

module:
	$(CARGO) build -p bc-rust-provider $(CARGO_FLAGS)

bulid-test:
	$(SUBMAKE) all

# ------------------------------------------------------------------ #
# Testing                                                            #
# ------------------------------------------------------------------ #

# The two suites. cargo's drives the module through the openssl CLI; the C
# one drives it through libcrypto's EVP API, reaching what the CLI cannot.
test: cargo-test c-test

# The C suite under prove: one recipe per test program in test/recipes/.
c-test:
	$(SUBMAKE) c-test

# Note that the CLI known-answer tests skip -- passing vacuously -- when no
# OpenSSL 3.x binary is found; OPENSSL=/path/to/openssl points at one.
cargo-test:
	$(CARGO) test $(CARGO_FLAGS)

# The full gate: both configurations build, formatting is clean, both suites
# pass.
check: build fmt-check test

# ------------------------------------------------------------------ #
# Housekeeping                                                       #
# ------------------------------------------------------------------ #

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check

clippy:
	$(CARGO) clippy --all-targets $(CARGO_FLAGS)

docs:
	$(MDBOOK) build docs

clean:
	$(CARGO) clean
	$(SUBMAKE) clean

help:
	@printf '%s\n' \
	'Targets:' \
	'  all            build (the default)' \
	'  build          both rustle configurations and the module' \
	'  build-no-std   rustle without std, with its panic handler' \
	'  build-std      rustle with std' \
	'  module         the loadable provider cdylib' \
	'  bulid-test     build the C test programs without running them' \
	'' \
	'  test           cargo-test and c-test' \
	'  c-test         the C suite under the TAP harness' \
	'  cargo-test     doctests and the openssl-CLI known answers' \
	'  check          build, fmt-check, test' \
	'' \
	'  fmt            cargo fmt' \
	'  fmt-check      cargo fmt --check' \
	'  clippy         cargo clippy --all-targets' \
	'  docs           mdbook build docs' \
	'  clean          cargo clean and drop the C build artifacts' \
	'' \
	'Variables: PROFILE (debug|release), PROVE_FLAGS, CARGO, MDBOOK,' \
	'PKG_CONFIG_PATH, OPENSSL'
