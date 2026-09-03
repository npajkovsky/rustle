#! /usr/bin/env perl
# Copyright The OpenSSL Project Authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# The digests through libcrypto's EVP API: FIPS 180-4 / FIPS 202 known
# answers, the digest-wide params, streaming updates, and context
# duplication. See ../evp_md_test.c.

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../perl";

use Rustle::Test;

run_test_program('evp_md_test');
