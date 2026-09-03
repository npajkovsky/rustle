#! /usr/bin/env perl
# Copyright The OpenSSL Project Authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Bufferless parameter queries against the default and bc-rust providers.

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../perl";

use Rustle::Test;

run_test_program('params_test');
