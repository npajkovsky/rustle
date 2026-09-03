#! /usr/bin/env perl
# Copyright The OpenSSL Project Authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# The provider itself: its identity params, and that the operations it does
# not serve stay unresolvable through it. See ../provider_test.c.

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../perl";

use Rustle::Test;

run_test_program('provider_test');
