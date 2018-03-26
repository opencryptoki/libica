#!/usr/bin/env perl

use strict;
use warnings;

my $random_experiments = 1000;

my $out = `./drbg_birthdays_test $random_experiments 0 0`;
print("$out");

$out =~ /p = ([0-1][.][0-9][0-9])/;
exit(1) if (($1 <= 0.4) || (0.6 <= $1));
