#!/usr/bin/perl
use strict;
use warnings;
use feature 'say';

my @SCnames = map /susp_sys_(\w+);$/, `grep susp_sys sct_header.h`;
die "FAILED" if ! @SCnames;
open my $fh, '>susp_versa.h' or die "$!";
say $fh 'int restore_sc_table(void *data) {';
for (@SCnames) { say $fh "\tSUSP_VERSA($_)" }
say $fh '}';
