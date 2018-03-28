#!/usr/bin/perl
use strict;
use warnings;
use feature 'say';

my $include =  "/usr/src/kernels/".(split /\n/, `uname -r`)[0]."/include/"; # struggling with hated chomp's return value :)
my ($path_unistd, $path_sysc) = ($include."uapi/asm-generic/unistd.h",$include."linux/syscalls.h");
die "[FAIL] $path_unistd not found" if ! -e $path_unistd;
die "[FAIL] $path_sysc not found" if ! -e $path_sysc;
die "[FAIL] syscalls.h problem" if system "grep -A 6  ^asmlin.*sys_ $path_sysc > ./syscalls_tmp.h";

open my $fh, 'syscalls_tmp.h' or die "$!";
my $sysc_file = join '', <$fh>;
close $fh;

my @prototypes = $sysc_file =~ /^(asmlinkage\s+long\s+sys_\w+\(.+?\);)/smg;
s/\R//g for @prototypes; # re-write (1)
s/\s+/ /g for @prototypes; # re-write (2)
my %scnames = map { /(\w+)\)$/; $1 => 1 } `grep '^__SYSCALL(__NR_' $path_unistd`;

my @prots = grep {!/void/} grep ! /(\*|int|unsigned),/, @prototypes;
my @prots2 = grep /(\*|int|unsigned),/, @prototypes; # should be necessarily re-writed
my %sys_;
open $fh, '>susp_header.h' or die "$!";
for (@prots) {
	my @arr = /^asmlinkage\slong\s(sys_\w+)(\(.+\));/;
    next if ! exists $scnames{$arr[0]}; 
    say $fh "SUSP($arr[0],".eval { $arr[1] =~ /\((.*?$)/; $1 };
	$arr[1] =~ s/.+?(?:\s|\*)(\w+(?:,|\)))/$1/g;
    $sys_{$arr[0]}++;
	s/;$//;
	s/sys_/susp_sys_/;
	say $fh "$_ {";
    my $scname = eval {$arr[0] =~ /sys_(\w+)/; $1};
	say $fh "\tif (check_perm(\"$scname\")) { return (($arr[0]_type)laid_sc_table[__NR_$scname])($arr[1]; }";
	#say $fh "\tif (check_perm(\"$arr[0]\")) { return (($arr[0]_type)laid_sc_table[__NR_".eval{$arr[0] =~ /sys_(\w+)/; $1}."])($arr[1]; }";
	say $fh "\telse { return EINVAL;  }";
	say $fh "}\n"
}
close $fh;

# unistd.h
open $fh, '>sct_header.h' or die "$!";
chomp (my @_SYSCALL = `grep '^__SYSCALL(__' $path_unistd`);

for (@_SYSCALL) {
    my @arr = /__SYSCALL\((\S+),\s+(\S+)\)/;
    if (exists $sys_{$arr[1]}) {
        say $fh "\tlaid_sc_table[$arr[0]] = (void *)sys_call_table[$arr[0]];";
        say $fh "\tsys_call_table[$arr[0]] = (unsigned long *)susp_$arr[1];\n";
    }
}
close $fh;
