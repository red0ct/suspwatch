#!/usr/bin/perl -n
use Storable;

$SIG{INT} = sub {
    store \%Hash, 'result.txt';
    die "Caught a sigint $!";
};

/(\w+)\s\w+\.(\w+)/;
$Hash{$1}{$2}++;
