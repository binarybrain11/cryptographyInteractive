#!/usr/bin/perl

use strict;
use warnings;
use lib ".";
use cryptointeractive;

sub printbytes {
    my $bytes = shift;
    my $i;
    for ($i = 0; $i < length($bytes); $i++) {
        printf("%08b", ord(substr($bytes, $i, 1)));
    }
}

sub exampleAttack {
    my ($lambda, $scheme) = @_;
    my $m = "\0" x $lambda;
    my $c = $scheme->{CTXT}->($m);

    if ($c eq $m){
        return "real";
    }
    else {
        return "random";
    }
}

print Advantage(1000, 1, \&se2_3OtsDistinguish, \&exampleAttack), "\n";
