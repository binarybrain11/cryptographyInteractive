#!/usr/bin/perl

use strict;
use warnings;
use lib ".";
use cryptointeractive;

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

print cryptointeractive::se2_3OtsAttack(1, \&exampleAttack), "\n";
