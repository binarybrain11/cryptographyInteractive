#!/usr/bin/perl

use strict;
use warnings;
use lib ".";
use CryptoInteractive;

sub exampleAttack {
    my ($lambda, $scheme) = @_;

    # Message is a string of zero bytes of length $lambda
    my $m = "\0" x $lambda;

    # Generate ciphertext
    my $c = $scheme->{CTXT}->($m);

    # if ciphertext and message are the same, we can distinguish real from rand
    if ($c eq $m){
        return "real";
    }
    else {
        return "random";
    }
}

print Advantage(1000, 1, \&se2_3OtsDistinguish, \&exampleAttack), "\n";
