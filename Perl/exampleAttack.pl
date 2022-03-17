#!/usr/bin/perl

use strict;
use warnings;
use lib ".";
use CryptoInteractive;

sub exampleAttack {
    my ($lambda, $scheme) = @_;

    # Message is a string of zero bytes of length $lambda
    my $m = chr(0x0) x $lambda;

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

# Advantage will run the attack on a distinguisher a specified number of times
# and report the average succes rate of distinguishing the real vs rand or left vs right libraries.
# - Additionally, we are choosing lambda to be 4 in this example.
print Advantage(1000, 4, \&se2_3OtsDistinguish, \&exampleAttack), "\n";
