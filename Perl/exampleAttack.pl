#!/usr/bin/perl

use strict;
use warnings;
use CryptoInteractive;

sub exampleAttack {
    my ($size, $scheme) = @_;
    my $m = "";
    my $c = $scheme->{ctxt}->($m);

    if ($c eq $m){
        return "real";
    }
    else {
        return "random";
    }
}

print se2_30tsAttack(\&exampleAttack);
