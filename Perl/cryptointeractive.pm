package cryptointeractive;

use strict;
use warnings;
use Exporter;

our @EXPORT = qw(se2_3OtsAttack);

# General tools

sub KeyGen {
    my $lambda = shift;
    my $k = "";
    for (my $i = 0; $i < $lambda; $i++) {
        $k .= chr(int(rand(256)));
    }
    return $k;
}

################################################################################
# Chapter 2
################################################################################


########################################
# Section 2.1
# OTS
########################################

sub se2_Enc {
    my ($k, $m) = @_;
    my $c = "";
    for (my $i = 0; $i < length($m); $i++) {
        my $c = ord(substr($m, $i, 1)) & ord(substr($k, $i % length($k), 1));
        $c .= chr($c);
    }
    return $c;
}

sub se2_3EAVESDROPL{
    my ($ml, $mr) = @_;
    my $key = KeyGen(length($ml));
    my $c = se2_Enc($key, $ml);
    return $c;
}

sub se2_3EAVESDROPR{
    my ($ml, $mr) = @_;
    my $key = KeyGen(length($mr));
    my $c = se2_Enc($key, $mr);
    return $c;
}

sub se2_3CTXTreal{
    my $m = shift;
    my $key = KeyGen(length($m));
    my $c = se2_Enc($key, $m);
    return $c;
}

sub se2_3CTXTrandom{
    my $m = shift;
    my $c = "";
    for (my $i = 0; $i < length($m); $i++) {
        $c .= chr(int(rand(256)));
    }
    return $c;
}

sub se2_3OtsAttack {
    my $lambda = shift;
    my $attack = shift;
    my %scheme = ();

    my $choice = int(rand(256));
    printf "choice: 0b%b\n", $choice;
    if ($choice & 1){
        $scheme{'EAVESDROP'} = \&se2_3EAVESDROPL;
    }
    else{
        $scheme{'EAVESDROP'} = \&se2_3EAVESDROPR;
    }
    if ($choice & 2){
        $scheme{'CTXT'} = \&se2_3CTXTrandom;
    }
    else{
        $scheme{'CTXT'} = \&se2_3CTXTreal;
    }
    my $result = $attack->($lambda, \%scheme);
    if (($choice & 1) && ($result eq "left")){
        return 1;
    }
    if (!($choice & 1) && ($result eq "right")){
        return 1;
    }
    if ((($choice & 2) == 2) && ($result eq "random")){
        return 1;
    }
    if (!($choice & 2) && ($result eq "real")){
        return 1;
    }
    return 0;
}

########################################
# Chapter 2 Homework
# Problem 1
########################################

sub hw2_1KeyGen{
    my $lambda = shift;
    my $k = "";
    for (my $i = 0; $i < $lambda; $i++) {
        $k .= chr(int(rand(256)));
    }
    while ($k eq "\0"x$lambda){
        $k = "";
        for (my $i = 0; $i < $lambda; $i++) {
            $k .= chr(int(rand(256)));
        }
    }
    return $k;
}

sub hw2_1EAVESDROPL{
    my ($ml, $mr) = @_;
    my $key = hw2_1KeyGen(length($ml));
    my $c = otpDetEnc($key, $ml);
    return $c;
}

