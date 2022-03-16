package cryptointeractive;

use strict;
use warnings;
use Exporter;

our @EXPORT = qw(se2_3OtsAttack);

###############################################################################
# Primitives
###############################################################################

sub KeyGen {
    my $lambda = shift;
    my $k = "";
    for (my $i = 0; $i < $lambda; $i++) {
        $k .= chr(int(rand(256)));
    }
    return $k;
}

sub otpDetEnc{
    my $k = shift;
    my $m = shift;
    my $c = "";
    for (my $i = 0; $i < length($m); $i++) {
        $c .= chr(ord(substr($m, $i, 1)) ^ ord(substr($k, $i, 1)));
    }
    return $c;
}

sub printbytes {
    my $bytes = shift;
    my $str = "";
    for (my $i = 0; $i < length($bytes); $i++) {
        $str .= sprintf("%02x", ord(substr($bytes, $i, 1)));
    }
    return $str;
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
        my $char = ord(substr($m, $i, 1)) & ord(substr($k, $i, 1));
        $c .= chr($char);
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

sub hw2_1EAVESDROPR{
    my ($ml, $mr) = @_;
    my $key = hw2_1KeyGen(length($mr));
    my $c = otpDetEnc($key, $mr);
    return $c;
}

sub hw2_1CTXTreal{
    my $m = shift;
    my $key = hw2_1KeyGen(length($m));
    my $c = otpDetEnc($key, $m);
    return $c;
}

sub hw2_1CTXTrandom{
    my $m = shift;
    my $c = "";
    for (my $i = 0; $i < length($m); $i++) {
        $c .= chr(int(rand(256)));
    }
    return $c;
}

sub hw2_1OtsAttack {
    my $lambda = shift;
    my $attack = shift;
    my %scheme = ();

    my $choice = int(rand(256));
    if ($choice & 1){
        $scheme{'EAVESDROP'} = \&hw2_1EAVESDROPL;
    }
    else{
        $scheme{'EAVESDROP'} = \&hw2_1EAVESDROPR;
    }
    if ($choice & 2){
        $scheme{'CTXT'} = \&hw2_1CTXTrandom;
    }
    else{
        $scheme{'CTXT'} = \&hw2_1CTXTreal;
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
