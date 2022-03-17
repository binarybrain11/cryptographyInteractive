package CryptoInteractive;

use strict;
use warnings;
use Exporter;
use Crypt::Random qw(makerandom);

our @ISA = qw(Exporter);
our @EXPORT = qw( se2_3OtsDistinguish hw2_1OtsDistinguish hw5_1aPrgDistinguish
hw5_1bPrgDistinguish hw5_1cPrcDistinguish hw6_1PrfDistinguish
hw6_2PrpDistinguish hw7_2CpaDistinguish Advantage );

###############################################################################
# Primitives
###############################################################################

# Generate a random key of byte length $lambda
sub KeyGen {
    my $lambda = shift;
    my $k = "";
    for (my $i = 0; $i < $lambda; $i++) {
        $k .= makerandom(Size => 8, Strength => 0);
    }
    return $k;
}

# Performs deterministic OTP encrytpion on the message with the key.
# - k must be at least lambda bytes long
# - m must be at least lambda bytes long
# - returns a ciphertext that is lambda bytes long
sub otpDetEnc{
    my $k = shift;
    my $m = shift;
    my $c = "";
    for (my $i = 0; $i < length($m); $i++) {
        $c .= chr(ord(substr($m, $i, 1)) ^ ord(substr($k, $i, 1)));
    }
    return $c;
}

# A length doubling PRG
# - Outputs a random string of bytes of lengeth 2 * $s
# - $s is the seed for the random number generator
sub prgDouble{
    my $s = shift;
    srand($s);
    my $out = "";
    for (my $i = 0; $i < 2 * length($s); $i++) {
        $out .= chr(ord(rand(256)));
    }
    return $out;
}

# A PRF using the above length doubling PRG
# - from Construction 6.4 in the textbook
sub prf{
    my $k = shift;
    my $m = shift;
    my $v = $k;
    my $output = "";
    for (my $i = 0; $i < length($m); $i++) {
        for (my $j = 0; $j < 8; $j++) {
            if (ord(substr($m, $i, 1)) & (0x80 >> $j)) {
                $output = substr(prgDouble($k), length($k), length($k));
            }
            else {
                $output = substr(prgDouble($k), 0, length($k));
            }
        }
    }
    return $output;
}

# A PRP made using 3 round feistel
sub prp{
    my $k = shift;
    my $m = shift;
    my $k1 = substr($k, 0, length($k) / 3);
    my $k2 = substr($k, length($k) / 3, length($k) / 3);
    my $k3 = substr($k, 2 * length($k) / 3, length($k) / 3);

    my $v0 = substr($m, 0, length($m) / 2);
    my $v1 = substr($m, length($m) / 2, length($m) / 2);
    my $v2 = "";
    my $v3 = "";
    my $v4 = "";
    my $tmp = prf($k1, $v1);
    for (my $i = 0; $i < length($v0); $i++) {
        $v2 .= chr(ord(substr($v0, $i, 1)) ^ ord(substr($tmp, $i, 1)));
    }
    $tmp = prf($k2, $v2);
    for (my $i = 0; $i < length($v1); $i++) {
        $v3 .= chr(ord(substr($v1, $i, 1)) ^ ord(substr($tmp, $i, 1)));
    }
    $tmp = prf($k3, $v3);
    for (my $i = 0; $i < length($v2); $i++) {
        $v4 .= chr(ord(substr($v2, $i, 1)) ^ ord(substr($tmp, $i, 1)));
    }
    return $v3 . $v4;
}


###############################################################################
# Helper functions
###############################################################################

# Returns a string with the values of each byte of the input string in hex
sub printbytes {
    my $bytes = shift;
    my $str = "";
    for (my $i = 0; $i < length($bytes); $i++) {
        $str .= sprintf("%X", ord(substr($bytes, $i, 1)));
    }
    return $str;
}

# Returns a string with the values of each byte of the input string in binary
sub printbinary {
    my $bytes = shift;
    my $str = "";
    for (my $i = 0; $i < length($bytes); $i++) {
        $str .= sprintf("%08b", ord(substr($bytes, $i, 1)));
    }
    return $str;
}

# Computes the distinguishing advantage of an attacker. 0.5 is unable to distinguish, 
# 1 is distinguishes correctly every time, 0 distinguishes incorrectly every time
# - trials is the number of trials to run the attack. The more trials, the more 
# accurate the advantage
# - attacker is the user attack function to be called inside of the distinguish
# - distinguisher is the function representing the problem, e.g. se2_3OtsDistinguish()
# - returns a float indicating the advantage of the attacker
sub Advantage{
    my $trials = shift;
    my $lambda = shift;
    my $distinguisher = shift;
    my $attacker = shift;
    my $advantage = 0;
    for (my $i = 0; $i < $trials; $i++) {
        my $res = $distinguisher->($lambda, $attacker);
        $advantage += $res;
    }
    return $advantage / $trials;
}

################################################################################
# Chapter 2
################################################################################


########################################
# Section 2.1
# OTS
########################################

# One time secrecy (ots) example from Chapter 2 Section 3 of the book 
# - k lambda bytes key
# - m lambda bytes message
# - returns lambda bytes ciphertext
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

# Chapter 2 Section 3 example
# Implements CTXT() and EAVESDROP()
sub se2_3OtsDistinguish {
    my $lambda = shift;
    my $attack = shift;
    my %scheme = ();

    my $choice = makerandom(Size => 8, Strength => 0);
    if ($choice & 0x1){
        $scheme{'EAVESDROP'} = \&se2_3EAVESDROPL;
    }
    else{
        $scheme{'EAVESDROP'} = \&se2_3EAVESDROPR;
    }
    if ($choice & 0x2){
        $scheme{'CTXT'} = \&se2_3CTXTrandom;
    }
    else{
        $scheme{'CTXT'} = \&se2_3CTXTreal;
    }
    my $result = $attack->($lambda, \%scheme);
    if (($choice & 0x1) && ($result eq "left")){
        return 1;
    }
    if (!($choice & 0x1) && ($result eq "right")){
        return 1;
    }
    if ((($choice & 0x2)) && ($result eq "random")){
        return 1;
    }
    if (!($choice & 0x2) && ($result eq "real")){
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

# Chapter 2 Homework Problem 1
# Implements CTXT() and EAVESDROP()
sub hw2_1OtsDistinguish {
    my $lambda = shift;
    my $attack = shift;
    my %scheme = ();

    my $choice = makerandom(Size => 8, Strength => 0);
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
    if ((($choice & 2)) && ($result eq "random")){
        return 1;
    }
    if (!($choice & 2) && ($result eq "real")){
        return 1;
    }
    return 0;
}

################################################################################
# Chapter 5
################################################################################

# "Secure" length tripling PRG. Not actually secure, but treat it as such.
# - s is the seed for the PRG
# - returns a random number of length 3*len(s)
sub hw5_1G{
    my $s = shift;
    srand($s);
    my $x = "";
    for (my $i = 0; $i < 3 * length($s); $i++) {
        $x .= chr(int(rand(256)));
    }
    return $x;
}

########################################
# Homework 5
# Problem 1 a
########################################

sub hw5_1aPRGreal{
    my $s = shift;
    my $x = hw5_1G($s);
    my $y = hw5_1G("\0" x length($s));
    return $x.$y;
}

sub hw5_1aPRGrand{
    my $s = shift;
    my $x = "";
    for (my $i = 0; $i < 6 * length($s); $i++) {
        $x .= chr(makerandom(Size => 8, Strength => 0));
    }
    return $x;
}

# Chapter 5 Homework Problem 1 a
# Implements QUERY()
sub hw5_1aPrgDistinguish{
    my $lambda = shift;
    my $attack = shift;
    my %scheme = ();

    my $choice = makerandom(Size => 8, Strength => 0);
    if ($choice & 2){
        $scheme{'QUERY'} = \&hw5_1aPRGrand;
    }
    else{
        $scheme{'QUERY'} = \&hw5_1aPRGreal;
    }
    my $result = $attack->($lambda, \%scheme);
    if ((($choice & 2) == 2) && ($result eq "random")){
        return 1;
    }
    if (!($choice & 2) && ($result eq "real")){
        return 1;
    }
    return 0;
}

########################################
# Homework 5
# Problem 1 b
########################################

sub hw5_1bPRGreal{
    my $s = shift;
    my $x = hw5_1G($s);
    my $y = hw5_1G("\0" x length($s));
    my $z = "";
    for (my $i = 0; $i < 3 * length($s); $i++) {
        $z .= chr(ord(substr($x, $i, 1)) ^ ord(substr($y, $i, 1)));
    }
    return $z;
}

sub hw5_1bPRGrand{
    my $s = shift;
    my $x = "";
    for (my $i = 0; $i < 3 * length($s); $i++) {
        $x .= chr(makerandom(Size => 8, Strength => 0));
    }
    return $x;
}

# Chapter 5 Homework Problem 1 b
# Implements QUERY()
sub hw5_1bPrgDistinguish{
    my $lambda = shift;
    my $attack = shift;
    my %scheme = ();

    my $choice = makerandom(Size => 8, Strength => 0);
    if ($choice & 2){
        $scheme{'QUERY'} = \&hw5_1bPRGrand;
    }
    else{
        $scheme{'QUERY'} = \&hw5_1bPRGreal;
    }
    my $result = $attack->($lambda, \%scheme);
    if ((($choice & 2) == 2) && ($result eq "random")){
        return 1;
    }
    if (!($choice & 2) && ($result eq "real")){
        return 1;
    }
    return 0;
}

########################################
# Homework 5
# Problem 1 c
########################################

sub hw5_1cPRGreal{
    my $s = shift;
    my $combined = hw5_1G($s);
    my $x = substr($combined, 0, length($s));
    my $w = hw5_1G($x);
    return $combined.$w;
}

sub hw5_1cPRGrand{
    my $s = shift;
    my $x = "";
    for (my $i = 0; $i < 6 * length($s); $i++) {
        $x .= chr(makerandom(Size => 8, Strength => 0));
    }
    return $x;
}

# Chapter 5 Homework Problem 1 c
# Implements QUERY()
sub hw5_1cPrcDistinguish{
    my $lambda = shift;
    my $attack = shift;
    my %scheme = ();

    my $choice = makerandom(Size => 8, Strength => 0);
    if ($choice & 2){
        $scheme{'QUERY'} = \&hw5_1cPRGrand;
    }
    else{
        $scheme{'QUERY'} = \&hw5_1cPRGreal;
    }
    my $result = $attack->($lambda, \%scheme);
    if ((($choice & 2) == 2) && ($result eq "random")){
        return 1;
    }
    if (!($choice & 2) && ($result eq "real")){
        return 1;
    }
    return 0;
}

################################################################################
# Chapter 6
################################################################################


########################################
# Homework 6
# Problem 1
########################################

our $hw6_1GLOBAL_K;
our %hw6_1GLOBAL_T;

sub hw6_1Prf{
    my $k = shift;
    my $m = shift;
    my $x = prf($k, $m);
    my $y = prf($k, $x);
    return $x . $y;
}

sub hw6_1LOOKUPreal{
    my $m = shift;
    return hw6_1Prf($hw6_1GLOBAL_K, $m);
}

sub hw6_1LOOKUPrand{
    my $m = shift;
    if (exists $hw6_1GLOBAL_T{$m}){
        return $hw6_1GLOBAL_T{$m};
    }
    else{
        my $x = "";
        for (my $i = 0; $i < length($m); $i++) {
            $x .= chr(makerandom(Size => 8, Strength => 0));
        }
        $hw6_1GLOBAL_T{$m} = $x;
        return $x;
    }
}

# Chapter 6 Homework Problem 1
# Implements LOOKUP()
sub hw6_1PrfDistinguish{
    my $lambda = shift;
    my $attack = shift;
    my %scheme = ();

    my $choice = makerandom(Size => 8, Strength => 0);
    if ($choice & 1){
        $scheme{'LOOKUP'} = \&hw6_1LOOKUPrand;
    }
    else{
        $scheme{'LOOKUP'} = \&hw6_1LOOKUPreal;
    }
    $hw6_1GLOBAL_K = "";
    for (my $i = 0; $i < $lambda; $i++) {
        $hw6_1GLOBAL_K .= chr(makerandom(Size => 8, Strength => 0));
    }
    my $result = $attack->($lambda, \%scheme);
    if ((($choice & 1) == 1) && ($result eq "random")){
        return 1;
    }
    if (!($choice & 1) && ($result eq "real")){
        return 1;
    }
    return 0;
}

########################################
# Homework 6
# Problem 2
########################################

our $hw6_2GLOBAL_K;
our %hw6_2GLOBAL_T;

sub hw6_2Prp{
    my $k = shift;
    my $m = shift;
    my $x = substr(prf($k, $m), 0, length($m) / 2);
    my $y = substr(prf($k, $m), length($m) / 2, length($m) / 2);
    my $outy = prf($k, $y);
    my $v = "";
    for (my $i = 0; $i < length($m); $i++) {
        $v .= chr(ord(substr($outy, $i, 1)) ^ ord(substr($x, $i, 1)));
    }
    my $v2 = "";
    for (my $i = 0; $i < length($m); $i++) {
        $v2 .= chr(ord(substr($v, $i, 1)) ^ ord(substr($y, $i, 1)));
    }
    return $v . $v2;
}

sub hw6_2LOOKUPreal{
    my $m = shift;
    return hw6_2Prf($hw6_2GLOBAL_K, $m);
}

sub hw6_2LOOKUPrand{
    my $m = shift;
    if (exists $hw6_2GLOBAL_T{$m}){
        return $hw6_2GLOBAL_T{$m};
    }
    else{
        my $x = "";
        for (my $i = 0; $i < length($m); $i++) {
            $x .= chr(makerandom(Size => 8, Strength => 0));
        }
        $hw6_2GLOBAL_T{$m} = $x;
        return $x;
    }
}

# Chapter 6 Homework Problem 2
# Implements LOOKUP()
# Note: lambda must be an even number for this implementation to work
sub hw6_2PrpDistinguish{
    my $lambda = shift;
    my $attack = shift;
    my %scheme = ();

    my $choice = makerandom(Size => 8, Strength => 0);
    if ($choice & 1){
        $scheme{'LOOKUP'} = \&hw6_2LOOKUPrand;
    }
    else{
        $scheme{'LOOKUP'} = \&hw6_2LOOKUPreal;
    }
    $hw6_2GLOBAL_K = "";
    for (my $i = 0; $i < $lambda; $i++) {
        $hw6_2GLOBAL_K .= chr(makerandom(Size => 8, Strength => 0));
    }
    my $result = $attack->($lambda, \%scheme);
    if ((($choice & 1) == 1) && ($result eq "random")){
        return 1;
    }
    if (!($choice & 1) && ($result eq "real")){
        return 1;
    }
    return 0;
}

################################################################################
# Chapter 7
################################################################################


########################################
# Homework 7
# Problem 2
########################################

sub hw7_2CpaEnc{
    my $k = shift;
    my $m = shift;
    my $s1 = "";
    for (my $i = 0; $i < length($m); $i++) {
        $s1 .= chr(makerandom(Size => 8, Strength => 0));
    }
    my $s2 = "";
    for (my $i = 0; $i < length($m); $i++) {
        $s2 .= chr(ord(substr($s1, $i, 1)) ^ ord(substr($m, $i, 1)));
    }
    my $x = prp($k, $s1);
    my $y = prp($k, $s2);
    return $x . $y;
}

sub hw7_2EAVESDROPL{
    my $ml = shift;
    my $mr = shift;
    my $k = KeyGen(3 * length($ml) / 2);
    my $c = hw7_2CpaEnc($k, $ml);
    return $c;
}

sub hw7_2EAVESDROPR{
    my $ml = shift;
    my $mr = shift;
    my $k = KeyGen(3 * length($ml) / 2);
    my $c = hw7_2CpaEnc($k, $mr);
    return $c;
}

sub hw7_2CTXTreal{
    my $m = shift;
    my $k = KeyGen(3 * length($m) / 2);
    my $c = hw7_2CpaEnc($k, $m);
    return $c;
}

sub hw7_2CTXTrand{
    my $m = shift;
    my $c = KeyGen(length($m));
    return $c;
}

# Chapter 7 Homeowrk Problem 2
# Implements CTXT() and EAVESDROP() 
sub hw7_2CpaDistinguish{
    my $lambda = shift;
    my $attack = shift;
    my %scheme = ();

    my $choice = makerandom(Size => 8, Strength => 0);
    if ($choice & 1){
        $scheme{'EAVESDROP'} = \&hw7_2EAVESDROPL;
    }
    else{
        $scheme{'EAVESDROP'} = \&hw7_2EAVESDROPR;
    }
    if ($choice & 2){
        $scheme{'CTXT'} = \&hw7_2CTXTrand;
    }
    else{
        $scheme{'CTXT'} = \&hw7_2CTXTreal;
    }

    my $result = $attack->($lambda, \%scheme);

    if ((($choice & 1)) && ($result eq "left")){
        return 1;
    }
    if (!($choice & 1) && ($result eq "right")){
        return 1;
    }
    if ((($choice & 2)) && ($result eq "random")){
        return 1;
    }
    if (!($choice & 2) && ($result eq "real")){
        return 1;
    }
    return 0;
}
1;
