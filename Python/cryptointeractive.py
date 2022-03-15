from email import generator
import random
import secrets
import sys

from datetime import timezone
import datetime

# int.from_bytes(bytes, byteorder, *, signed=False)
# SIZE IS BYTES

L_SIZE = 4


class Bits:
    def __init__(self, size):
        self.size = size

    def set(self, value):
        if value == 1:
            self.bits = int.to_bytes(
                pow(2, self.size*8) - 1, self.size, sys.byteorder)
            return self

        if value == 0:
            self.bits = int.to_bytes(
                pow(1, self.size) - 1, self.size, sys.byteorder)
            return self

        self.bits = int.to_bytes(value, self.size, sys.byteorder)
        return self

    def rand(self):
        self.bits = (secrets.randbits(self.size*8)
                     ).to_bytes(self.size, sys.byteorder)

    def __str__(self):
        x = bin(int.from_bytes(self.bits, sys.byteorder, signed=False))[2:]
        while len(x) < len(self.bits)*8:
            x = '0'+x
        return x

    def __and__(self, other):
        xLen = len(self.bits)
        yLen = len(other.bits)
        if xLen != yLen:
            raise TypeError("Cannot AND variable length bits")
        self_int = int.from_bytes(self.bits, sys.byteorder, signed=False)
        other_int = int.from_bytes(other.bits, sys.byteorder, signed=False)
        result = Bits(self.size)
        result.bits = (self_int & other_int).to_bytes(xLen, sys.byteorder)
        return result

    def __or__(self, other):
        xLen = len(self.bits)
        yLen = len(other.bits)
        if xLen != yLen:
            raise TypeError("Cannot OR variable length bits")
        self_int = int.from_bytes(self.bits, sys.byteorder, signed=False)
        other_int = int.from_bytes(other.bits, sys.byteorder, signed=False)
        result = Bits(self.size)
        result.bits = (self_int | other_int).to_bytes(xLen, sys.byteorder)
        return result

    def __xor__(self, other):
        xLen = len(self.bits)
        yLen = len(other.bits)
        if xLen != yLen:
            raise TypeError("Cannot XOR variable length bits")
        self_int = int.from_bytes(self.bits, sys.byteorder, signed=False)
        other_int = int.from_bytes(other.bits, sys.byteorder, signed=False)
        result = Bits(self.size)
        result.bits = (self_int ^ other_int).to_bytes(xLen, sys.byteorder)
        return result

    def __add__(self, other):
        retBits = Bits(len(self.bits) + len(other.bits))
        retBits.bits = other.bits + self.bits
        return retBits

    def __eq__(self, other):
        if self.bits == other.bits:
            return True
        else:
            return False


class Scheme:
    def __init__(self, eavesdrop=None, ctxt=None, query=None, lookup=None, inverse=None, decrypt=None):
        self.eavesdrop = eavesdrop
        self.ctxt = ctxt
        self.query = query
        self.lookup = lookup
        self.inverse = inverse
        self.decrypt = decrypt


def randBytes(size):
    return (secrets.randbits(size)).to_bytes(size, sys.byteorder)


def keyGen(size):
    return (secrets.randbits(size*8)).to_bytes(size, sys.byteorder)


def se2_3EAVESDROPL(size, mL, mR):
    k = keyGen(len(mL))
    c = __se2_3Enc(k, mL)
    return c


def se2_3EAVESDROPR(size, mL, mR):
    k = keyGen(len(mR))
    c = __se2_3Enc(k, mR)
    return c


def se2_3OtsAttack(size, attack):
    """
    """
    scheme = Scheme()
    eavesChoice = secrets.choice([0, 1])
    ctxtChoice = secrets.choice([0, 1])

    if eavesChoice:
        scheme.eavesdrop = se2_3EAVESDROPL
    else:
        scheme.eavesdrop = se2_3EAVESDROPR

    if ctxtChoice:
        scheme.ctxt = se2_3CTXTrand
    else:
        scheme.ctxt = se2_3CTXTreal

    result = attack(size, scheme)

    if (eavesChoice and result.lower() == 'left'):
        return True

    if (not eavesChoice and result.lower() == 'right'):
        return True

    if (ctxtChoice and result.lower() == 'random'):
        return True

    if (not ctxtChoice and result.lower() == 'real'):
        return True

    return False


def __se2_3Enc(k, m):
    kLen = len(k)
    mLen = len(m)
    if kLen != mLen:
        return "AWW HELL NO"

    k_val = int.from_bytes(k, sys.byteorder, signed=False)
    m_val = int.from_bytes(m, sys.byteorder, signed=False)
    cipher = k_val & m_val
    return cipher.to_bytes(kLen, sys.byteorder)


def se2_3CTXTreal(m):
    k = keyGen(len(m))
    c = __se2_3Enc(k, m)
    return c


def se2_3CTXTrand(m):
    c = randBytes(len(m))
    return c


def otpEnc(k, m):
    return k ^ m

# Check


def se2_30tsAdvantage(trials, attack):
    advantage = 0
    for trial in trials:
        advantage += se2_3OtsAttack(attack)
    return advantage/trials


# @todo implement homework 2

########################### Homework 2 ###########################

def hw2_1KeyGen():
    k = Bits(L_SIZE)
    k.rand()
    d = Bits(L_SIZE)
    d.set(0)
    while k == d:
        k.rand()
    return k


def hw2_1EAVESDROPL(mL, mR):
    k = hw2_1KeyGen()
    c = k ^ mL
    return c


def hw2_1EAVESDROPR(mL, mR):
    k = hw2_1KeyGen()
    c = k ^ mR
    return c


def hw2_1CTXTreal(m):
    k = hw2_1KeyGen()
    c = k ^ m
    return c


def hw2_1CTXTrandom(m):
    c = Bits(L_SIZE)
    c.rand()
    return c


def hw2_1OtsAttack(size, attack):

    scheme = Scheme()
    eavesChoice = secrets.choice([0, 1])
    ctxtChoice = secrets.choice([0, 1])
    if eavesChoice:
        scheme.eavesdrop = hw2_1EAVESDROPL
    else:
        scheme.eavesdrop = hw2_1EAVESDROPR

    if ctxtChoice:
        scheme.ctxt = se2_3CTXTrand
    else:
        scheme.ctxt = se2_3CTXTreal

    result = attack(size, scheme)

    if (eavesChoice and result.lower() == 'left'):
        return True

    if (not eavesChoice and result.lower() == 'right'):
        return True

    if (ctxtChoice and result.lower() == 'random'):
        return True

    if (not ctxtChoice and result.lower() == 'real'):
        return True

    return False


# hw2_1KeyGen()


def hw2_1OtsAdvantage(trials, attack):
    advantage = 0
    for trial in trials:
        advantage += hw2_1OtsAttack(attack)
    return advantage/trials


########################### Homework 5 ###########################

# random.seed(10)
# random.random()
# print(random.randint(1, 10), random.randint(1, 10))


def hw5_1G(s):
    random.seed(int.from_bytes(s.bits, sys.byteorder, signed=False))
    # @follow-up why not use randbits here (says zach)
    x = random.randint(0, pow(2, 3 * L_SIZE*8))
    b = Bits(3 * L_SIZE)
    b.set(x)
    return b


def hw5_1aPRGReal(s):
    x = hw5_1G(s)
    b = Bits(L_SIZE)
    b.set(0)
    y = hw5_1G(b)
    return (x + y)


def hw5_1aPRGRand(s):
    x = Bits(6*L_SIZE)
    x.rand()
    return x


def hw5_1aAttack(size, attack):

    scheme = Scheme()
    ctxtChoice = secrets.choice([0, 1])
    if ctxtChoice:
        scheme.ctxt = hw5_1aPRGRand
    else:
        scheme.ctxt = hw5_1aPRGReal

    result = attack(size, scheme)

    if (ctxtChoice and result.lower() == 'random'):
        return True

    if (not ctxtChoice and result.lower() == 'real'):
        return True

    return False


def hw5_1aPrgAdvantage(trials, attack):
    advantage = 0
    for trial in trials:
        advantage += hw5_1aAttack(attack)
    return advantage/trials


def hw5_1bPRGReal(s):
    x = hw5_1G(s)
    b = Bits(L_SIZE)
    b.set(0)
    y = hw5_1G(b)
    return (x ^ y)


def hw5_1bPRGRand(s):
    x = Bits(6*L_SIZE)
    x.rand()
    return x


def hw5_1bAttack(size, attack):

    scheme = Scheme()
    ctxtChoice = secrets.choice([0, 1])
    if ctxtChoice:
        scheme.ctxt = hw5_1bPRGRand
    else:
        scheme.ctxt = hw5_1bPRGReal

    result = attack(size, scheme)

    if (ctxtChoice and result.lower() == 'random'):
        return True

    if (not ctxtChoice and result.lower() == 'real'):
        return True

    return False


def hw5_1bPrgAdvantage(trials, attack):
    advantage = 0
    for trial in trials:
        advantage += hw5_1bAttack(attack)
    return advantage/trials


def hw5_1cPRGReal(s):
    x = hw5_1G(s)
    temp = Bits(L_SIZE)
    temp.bits = x.bits[2*L_SIZE:3*L_SIZE]
    y = hw5_1G(temp)
    return (x + y)


def hw5_1cPRGRand(s):
    x = Bits(6*L_SIZE)
    x.rand()
    return x


def hw5_1cAttack(size, attack):

    scheme = Scheme()
    ctxtChoice = secrets.choice([0, 1])
    if ctxtChoice:
        scheme.ctxt = hw5_1cPRGRand
    else:
        scheme.ctxt = hw5_1cPRGReal

    result = attack(size, scheme)

    if (ctxtChoice and result.lower() == 'random'):
        return True

    if (not ctxtChoice and result.lower() == 'real'):
        return True

    return False


def hw5_1cPrgAdvantage(trials, attack):
    advantage = 0
    for trial in trials:
        advantage += hw5_1bAttack(attack)
    return advantage/trials
