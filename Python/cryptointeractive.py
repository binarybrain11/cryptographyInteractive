import random
import secrets
import sys
from datetime import timezone

L_SIZE = 4
__KEY = None
__T = {}

########################### Primitives ###########################


class Bytes:

    '''
    Creates an object to represent binary.

            Parameters:
                    size (int): Sets the size in bytes

            Returns:
                    object (Bytes): Bits object to represent binary
    '''

    def __init__(self, size):
        self.size = size

    def set(self, value):
        '''
        Set the bits value.

            0 - sets all bits to 0

            1 - sets all bits to 1

            Any other int - sets bits to int
        '''
        if value == 1:
            self.bits = int.to_bytes(
                pow(2, self.size*8) - 1, self.size, "big")
            return self

        if value == 0:
            self.bits = int.to_bytes(
                pow(1, self.size) - 1, self.size, "big")
            return self

        self.bits = int.to_bytes(value, self.size, "big")
        return self

    def rand(self):
        '''
            Randomizes bits
        '''
        self.bits = (secrets.randbits(self.size*8)
                     ).to_bytes(self.size, "big")

    def __str__(self):
        x = bin(int.from_bytes(self.bits, "big", signed=False))[2:]
        while len(x) < len(self.bits)*8:
            x = '0'+x
        return x

    def __and__(self, other):
        xLen = len(self.bits)
        yLen = len(other.bits)
        if xLen != yLen:
            raise TypeError("Cannot AND variable length bits")
        self_int = int.from_bytes(self.bits, "big", signed=False)
        other_int = int.from_bytes(other.bits, "big", signed=False)
        result = Bytes(self.size)
        result.bits = (self_int & other_int).to_bytes(xLen, "big")
        return result

    def __or__(self, other):
        xLen = len(self.bits)
        yLen = len(other.bits)
        if xLen != yLen:
            raise TypeError("Cannot OR variable length bits")
        self_int = int.from_bytes(self.bits, "big", signed=False)
        other_int = int.from_bytes(other.bits, "big", signed=False)
        result = Bytes(self.size)
        result.bits = (self_int | other_int).to_bytes(xLen, "big")
        return result

    def __xor__(self, other):
        xLen = len(self.bits)
        yLen = len(other.bits)
        if xLen != yLen:
            raise TypeError("Cannot XOR variable length bits")
        self_int = int.from_bytes(self.bits, "big", signed=False)
        other_int = int.from_bytes(other.bits, "big", signed=False)
        result = Bytes(self.size)
        result.bits = (self_int ^ other_int).to_bytes(xLen, "big")
        return result

    def __add__(self, other):
        retBits = Bytes(len(self.bits) + len(other.bits))
        retBits.bits = self.bits + other.bits
        return retBits

    def __eq__(self, other):
        if self.bits == other.bits:
            return True
        else:
            return False

    def __len__(self):
        return len(self.bits)


class Scheme:
    def __init__(self, eavesdrop=None, ctxt=None, query=None, lookup=None, inverse=None, decrypt=None):
        self.eavesdrop = eavesdrop
        self.ctxt = ctxt
        self.query = query
        self.lookup = lookup
        self.inverse = inverse
        self.decrypt = decrypt


def randBytes(size):
    return (secrets.randbits(size)).to_bytes(size, "big")


def keyGen(size):
    return (secrets.randbits(size*8)).to_bytes(size, "big")


def prf(k, m):
    v = Bytes(len(k))
    v.bits = k.bits
    output = Bytes(2 * len(k))
    for bit in str(m):
        if bit == '0':
            output = prgDouble(v)
            v.bits = output.bits[0:(len(output)//2)]
        else:
            output = prgDouble(v)
            v.bits = output.bits[(len(output)//2):len(output)]
    return v


def prgDouble(s):
    random.seed(int.from_bytes(s.bits, "big", signed=False))
    x = random.randint(0, pow(2, 2 * len(s)*8))
    y = Bytes(2*len(s))
    y.set(x)
    return y


def prp(k, v):
    v0 = Bytes(len(v)/2)
    v1 = Bytes(len(v)/2)
    v0.bits = v.bits[0:(len(v)//2)]
    v1.bits = v.bits[(len(v)//2): len(v)]
    out = prf(k[0], v1)
    v2 = out ^ v0
    out2 = prf(k[1], v2)
    v3 = out2 ^ v1
    out3 = prf(k[2], v3)
    v4 = out3 ^ v2
    return v3+v4


def advantage(trials, attack, distinguisher):
    advantage = 0
    for i in range(0, trials):
        advantage += distinguisher(L_SIZE, attack)
    return advantage/trials

########################### Chapter 2 ###########################


def se2_3EAVESDROPL(size, mL, mR):
    k = keyGen(len(mL))
    c = __se2_3Enc(k, mL)
    return c


def se2_3EAVESDROPR(size, mL, mR):
    k = keyGen(len(mR))
    c = __se2_3Enc(k, mR)
    return c


def se2_3OtsDistinguish(size, attack):
    """
    Chapter 2 section 3 example - Implements CTXT() and EAVESDROP()
    """
    scheme = Scheme()
    eavesChoice = secrets.choice([0, 1])
    ctxtChoice = secrets.choice([0, 1])

    if eavesChoice:
        scheme.eavesdrop = se2_3EAVESDROPL
    else:
        scheme.eavesdrop = se2_3EAVESDROPR

    if ctxtChoice:
        scheme.ctxt = __se2_3CTXTrand
    else:
        scheme.ctxt = __se2_3CTXTreal

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
    c = k & m
    return c


def __se2_3CTXTreal(m):
    k = Bytes(len(m))
    k.bits = keyGen(len(m))
    c = __se2_3Enc(k, m)
    return c


def __se2_3CTXTrand(m):
    c = Bytes(len(m))
    c.rand()
    return c


def otpEnc(k, m):
    return k ^ m


def se2_30tsAdvantage(trials, attack):
    advantage = 0
    for i in range(0, trials):
        advantage += se2_3OtsDistinguish(2, attack)
    return advantage/trials


def __hw2_1KeyGen():
    k = Bytes(L_SIZE)
    k.rand()
    d = Bytes(L_SIZE)
    d.set(0)
    while k == d:
        k.rand()
    return k


def __hw2_1EAVESDROPL(mL, mR):
    k = __hw2_1KeyGen()
    c = k ^ mL
    return c


def __hw2_1EAVESDROPR(mL, mR):
    k = __hw2_1KeyGen()
    c = k ^ mR
    return c


def __hw2_1CTXTreal(m):
    k = __hw2_1KeyGen()
    c = k ^ m
    return c


def __hw2_1CTXTrandom(m):
    c = Bytes(L_SIZE)
    c.rand()
    return c


def hw2_1OtsDistinguish(size, attack):
    '''
        Chapter 2 Homework Problem 1 - Implements CTXT() and EAVESDROP()
    '''
    scheme = Scheme()
    eavesChoice = secrets.choice([0, 1])
    ctxtChoice = secrets.choice([0, 1])
    if eavesChoice:
        scheme.eavesdrop = __hw2_1EAVESDROPL
    else:
        scheme.eavesdrop = __hw2_1EAVESDROPR

    if ctxtChoice:
        scheme.ctxt = __hw2_1CTXTrandom
    else:
        scheme.ctxt = __hw2_1CTXTreal

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
    for i in range(0, trials):
        advantage += hw2_1OtsDistinguish(L_SIZE, attack)
    return advantage/trials


########################### Chapter 5 ###########################

# random.seed(10)
# random.random()
# print(random.randint(1, 10), random.randint(1, 10))


def hw5_1G(s):
    '''
    Chapter 5 Homework Problem 1
        *secure* length tripling PRG. Not actually secure, but treat it as such.

        Parameters:
            s - seed with at least lambda bytes

        Returns: Bytes(3 L_SIZE)
    '''
    random.seed(int.from_bytes(s.bits, "big", signed=False))
    x = random.randint(0, pow(2, 3 * L_SIZE*8))
    b = Bytes(3 * L_SIZE)
    b.set(x)
    return b


def __hw5_1aPRGReal():
    s = Bytes(L_SIZE)
    s.rand()
    x = hw5_1G(s)
    b = Bytes(L_SIZE)
    b.set(0)
    y = hw5_1G(b)
    return (x + y)


def __hw5_1aPRGRand():
    x = Bytes(6*L_SIZE)
    x.rand()
    return x


def hw5_1aPrgDistinguish(size, attack):
    '''
        Chapter 5 Homework Problem 1a - Implements QUERY()
    '''
    scheme = Scheme()
    ctxtChoice = secrets.choice([0, 1])
    if ctxtChoice:
        scheme.query = __hw5_1aPRGRand
    else:
        scheme.query = __hw5_1aPRGReal

    result = attack(size, scheme)

    if (ctxtChoice and result.lower() == 'random'):
        return True

    if (not ctxtChoice and result.lower() == 'real'):
        return True

    return False


def hw5_1aPrgAdvantage(trials, attack):
    advantage = 0
    for i in range(0, trials):
        advantage += hw5_1aPrgDistinguish(L_SIZE, attack)
    return advantage/trials


def __hw5_1bPRGReal():
    s = Bytes(L_SIZE)
    s.rand()
    x = hw5_1G(s)
    b = Bytes(L_SIZE)
    b.set(0)
    y = hw5_1G(b)
    return (x ^ y)


def __hw5_1bPRGRand():
    x = Bytes(6*L_SIZE)
    x.rand()
    return x


def hw5_1bPrgDistinguish(size, attack):
    '''
        Chapter 5 Homework Problem 1b - Implements QUERY()
    '''
    scheme = Scheme()
    ctxtChoice = secrets.choice([0, 1])
    if ctxtChoice:
        scheme.query = __hw5_1bPRGRand
    else:
        scheme.query = __hw5_1bPRGReal

    result = attack(size, scheme)

    if (ctxtChoice and result.lower() == 'random'):
        return True

    if (not ctxtChoice and result.lower() == 'real'):
        return True

    return False


def hw5_1bPrgAdvantage(trials, attack):
    advantage = 0
    for i in range(0, trials):
        advantage += hw5_1aPrgDistinguish(L_SIZE, attack)
    return advantage/trials


def __hw5_1cPRGReal():
    s = Bytes(L_SIZE)
    s.rand()
    x = hw5_1G(s)
    temp = Bytes(L_SIZE)
    temp.bits = x.bits[0:L_SIZE]
    y = hw5_1G(temp)
    return (x + y)


def __hw5_1cPRGRand():
    x = Bytes(6*L_SIZE)
    x.rand()
    return x


def hw5_1cPrgDistinguish(size, attack):
    '''
        Chapter 5 Homework Problem 1c - Implements QUERY()
    '''
    scheme = Scheme()
    ctxtChoice = secrets.choice([0, 1])
    if ctxtChoice:
        scheme.query = __hw5_1cPRGRand
    else:
        scheme.query = __hw5_1cPRGReal

    result = attack(size, scheme)

    if (ctxtChoice and result.lower() == 'random'):
        return True

    if (not ctxtChoice and result.lower() == 'real'):
        return True

    return False


def hw5_1cPrgAdvantage(trials, attack):
    advantage = 0
    for i in range(0, trials):
        advantage += hw5_1bPrgDistinguish(L_SIZE, attack)
    return advantage/trials


########################### Chapter 6 ###########################

def __hw6_1Prf(k, m):
    return prf(k, m) + prf(k, prf(k, m))


def __hw6_1LOOKUPreal(x):
    return __hw6_1Prf(__KEY, x)


def __hw6_1LOOKUPrand(x):
    if __T.get(x) == None:
        bits = Bytes(L_SIZE)
        bits.rand()
        __T[x] = bits
    return __T[x]


def hw6_1PrfDistinguish(size, attack):
    '''
        Chapter 6 Homework Problem 1 - Implements LOOKUP()
    '''
    scheme = Scheme()
    ctxtChoice = secrets.choice([0, 1])
    if ctxtChoice:
        scheme.lookup = __hw6_1LOOKUPrand
    else:
        scheme.lookup = __hw6_1LOOKUPreal

    k = Bytes(L_SIZE)
    k.rand()
    __KEY = k
    result = attack(size, scheme)
    __T = {}
    if (ctxtChoice and result.lower() == 'random'):
        return True

    if (not ctxtChoice and result.lower() == 'real'):
        return True

    return False


def hw6_1PrfAdvantage(trials, attack):
    advantage = 0
    for i in range(0, trials):
        advantage += hw6_1PrfDistinguish(L_SIZE, attack)
    return advantage/trials


def __hw6_2Prp(k, v):
    v0 = Bytes(len(v)/2)
    v1 = Bytes(len(v)/2)
    v0.bits = v.bits[0:(len(v)//2)]
    v1.bits = v.bits[(len(v)//2): len(v)]
    out = prf(k[0], v1)
    v2 = out ^ v0
    out2 = prf(k[1], v2)
    v3 = out2 ^ v1
    return v2+v3


def __hw6_2LOOKUPreal(x):
    return __hw6_2Prp(__KEY, x)


def __hw6_2LOOKUPrand(x):
    if __T.get(x) == None:
        bits = Bytes(L_SIZE)
        bits.rand()
        __T[x] = bits
    return __T[x]


def hw6_2PrpDistinguish(size, attack):
    """
    Chapter 6 Homework Problem 2 - Implements LOOKUP()
        * Lamdbda must be an even value
    """
    scheme = Scheme()
    ctxtChoice = secrets.choice([0, 1])
    if ctxtChoice:
        scheme.lookup = __hw6_2LOOKUPrand
    else:
        scheme.lookup = __hw6_2LOOKUPreal

    k = Bytes(L_SIZE)
    k.rand()
    __KEY = k
    result = attack(size, scheme)
    __T = {}
    if (ctxtChoice and result.lower() == 'random'):
        return True

    if (not ctxtChoice and result.lower() == 'real'):
        return True

    return False

########################### Chapter 7 ###########################


def __hw7_2cpaEnc(k, m):
    s1 = Bytes(L_SIZE)
    s1.rand()
    s2 = s1 ^ m
    x = prp(k, s1)
    y = prp(k, s2)
    return x+y


def __hw7_2EAVESDROPL(mL, mR):
    key = keyGen(3*L_SIZE)
    k = Bytes(3*L_SIZE)
    k.bits = key
    return __hw7_2cpaEnc(k, mL)


def __hw7_2EAVESDROPR(mL, mR):
    key = keyGen(3*L_SIZE)
    k = Bytes(3*L_SIZE)
    k.bits = key
    return __hw7_2cpaEnc(k, mR)


def __hw7_2CTXTreal(m):
    key = keyGen(3*L_SIZE)
    k = Bytes(3*L_SIZE)
    k.bits = key
    return __hw7_2cpaEnc(k, m)


def __hw7_2CTXTrand(m):
    key = keyGen(len(m))
    c = Bytes(len(m))
    c.bits = key
    return c


def hw7_2CpaDistinguish(size, attack):
    """
    Chapter 7 Homeowrk Problem 2
        Implements CTXT() and EAVESDROP()
        The output (x,y) is concatenated with x as the most significant bits
        * Lamdbda must be an even value
    """
    scheme = Scheme()
    eavesChoice = secrets.choice([0, 1])
    ctxtChoice = secrets.choice([0, 1])

    if eavesChoice:
        scheme.eavesdrop = __hw7_2EAVESDROPL
    else:
        scheme.eavesdrop = __hw7_2EAVESDROPR

    if ctxtChoice:
        scheme.ctxt = __hw7_2CTXTrand
    else:
        scheme.ctxt = __hw7_2CTXTreal

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


def hw7_2PrfAdvantage(trials, attack):
    advantage = 0
    for i in range(0, trials):
        advantage += hw6_1PrfDistinguish(L_SIZE, attack)
    return advantage/trials
