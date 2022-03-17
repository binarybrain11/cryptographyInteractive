from cryptointeractive import *


def exampleAttack(size, scheme):
    m = Bits(size)
    m.set(0)
    c = scheme.ctxt(m)
    if(m == c):
        return "real"
    else:
        return "random"


print(se2_3OtsDistinguish(1, exampleAttack))

print(se2_30tsAdvantage(1000, exampleAttack))
