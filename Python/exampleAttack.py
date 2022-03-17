from cryptointeractive import *


def exampleAttack(size, scheme):
    m = Bytes(size)
    m.set(0)
    c = scheme.ctxt(m)
    if(m == c):
        return "real"
    else:
        return "random"

print(advantage(1000, exampleAttack, se2_3OtsDistinguish))
