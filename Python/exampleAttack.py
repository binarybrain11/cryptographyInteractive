from cryptointeractive import *
import sys


def exampleAttack(size, scheme):
    m = 0
    c = scheme.ctxt(m.to_bytes(1, sys.byteorder))
    if(m == int.from_bytes(c, sys.byteorder)):
        return "real"
    else:
        return "random"


print(se2_3OtsAttack(1, exampleAttack))
