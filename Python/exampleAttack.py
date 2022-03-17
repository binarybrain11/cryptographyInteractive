from cryptointeractive import *


def exampleAttack(size, scheme):
    m = Bytes(size)
    m.set(0)
    c = scheme.ctxt(m)
    if(m == c):
        return "real"
    else:
        return "random"

def A(size, scheme):
    xyzw = scheme.query()
    w = Bytes(3 * size)
    w.bits = xyzw.bits[3 * size:]
    x = Bytes(size)
    x.bits = xyzw.bits[:size]
    c = hw5_1G(x)
    print ("xyzw: ", xyzw)
    print ("w = ", w)
    print ("x = ", x)
    if w == c:
        print("real")
        return "real"
    else:
        return "random"


x = Bytes(2)
y = Bytes(2)
x.set(1)
y.set(0)
z = Bytes(2)
z = x + y
b = Bytes(2)
b.bits = x.bits[1:]
z.bits = z.bits[1:]
print(z)
#print(se2_3OtsDistinguish(1, exampleAttack))

print(advantage(1000, A, hw5_1cPrgDistinguish))
