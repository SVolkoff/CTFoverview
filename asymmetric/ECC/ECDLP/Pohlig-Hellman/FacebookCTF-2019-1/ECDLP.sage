from sys import argv
import hashlib
import random
import base64


def sign(message, key, n, G):
    while True:
        k = random.randint(1, n)
        Q = k * G

        hash_message = message + str(int(Q[0]))
        mhash = hashlib.sha256(hash_message)
        r = int(mhash.hexdigest(), 16)
        if r % n == 0:
            continue

        s = (k - (r * key)) % n
        if s != 0:
            return (r, s)


def verify(message, signature, n):
    r, s = signature
    if r < 0 or s < 1 or s > n - 1:
        return False
    Q = (s * G) + (r * H)
    if Q == 0:
        return False
    hash_message = message + str(int(Q[0]))
    mhash = hashlib.sha256(hash_message)
    v = int(mhash.hexdigest(), 16)
    return v == r

assert len(argv[1:]) == 8
[a, b, p, Gx, Gy, Hx, Hy] = [int(x) for x in argv[1:8]]
message_to_forge = argv[8]

E = EllipticCurve(IntegerModRing(p), [0, 0, 0, a, b])
G = E(Gx, Gy)
H = E(Hx, Hy)

key = discrete_log(H, G, operation="+")

# sanity check
assert key * G == H
n = E.order()
(r, s) = sign(message_to_forge, key, n, G)
assert verify(message_to_forge, (r, s), n)

sig = base64.b64encode((str(r) + '|' + str(s)).encode())
print(key)
print(sig)
