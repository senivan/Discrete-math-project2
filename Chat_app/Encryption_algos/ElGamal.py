"""
This file contains the implementation of the ElGamal encryption algorithm.
"""
import random

def gcd(a, b):
    """GCD of two numbers."""
    while b != 0:
        a, b = b, a % b
    return a

CYC_GROUP = 2**256 - 189

def generate_keys():
    """
    This function generates the public and private keys for the ElGamal encryption algorithm.
    """
    # Private key
    a = random.randint(1, CYC_GROUP - 1)
    if gcd(a, CYC_GROUP - 1) != 1:
        return generate_keys()
    # Public key
    q = random.randint(1, CYC_GROUP - 1)
    g = 2
    h = pow(g, a, CYC_GROUP)
    return a, (q, h, g)

def encrypt(public_key, message):
    """
    This function encrypts the message using the public key.
    """
    encrypted = []
    for _, val in enumerate(message):
        encrypted.append(ord(val))
    q, h, g = public_key
    k = random.randint(1, CYC_GROUP - 1)
    if gcd(k, q) != 1:
        return encrypt(public_key, message)
    p = pow(g, k, CYC_GROUP)
    s = pow(h, k, CYC_GROUP)
    return p, [encrypted[i] * s for i in range(0, len(encrypted))]

def decrypt(private_key, p, ms):
    """
    This function decrypts the message using the private key.
    """
    a = private_key
    s = pow(p, a, CYC_GROUP)
    return "".join([chr(int(ms[i] / s)) for i in range(0, len(ms))])

# keys = generate_keys()
# c1, c2 = encrypt(keys[1], 'Hello, world!')
# print(decrypt(keys[0], c1, c2))
