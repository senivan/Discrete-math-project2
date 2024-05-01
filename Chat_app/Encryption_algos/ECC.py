"""
    This module implements the Elliptic Curve Cryptography algorithm(ECIES).
    Standart used: c2pnb176w1
    Elliptic curve domain parameters over Fp is defined by the tuple:
    T = (p, a, b, G, n, h)
    where:
"secp256r1": {"p": 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
                                   "a": 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
                                   "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
                                   "g": (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                                         0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
                                   "n": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
                                   "h": 0x1},

"""
import random   
import hashlib
class Point:
        def __init__(self, x, y):
            self.x = x
            self.y = y

        def __add__(self, other):
            if self == Point(0, 0):
                return other
            if other == Point(0, 0):
                return self
            if self.x == other.x and (self.y != other.y or self.y == 0):
                return Point(0, 0)
            if self == other:
                m = (3 * self.x * self.x + ECC.CONSTANTS['a']) * pow(2 * self.y, -1, ECC.CONSTANTS['p'])
            else:
                m = (self.y - other.y) * pow(self.x - other.x, -1, ECC.CONSTANTS['p'])
            x3 = m * m - self.x - other.x
            y3 = self.y + m * (x3 - self.x)
            return Point(x3 % ECC.CONSTANTS['p'], -y3 % ECC.CONSTANTS['p'])
        def __mul__(self, other):
            n = other
            Q = Point(0, 0)
            R = self
            while n > 0:
                if n % 2 == 1:
                    Q = Q + R
                R = R + R
                n = n // 2
            return Q
        def double(self):
            return self + self
        def __str__(self):
            return f"({hex(self.x)}, {hex(self.y)})"
        def __eq__(self, other):
            return self.x == other.x and self.y == other.y
        def __rmul__(self, other):
            return self.__mul__(other)
        
class ECC:
    CONSTANTS = {"p": 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
                                   "a": 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
                                   "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
                                   "g": Point(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                                         0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
                                   "n": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
                                   "h": 0x1}
    @staticmethod
    def generate_keys():
        d = random.randint(1, ECC.CONSTANTS['n'] - 1)
        Q = ECC.CONSTANTS['g'] * d
        return d, Q
    
    @staticmethod
    def derive_key_function(my_private_key, other_public_key):
        shared_secret = ECC.compute_shared_secret(my_private_key, other_public_key)
        ky = str(shared_secret.x).encode()
        return hashlib.sha256(ky).hexdigest()
    
    @staticmethod
    def compute_shared_secret(my_private_key, other_public_key):
        return my_private_key * other_public_key

# Implementing the ECIES algorithm
# We use the ECC class to generate the keys
# than if we want to exchange the keys we use the ECC class to generate the shared secret

    
def encrypt_message(message, symetric_key):
    pass

def decrypt_message(message, private_key):
    pass


if __name__ == '__main__':
    my_d, my_Q = ECC.generate_keys()
    print(my_d, my_Q)
    other_d, other_Q = ECC.generate_keys()
    print(other_d, other_Q)
    my_shared_secret = ECC.compute_shared_secret(my_d, other_Q)
    print(my_shared_secret)
    other_shared_secret = ECC.compute_shared_secret(other_d, my_Q)
    print(other_shared_secret)

    assert my_shared_secret == other_shared_secret
    symmetrical_key = ECC.derive_key_function(my_d, other_Q)
    print(symmetrical_key)
    other_symmetrical_key = ECC.derive_key_function(other_d, my_Q)
    print(other_symmetrical_key)
    print(len(other_symmetrical_key))
    print(len(symmetrical_key))
    assert symmetrical_key == other_symmetrical_key
    print("Test passed")

    