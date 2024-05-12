from Encryption_algos.RSA import KeyGen
import json
def find_prime(bits):
    prime = 0
    counter = 0
    while prime % 4 != 3:
        prime = KeyGen.get_big_prime(bits)
        counter += 1
    # print(f"Number of retries to get big prime number: {counter}")
    return prime

def encrypt(m, public_key):
    # c = m^2 mod n
    public_key = int(public_key)
    int_message = int.from_bytes(m.encode('utf-8'), "big")
    temp = bin(int_message)
    temp += temp[2:7]
    temp = int(temp, 2)
    temp =  temp ** 2 % public_key
    return str(temp)


def decrypt(a, private_key):
    a = int(a)
    p, q = private_key['p'], private_key['q']
    p = int(p)
    q = int(q)
    n = p * q
    r, s = 0, 0
    # find sqrt
    def _3_mod_4(a, p):
        r = pow(a, (p + 1) // 4, p)
        return r

    def _5_mod_8(a, p):
        d = pow(a, (p - 1) // 4, p)
        r =0
        if d == 1:
            r = pow(a, (p + 3) // 8, p)
        elif d == p - 1:
            r = 2 * a * pow(4 * a, (p - 5) // 8, p) % p

        return r
    # for p
    if p % 4 == 3:
        r = _3_mod_4(a, p)
    elif p % 8 == 5:
        r = _5_mod_8(a, p)
    # for q
    if q % 4 == 3:
        s = _3_mod_4(a, q)
    elif q % 8 == 5:
        s = _5_mod_8(a, q)

    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            gcd, y, x = egcd(b % a, a)
            return gcd, x - (b // a) * y, y
    gcd, c, d = egcd(p, q)
    x = (r * d * q + s * c * p) % n
    y = (r * d * q - s * c * p) % n
    lst = [x, n - x, y, n - y]

    for mes in lst:
        temp = bin(mes)
        if temp[2:7] == temp[-5:]:
            result = int(temp[:-5], 2)
            return result.to_bytes((result.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
    
def gen_keys(bits):
    p = find_prime(bits)
    q = find_prime(bits)
    n = p * q
    return (p, q), n

if __name__ == "__main__":
    private_key, public_key = gen_keys(256)
    private_key = {'p': private_key[0], 'q': private_key[1]}
    print(private_key, public_key)
    message = json.dumps({"username":"Ivan", "password":"1234", "register":"False"})
    encrypted = encrypt(message, public_key)
    print(encrypted)
    decrypted = decrypt(encrypted, private_key)
    print(decrypted)
    print(json.loads(decrypted))
    assert message == decrypted
