'''
The module has an RSA function for generating keys and encryption-decryption
'''

import random
import math

class RSA:
    '''
    class generates a public and private keys
    '''
    @staticmethod
    def __is_prime(n):
        if n <= 1:
            return False
        if n == 2:
            return True
        if n % 2 == 0:
            return False

        i = 3
        while i <= math.sqrt(n):
            if n % i == 0:
                return False
            i += 2
        return True

    def __generate_prime(self):
        '''
        generate prime numbers
        '''
        num = 0
        a = 576
        b = 2048
        while self.__is_prime(num) is False:
            num = random.randint(a, b)
        return num

    @staticmethod
    def __gcd(x, y):
        while y:
            x, y = y, x % y
        return x

    def key_gen(self):
        '''
        generates keys
        '''
        q = self.__generate_prime()
        p = self.__generate_prime()
        n = q * p

        phi = (p - 1) * (q - 1)
        e = random.randint(1, phi)
        g = self.__gcd(e, phi)

        while g != 1:
            e = random.randint(1, phi)
            g = self.__gcd(e, phi)

        d = pow(e, -1, phi)
        return (e, n), (d, n)

    @staticmethod
    def encrypt(message, primary_key):
        '''
        encryptes the message using public key
        '''
        key = primary_key[0]
        n = primary_key[1]
        res = []
        for char in message:
            res.append(pow(ord(char), key, n))
        return res

    @staticmethod
    def decrypt(ciphertext, primary_key):
        '''
        Function decryptes the message using private key
        '''
        key = primary_key[0]
        n = primary_key[1]
        char_list = []

        for char in ciphertext:
            decrypted_char = pow(char, key, n)
            char = chr(decrypted_char)
            char_list.append(char)
        decrypted_text = ''.join(char_list)
        return decrypted_text

    @staticmethod
    def in_file(public_key, private_key):
        '''
        Writes the keys into files in str format
        '''
        file1 = open('private_key.txt', 'w', encoding='utf-8')
        file1.write(str(private_key))
        file1.close()

        file2 = open("public_key.txt","w", encoding= "utf-8")
        file2.write(str(public_key))
        file2.close()
        print("Public key stored at public_key.txt and private key stored at private_key.txt")

if __name__ == '__main__':
    public, private = RSA().key_gen()
    RSA().in_file(public, private)
