'''
The module provides a signing
'''
import hashlib
import sys
from rsa import RSA

def sha1_hash(message):
    """
    Computes SHA-1 hash of data
    """
    message_bytes = message.encode('utf-8')
    sha256_hash = hashlib.sha1(message_bytes).hexdigest()
    return sha256_hash

def sign(message, kod):
    '''
    Function signs the data
    '''
    hashed_message = sha1_hash(message)
    print(hashed_message)
    sign_ = RSA.encrypt(hashed_message, kod)
    return sign_

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Format: python sign.py filename_for_signing public_key private_key")
    elif len(sys.argv) == 4:
        print("Signing the file...")
        file_data = sys.argv[1]
        fpublic_key = sys.argv[2]
        fprivate_key = sys.argv[3]
        with open(file_data, 'r', encoding='utf-8') as doc1:
            data = doc1.read()
        with open(fpublic_key, 'r', encoding='utf-8') as file_pub:
            pub_key = tuple(int(el) for el in file_pub.read()[1:-1].split(', '))
        with open(fprivate_key, 'r', encoding='utf-8') as file_pr:
            pr_key = tuple(int(el) for el in file_pr.read()[1:-1].split(', '))
        signature = sign(data, pr_key)
        with open('signature.txt', 'w', encoding='utf-8') as wfile:
            wfile.write(str(signature))
