'''
Module has a function to verify a signature.
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

def verify(message, signature, kod):
    '''
    The function verifies whether the signature is correct.
    '''
    hashed_message = sha1_hash(message)
    decrypted_signature = RSA.decrypt(signature, kod)
    return hashed_message == decrypted_signature

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Format: python sign.py filename_to_verify signature public_key")
    elif len(sys.argv) == 4:
        print("Verifying the file...")
        file_data = sys.argv[1]
        fsignature = sys.argv[2]
        fpublic_key = sys.argv[3]
        with open(file_data, 'r', encoding='utf-8') as doc1:
            data = doc1.read()
        with open(fsignature, 'r', encoding='utf-8') as signadoc:
            signature_ = [int(el) for el in signadoc.read()[1:-1].split(', ')]
        with open(fpublic_key, 'r', encoding='utf-8') as file_pub:
            pub_key = tuple(int(el) for el in file_pub.read()[1:-1].split(', '))
        if verify(data, signature_, pub_key) is True:
            print('Valid signature')
        else:
            print('Invalid signature')
