import hashlib
from Encryption_algos import RSA

class DSA:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

    def sign(self, message):
        '''
        Function signs the data
        '''
        hashed_message = hashlib.sha256(message.encode('utf-8')).hexdigest()
        sign_ = RSA.encrypt(hashed_message, self.private_key)
        return sign_

    def verify(self, message, signature):
        '''
        The function verifies whether the signature is correct.
        '''
        hashed_message = hashlib.sha256(message.encode('utf-8')).hexdigest()
        decrypted_signature = RSA.decrypt(signature, self.public_key)
        return hashed_message == decrypted_signature

