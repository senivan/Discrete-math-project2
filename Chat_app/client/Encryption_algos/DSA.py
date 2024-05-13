import hashlib
from Encryption_algos import RSA
class DSA:
    # def __init__(self, private_key, public_key):
    #     self.private_key = private_key
    #     self.public_key = public_key
    @staticmethod
    def sign(message, private_key):
        '''
        Function signs the data
        '''
        hashed_message = hashlib.sha256(message.encode('utf-8')).hexdigest()
        sign_ = RSA.encrypt(hashed_message, private_key).decode()
        return sign_
    @staticmethod
    def verify(message, signature, public_key):
        '''
        The function verifies whether the signature is correct.
        '''
        hashed_message = hashlib.sha256(message.encode('utf-8')).hexdigest()
        decrypted_signature = RSA.decrypt(signature, public_key)
        return hashed_message == decrypted_signature


if __name__ == "__main__":
    pub, priv = RSA.generateRSAkeys()
    message = "Hello world"
    signature = DSA.sign(message, priv)
    print(DSA.verify(message, signature, pub))
    # print(DSA.verify(message, signature, priv))
    print(DSA.verify("Hello world", signature, pub))
    # print(DSA.verify("Hello world", signature, priv))