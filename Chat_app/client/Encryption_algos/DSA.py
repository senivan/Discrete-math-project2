import hashlib
from Encryption_algos import RSA

def sh_hash(message):
    """
    Computes SHA-256 hash of data
    """
    message_bytes = message.encode('utf-8')
    sha256_hash = hashlib.sha256(message_bytes).hexdigest()
    return sha256_hash

def sign(message, pri_key):
    '''
    Function signs the data
    '''
    hashed_message = sh_hash(message)
    sign_ = RSA.encrypt(hashed_message, pri_key)
    return sign_

def verify(message, signature, kod):
    '''
    The function verifies whether the signature is correct.
    '''
    hashed_message = sh_hash(message)
    decrypted_signature = RSA.decrypt(signature, kod)
    return hashed_message == decrypted_signature