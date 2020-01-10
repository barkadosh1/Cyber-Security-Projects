import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
import base64
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def format_plaintext(is_admin, password):
    tmp = bytearray(str.encode(password))
    return bytes(bytearray((is_admin).to_bytes(1,"big")) + tmp)

def is_admin_cookie(decrypted_cookie):
    return decrypted_cookie[0] == 1

class Encryption(object):
    def __init__(self, in_key=None):
        self._backend = default_backend()
        self._block_size_bytes = int(ciphers.algorithms.AES.block_size/8)

        if in_key is None:
            self._key = os.urandom(self._block_size_bytes)
        else:
            self._key = in_key

    def encrypt(self, msg):
        # initialize the key and nonce. encrypt the message using these values
        key = AESGCM.generate_key(bit_length = 128)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        _ciphertext = aesgcm.encrypt(nonce, msg, None)

        # append the nonce and key to the encrypted message so that we can
        # seperate the values in the decrypt method, as we will need access to
        # the same key and nonce
        _ciphertext = _ciphertext + nonce + key
        return _ciphertext


    # when running maul and padding oracle attack with this decrypt method, the
    # attacks no longer work, as they both alter the cyphertext/encrypted
    # message. As is stated in the cryptography.io documentation, the decrypt
    # method will throw an InvalidTag error if the cyphertext is altered, which
    # is exactly what happens
    def decrypt(self, ctx):
        # using the ctx input, we parse the key out by taking the last 16 bytes
        # we know this is the length of the key because we defined it
        key = ctx[-16:]
        aesgcm = AESGCM(key)

        # similarly, we extract the 12 bytes before the key to get the nonce
        nonce = ctx[-28:-16]

        # we extract the remaining bytes of the ctx input to isolate the
        # encrypted meessage
        ctx_msg = ctx[:-28]

        # decrypt the extracted message using our same key and nonce
        msg = aesgcm.decrypt(nonce, ctx_msg, None)
        return msg

 
if __name__=='__main__':
    test_encr_decr()
