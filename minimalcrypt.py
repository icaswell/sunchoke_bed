# minimalcrypt.py
# @author: Isaac Caswell, though mainly copypasta from simplecrypt
# @date: 3/3/2017
# 
# This is specifically intended for encrypting one-use messages. Do not use it for passwords, etc.
#
# Notes:
# -data can be corrupted and only certain segments will be lost. No warning is given for corrupted data.
# -no nonce is used: be careful of replay attacks (or include a date in your message!)
# -no salt: This module is not used for storing passwords. If you want to store passwords (or do
#  something else that is vulnerable to a rainbow table attack), plese do not use this module.

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random.random import getrandbits


SALT = '-'*256 # essentially unused, but required by the algorithm.
# EXPANSION_COUNT:number of hashes for key expansion. Larger the number, more time ti takes to encrypt/decrypt.
# Increase this number to make brute-force attacks harder to carry out on you.
EXPANSION_COUNT = 10 
AES_KEY_LEN = 256
HASH = SHA256

if EXPANSION_COUNT < 10*1000:
    print "WARNING: you are using an EXPANSION_COUNT of %s, meaning that this message is susceptible"%EXPANSION_COUNT + \
    " to brute-force attacks. If you fear such an attack, please open minimalcrypt.py and increase it.\n"


#===============================================================================
# PUBLIC

def encrypt(password, data):
    """
    Encrypt some data.  Input can be bytes or a string (which will be encoded
    using UTF-8).

    @param password: The secret value used as the basis for a key.
    This should be as long as varied as possible.  Try to avoid common words.

    @param data: The data to be encrypted.

    @return: The encrypted data, as bytes.
    """
    data = _str_to_bytes(data)
    cipher_key = _stretch_key(password, SALT, EXPANSION_COUNT)
    cipher = AES.new(cipher_key)
    encrypted = cipher.encrypt(data)
    # TODO  why is this a string??? I guess it's a byte string?
    # print "type(encrypted)",  type(encrypted)
    return encrypted


def decrypt(password, data):
    """
    Decrypt some data.  Input must be bytes.

    @param password: The secret value used as the basis for a key.
    This should be as long as varied as possible.  Try to avoid common words.

    @param data: The data to be decrypted, typically as bytes.

    @return: The decrypted data, as bytes.  If the original message was a
    string you can re-create that using `result.decode('utf8')`.
    """
    _assert_not_unicode(data)
    cipher_key = _stretch_key(password, SALT, EXPANSION_COUNT)
    cipher = AES.new(cipher_key)
    return cipher.decrypt(data)


def random_bytes(n):
	# appelbaum recommends obscuring output from random number generators since it can reveal state.
    # we can do this explicitly with a hash, but this is what a PBKDF does anyway, so use one.
    # we don't care about the salt or work factor because there is a large space of values anyway.
    unhashed_bytes = bytearray(getrandbits(8) for _ in range(n))
    hashed_bytes = bytearray(_pbkdf2(bytes(unhashed_bytes), b'', len(unhashed_bytes), 1))
    return hashed_bytes



#===============================================================================
# PRIVATE

def _pbkdf2(password, salt, n_bytes, count):
    # the form of the prf below is taken from the code for PBKDF2
    return PBKDF2(password, salt, dkLen=n_bytes,
                  count=count, prf=lambda p,s: HMAC.new(p,s,HASH).digest())

def _str_to_bytes(data):
    u_type = type(b''.decode('utf8'))
    if isinstance(data, u_type):
        return data.encode('utf8')
    return data

def _stretch_key(password, salt, expansion_count):
    key_len = AES_KEY_LEN // 8 #TODO: don't understand why it's divided by 8
    key = _pbkdf2(_str_to_bytes(password), salt, key_len, expansion_count)
    return key

def _assert_not_unicode(data):
    # warn confused users
    u_type = type(b''.decode('utf8'))
    if isinstance(data, u_type):
        raise DecryptionException('Data to decrypt must be bytes; ' +
        'you cannot use a string because no string encoding will accept all possible characters.')

