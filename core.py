# core.py
#
# @author: Isaac Caswell
# @date: 3/3/2017
# 
# Core functionality for fragmenting, encrypting and interleaving messages.
# This is specifically intended for encrypting one-use messages. Do not use it for passwords, etc.
#
# Notes:
# -data can be corrupted and only certain segments will be lost. No warning is given for corrupted data.
# -no nonce is used: be careful of replay attacks (or include a date in your message!)
# -no salt: This module is not used for storing passwords. If you want to store passwords (or do
#  something else that is vulnerable to a rainbow table attack), plese do not use this module.


from Crypto.Random import random

from minimalcrypt import encrypt, decrypt, random_bytes
from fragment import prep_and_fragment_messages, interleave_messages
from defragment import defragment

def encrypt_fragmented_messages(keys_and_messages):
    for key, fragmented_message in keys_and_messages.iteritems():
        encrypted_comma_fragmented_message = []
        for i, frag in enumerate(fragmented_message):
            encrypted_comma_fragmented_message = encrypt(key, frag)
            keys_and_messages[key][i] = encrypted_comma_fragmented_message


def encrypt_all_messages(keys_and_messages, size_constraint=None):
    """
    keys_and_messages: a dict of {key:message}
        -design note: using a dict prevents duplicate keys
    size constraint: as of yet unused
    """
    if size_constraint is not None and size_constraint%16 != 0:
        raise ValueError("size_constraint must be a multiple of 16 (got %s)"%size_constraint)

    # converts from unicode, pads to the correct length, randomly fragments messages
    prep_and_fragment_messages(keys_and_messages)

    # encrypt messages
    encrypt_fragmented_messages(keys_and_messages)

    # combine encrypted messages into one incomprehensible string
    cyphertext = interleave_messages(keys_and_messages, size_constraint)

    return cyphertext


def decrypt_message(key, message):
    decrypted = decrypt(key, message)
    decrypted = defragment(decrypted)
    return decrypted


if __name__=="__main__":
    print "running some simple tests to show this works!"

    keys_and_messages = {
        'Emma': 'She brought new tea here and I like her!',
        'Medb': 'She is my roommate!',
    }

    cyphertext = str(encrypt_all_messages(keys_and_messages))
    print decrypt_message('Emma', cyphertext)
    print decrypt_message('Medb', cyphertext)

