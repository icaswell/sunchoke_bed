# defragment.py
# @author: Isaac Caswell
# @date: 3/3/2017
# 
# Functions for reconstructing messages that have been fragmented with the methods in fragment.py.
# 
# Nothing particularly interesting here; just string manipulation.

from collections import Counter
import re
from header_prefix import HEADER_PREFIX


def chunk_message(msg):
    chunked = [msg[i*16:(i+1)*16] for i in range(len(msg)/16 + 1)]
    if not chunked[-1]: del chunked[-1] # if len(msg)%16 == 0
    return chunked

def _match_prefix(chunk):
    match = re.match(re.escape(HEADER_PREFIX) + '\d', chunk, re.DOTALL)
    if match is None: return None
    return match.group(0)


def reconstruct(chunked_message, header_prefix):
    reconstructed = ''
    i = 0
    while i < len(chunked_message):
        n_chunks = 1
        if _match_prefix(chunked_message[i]) is not None:
            n_chunks = int(chunked_message[i][len(HEADER_PREFIX)])
            if n_chunks == 0: break
            reconstructed += chunked_message[i][len(HEADER_PREFIX) + 1:]
            reconstructed += "".join(chunked_message[i+1: i + n_chunks])
        i += n_chunks
    return reconstructed


def defragment(decrypted_message):
    chunked_message = chunk_message(decrypted_message)

    reconstructed = reconstruct(chunked_message, HEADER_PREFIX)

    return reconstructed
