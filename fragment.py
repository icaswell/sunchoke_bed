# fragment.py
# @author: Isaac Caswell
# @date: 3/3/2017
# 
# Functions for fragmenting messages into randomly-sized chunks (of sizes that are multiples of 16)
# and prepending headers to them.
# 
# Nothing particularly interesting here; just string manipulation.

from Crypto.Random import random
import string

from minimalcrypt import _str_to_bytes, random_bytes
from header_prefix import HEADER_PREFIX


PAD_TOKEN = ' '
assert len(PAD_TOKEN) == 1

#===============================================================================
# PUBLIC FUNCTIONS

def prep_and_fragment_messages(keys_and_messages):

    # just in case they tried to encrypt something in unicode, e.g.
    _convert_messages_to_bytes(keys_and_messages)

    # # need to have lengths of multiples of 16
    # _pad_messages(keys_and_messages)

    # fragments messages and adds opening and closing brackets to each message
    _fragment_messages(keys_and_messages)


def interleave_messages(encrypted_and_fragmented_messages, size_constraint):

    size_constraint = _add_chaff(encrypted_and_fragmented_messages, size_constraint)

    #-------------------------------------------------------------------------------
    # this is done in an annoying way...
    messages = encrypted_and_fragmented_messages.values()
    # Get the indices of which message goes where:
    msg_idx = [msg_i for msg_i, frags in enumerate(messages) for _, frag in enumerate(frags)]
    permuted_msg_idx = random.sample(msg_idx, len(msg_idx))
    permuted = reversed([messages[i].pop() for i in permuted_msg_idx])
    return reduce(lambda x, y: x + y, permuted) 
    

#===============================================================================
# PRIVATE

def _add_chaff(encrypted_and_fragmented_messages, size_constraint):
    """
    Adds a 'message' into `encrypted_and_fragmented_messages` that is composed of random bytes.
    The length of the true messages and the chaff sum to `size_constraint`, if not None.
    Because of the fragmentation/interleaving procedure, once the messages are interleaved, it 
    is impossible to distinguish these bytes from any number of interleaved messages. The random
    bytes are generated in a cryptograpically secure manner, and as such cannto be distinguished
    from cyphertext.

    Returns the size_constraint. The reason for this is that if `size_constraint` was None, a new
    value for it was chosen in this function.
    """
    _fragments_len = lambda frags: sum([len(msg) for msg in frags])
    len_so_far = sum([_fragments_len(frags) for frags in encrypted_and_fragmented_messages.values()])
    if size_constraint is not None and size_constraint < len_so_far:
        raise ValueError("size_constraint less than size of encrypted messages (got %s)"%size_constraint)
    if size_constraint is None:
        # always add a lot of chaff
        lb, ub = 2, 4
        # additive term ensures that an observer can't reason about the length of the message based on the factorization of
        # the length of the encrypted text
        size_constraint = len_so_far * random.randint(lb, ub) + random.randint(lb, ub) 

    remaining_blocks = size_constraint - len_so_far 
    # the "key" is not used. There is no possibility for collision unless the user specifies the
    # empty string as their password, in which case they are a doofus.
    chaff = {'': random_bytes(remaining_blocks)}

    _fragment_messages(chaff, omit_header=True)
    encrypted_and_fragmented_messages.update(chaff) # add in the chaff
    return size_constraint

    
def _convert_messages_to_bytes(keys_and_messages):
    for key, message in keys_and_messages.iteritems():
        keys_and_messages[key] = _str_to_bytes(message)

def _pad(message):
    """
    Pads `message` to a length that is a multiple of 16
    """
    if len(message)%16 !=0:
        padding = 16*(len(message)/16 + 1) - len(message)
        message = message + PAD_TOKEN*padding
    return message


def _get_random_fragment_size():
    """
    One could just always return 16, but larger chunks mean less space used for the headers.
    """
    frag_size = random.randint(1,3)*16 # encoded chunks must have lengths be multiple of 16
    # right now, because we are matching with regex, we can have no more than 9 blocks.
    # If you're really worried about size constraints and need to save so much space that you want
    # blocks bigger than length 9*16 bytes, change the defragmenter to look only for the header, 
    # without an integer following it, and then encode the next block as an 8-bit integer.
    # This makes the header 256x less reliable, so perhaps increase the header size as well.
    assert frag_size <= 9*16 and frag_size >= 16
    return frag_size 

def _fragment_message(message, omit_header):
    """
    @param string message: a string
    @param bool omit_header: see docstring on `_fragment_messages`
    """

    result = []
    i = 0
    while i < len(message):
        # i and frag_size are measured in bytes
        frag_size = _get_random_fragment_size() # this will be a multiple of 16

        if not omit_header:
            num_blocks = frag_size/16
            unencrypted_header = HEADER_PREFIX + str(num_blocks)
            frag_size -= len(unencrypted_header)

            # if this is the last fragment, make it no larger than it has to be
            if i + frag_size > len(message):
                revised_num_blocks = (len(message) - i)/16 + 1
                unencrypted_header = HEADER_PREFIX + str(revised_num_blocks)
                frag_size = 16*revised_num_blocks - len(unencrypted_header)


        fragment = message[i:i+frag_size]

        if not omit_header:
            fragment = unencrypted_header + fragment
        fragment = _pad(fragment)
        result.append(fragment)
        i = i + frag_size
    return result


def _fragment_messages(keys_and_messages, omit_header=False):
    """
    @param dict keys_and_messages: a mapping from cryptographic key (string) to [plaintext] message
    @param bool omit_header: if this is used, instead of brackets being added, chunks are taken that are that much larger.
        This is used specifically when fragmenting chaff (random noise) that doesn't need headers.
        Could alternately be used to fragment already-encrypted text (with a linearly distributive cypher, as is common)

    Breaks each value in `keys_and_messages`, which was previously a string, into a list of fragments.
    Modifies the object `keys_and_messages`
    """
    for key, message in keys_and_messages.iteritems():
        keys_and_messages[key] = _fragment_message(message, omit_header)



if __name__=="__main__":
    print "for your enjoyment, some basic tests:"
    print len(HEADER_PREFIX)
    for message in ['hi', 'qwertyuiop', 'qwertyuiop'*12]:
        print message
        print _fragment_message(message, omit_header=False)
        print
