# constant.py

# This does not include the integer that follows the header.
# The probability of a false header occurring randomly in a string of n bytes is:
# p = 1 - (1- 1/256^(HEADER_LENGTH+1))^(n - HEADER_LENGTH)
# for instance, with HEADER_LENGTH==2 and n==1028, this is 6.115249747185025e-05
#
# Actually, since the following digit could be one of nine options, it is:
#       p = 1 - (1- (9.0/256)*256^(-HEADER_LENGTH))^(n - HEADER_LENGTH)
# or if you prefer python:
#       p = lambda n, k: 1 - (1- ((9.0/256)*(256**-k)))**(n - k)
#
# For 1028, 3 this is 2.1478603833280374e-06
#
# Ah, but I have forgotten that since there is the constraint that the header has to be on a
# boundary of a 16 byte section, the n is decreased by 16:
#   >>> p = lambda n, k: 1 - (1- ((9.0/256)*(256**-k)))**(n/16 - k)
#   >>> p(1024, 3)
#   1.2782401537236865e-07

HEADER_PREFIX = b'\x06\xcf\x96\xf3'#'<<|`'