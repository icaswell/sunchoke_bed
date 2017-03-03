SUNCHOKE BED
=======

## What is This?
This module allows one to encrypt any number of messages, each with its own key (password), into a single ciphertext. Anyone with this script and one of the passwords can decrypt only the message that their password corresponds to. One could use this module to make a sort of puzzle game, wherein someone is given a ciphertext, and each text they decrypt gives a hint at another key for another message hidden in the ciphertext, or similar.

An observer has no way of knowing how many, if any, messages have been encrypted in this fashion. In fact, there exist mathematical guarantees that an observer can't distinguish the ciphertext from random noise. If you are interested in discussion about such methods, you can research "deniable encryption". Importantly, it does not help the observer to have access to this script, which is why it can freely be posted online. Even with this code, one still needs the key in order to decrypt a message.

Implementation note: since fragments of messages are randomly distributed throughout the ciphertext, an observer cannot estimate how many other messages there are, if any. The design is similar to the Rubberhose File system, developed by Assange et al.


## How to Encrypt
1. In 'input.txt', write a map of keys to their messages. The syntax is that of a Python dictionary:
	```python
	    {
	        'key': """message""",
	        'key 2': """message 2""",
	    }
	```

	And so on. Keys and messages may have upper and lower case letters, as well as letters in different encodings. Key and messages can be as long as you please.

2. Open up Command Line (The Terminal app on mac), and navigate to the folder where this repository is:

        $ cd path/to/sunchoke_bed 

    If you are not used to the command line it can seem baffling and scary. Although it is these things, for the purposes of this package, it is very simple. The only part you might have difficulties with is finding out how to do the above command, which anyone with command line experience could tell you in about five seconds.

3. Run the following command:
        $ python sunchoke_bed.py encrypt

    Your message will be somewhere between two and four times length of your original message (see `fragment._add_chaff()`). Now, if you want to make sure that the message is a particular size, run it with the `--size_constraint` parameter. For instance, if you want your message to be exactly one kilobyte:

        $ python sunchoke_bed.py encrypt --size_constraint 1024

    Your ciphertext is in `output.txt`!


## How to Decrypt
To decrypt with a single password, run the following command:

    $ python sunchoke_bed.py decrypt --password 'Anna'

with whatever password you have used, instead of `Anna`.

If this doesn't work, try the following:

- check your key. It's case sensitive--maybe you forgot a capital letter?
- maybe the person encrypting changed `EXPANSION_COUNT` and forgot to tell you?

## How to make harder to crack
Encrypted messages are always susceptible to bute-force key search––that is, trying every possible key until something good comes out.

This module protects against that using the `EXPANSION_COUNT` constant in `minimalcrypt.py`. Increasing this value linearly increases the time it takes to encrypt or decrypt any text. If it takes a full second to decrypt the text, a brute force attack becomes infeasible. The default value of 10 is meant only for testing, and should be increased if one fears a brute-force attack.

**Note that whoever is decrypting your message needs the same value of `EXPANSION_COUNT` as you had when you encrypted the message.**


## Is this secure? They say never to invent your own crypto.

I didn't really invent anything: this module just uses a standard, tried-and-true encryption algorithm on several messages, and then intersperses them with each other. It's really not a very clever idea, thank goodness, so there's little danger of vulnerability, I think. The fact that the header tokens are known shouldn't be a problem, because AES encryption is not vulnerable to known-plaintext attacks.


## Disclaimer
I did this project for fun/academic interest. Please don't do sketchy things with it.

This project has not been extensively tested, and there might be problems with encrypting or decrypting certain messages––perhaps ones with lots of whitespace or weird encodings, for instance.

Furthermore, there is a small chance (around 1 in 100k, for 1kb of ciphertext) that there will be garbled junk introduced into your message, if the header token is randomly generated. For this reason, it is good practice to decrypt what you encrypt, to make sure it works. If you are makign a very large syphertext, you may want to increase the length of the header in `constant.py`. Remember that if you do this, whoever is decrypting must use the same header.


## Dependencies
You need python on your computer, as well as the Crypto module, which comes preinstalled on mac, I think.
