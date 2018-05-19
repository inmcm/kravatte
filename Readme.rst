Kravatte Achouffe Cipher Suite in Python/NumPy
==============================================

An implementation, in Python3, of the
`Kravatte <https://keccak.team/kravatte.html>`__ pseudo-random function
and associated modes based on the `Farfalle
PRF <https://eprint.iacr.org/2016/1188.pdf>`__ system. At its core,
Kravatte accepts a user defined secret key and a sequence of input bytes
to generate pseudo-random output of arbitrary size.

Kravatte makes use of the
`Keccak <https://keccak.team/files/Keccak-reference-3.0.pdf>`__
permutation, most notably used in NIST’s `FIPS 202 SHA-3
algorithm <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>`__.
Because the underlying structure of Keccak function works on a
three-dimensional state of 1600 bits, it maps well to a 5x5 matrix of
64-bit unsigned integers. As such, the `NumPy <http://www.numpy.org>`__
computational library is a natural fit to quickly manipulate such a
structure and thus is a hard requirement.

This implementation reflects the updated, more secure Kravatte
**Achouffe** released in late 2017. The older “Kravatte 6644” logic is
available within this repo as well.

Installation
------------
Kravatte can be easily installed from `pypi <https://pypi.org/project/kravatte/>`__ via ``pip``:

.. code:: bash

    $ pip install kravatte

If ``pip`` is unavailable, this repo can be cloned and setup can be done manually:

.. code:: bash

    $ python setup.py install


Kravatte Object
---------------

The basic ``Kravatte`` object operates on two Keecak-1600 state matrices;
the collector state and the key state. Instantiating a ``Kravatte`` object
initializes the key state with provided user key and sets the collector
state to zeros.

.. code:: python

    In [1]: from kravatte import Kravatte
    In [2]: my_krav = Kravatte(b'1234567890')

The newly initialized ``Kravatte`` object is now ready to accept input
strings of bytes for absorption into the collector state via the
``collect_message`` method. Repeated calls to ``collect_message`` are
equivalent to ``B ◦ A`` sequences as described in the the Farfalle
spec:

.. code:: python

    In [3]: input_a = b'The quick brown fox jumps over the lazy dog'
    In [4]: my_krav.collect_message(input_a)
    In [5]: input_b = b'3533392d36302d35313235'
    In [6]: my_krav.collect_message(input_b)

Once absorbing message strings is complete, the ``Kravatte`` object can
produce an arbitrary number of pseudo-random output bytes via the
``generate_digest`` method. Those bytes are then available in the
``digest`` attribute:

.. code:: python

    In [7]: output_bytes = 64
    In [8]: my_krav.generate_digest(output_bytes)
    In [9]: from binascii import hexlify
    In [10]: hexlify(my_krav.digest)
    Out[10]: b'8a0fc89899e058dedd368b60111bf4958f4f24216bbac76936471e6f7c3958b881c38c8e829ff07bf137701917b3e49ab392e93f3b2abfc714f90c0ca023124d'

The absorb/output sequence can be restarted with another call to
``collect_message``. This clears the collector state and resets the key
state to its initialized value. Alternatively, the user may change to a
new secret key with the ``update_key`` method to reinitialize the key
state used at the start of message absorption.

MAC
---

The most basic mode of ``Kravatte`` is an authenticated pseudo-random
function (PRF). ``Kravatte`` can absorb an arbitrary sized user message and
key, and output an arbitrary collection of pseudo-random bytes that can
act as a message authentication code. The ``mac`` does this in a single step:

.. code:: python

    In [1] from kravatte import mac
    In [2] from binascii import hexlify
    In [3] message = b'Attack at Dawn!'
    In [4] key = b'something_secret'
    In [5] mac_size = 64
    In [6] g = mac(key, message, mac_size)
    In [7] hexlify(g)
    Out[7] b'24f61fc5fd38fef7f3d799ed72b24578c4479e1c035c70d8bc55ce23d74124255d5e8a0c5dd33aa36d5289f1e4e995a19be804d97bb338fa875e01e3c2d2dd51'

Kravatte-SIV
------------

``Kravatte-SIV`` mode is a method of authenticated encryption with
associated metadata (AEAD) that allows for encrypting a provided
plaintext with a secret shared key and an arbitrary metadata value.
Encryption generates an equal length ciphertext and fixed length tag
that can be used to validate the plaintext at decryption. Metadata
values can be shared for different key/message combinations with
understanding that the more a value is used, the greater the chance of a
tag collision. 

Encrypt
~~~~~~~

.. code:: python

    In [1] from kravatte import siv_wrap, siv_unwrap
    In [2] from binascii import hexlify
    In [3] from datetime import datetime
    In [4] message = b'Attack at Dawn!'
    In [5] key = b'something_secret'
    In [6] metadata = str(datetime.now()).encode()
    In [7] ciphertext, tag = siv_wrap(key, message, metadata)
    In [8] hexlify(ciphertext)
    Out[8] b'79f7bd89a7cb7af1892ea51c531f4b'
    In [9] hexlify(tag)
    Out[9] b'37c7e11f0c9c744e7c113590fdfba7737cb38b629ef6901df22d6994340e89eas'

Decrypt
~~~~~~~

.. code:: python

    In [10] plaintext, tag_valid = siv_unwrap(key, ciphertext, tag, metadata)
    In [11] plaintext
    Out[11] b'Attack at Dawn!'
    In [12] tag_valid
    Out[12] True

Kravatte-SAE
------------

``Kravatte-SAE`` mode is a session based method of AEAD. Given a random
nonce and secret key, this mode encrypts a sequence of plaintext
messages and/or metadata into equal size ciphertexts and a validation
tag. The sequence of plaintext/metadata is tracked as a history that
builds a chain of authentication from message to message and requires
all generated ciphertexts to be processed to fully decrypt and verify.

A separate ``KravatteSAE`` class is provided that adds the history
tracking for each encryption operation done via the ``sae_wrap`` method.

Encrypt
~~~~~~~

.. code:: python

    In [1]: from kravatte import KravatteSAE
    In [2]: from datetime import datetime
    In [3]: from binascii import hexlify
    In [4]: message_1 = b'Directions to my house:'
    In [5]: metadata_1 = str(datetime.now()).encode()
    In [6]: message_2 = b'Turn right on main street'
    In [7]: metadata_2 = str(datetime.now()).encode()
    In [8]: message_3 = b'Continue straight for 3500 miles'
    In [9]: metadata_3 = str(datetime.now()).encode()
    In [10]: message_4 = b'You have arrived at your destination'
    In [11]: metadata_4 = str(datetime.now()).encode()
    In [12]: nonce = b'a well chosen random number'
    In [13]: key = b'an even better random number'
    In [14]: KravSAE_wrapper = KravatteSAE(nonce, key)
    In [15]: ciphertext_1, tag_1 = KravSAE_wrapper.sae_wrap(message_1, metadata_1)
    In [16]: hexlify(ciphertext_1)
    Out[16]: b'7b8932a1c3673fcfe752631ef5b867843951514335de61'
    In [17]: hexlify(tag_1)
    Out[17]: b'3384885ca293925cc65a03fa10790420'
    In [18]: ciphertext_2, tag_2 = KravSAE_wrapper.sae_wrap(message_2, metadata_2)
    In [19]: hexlify(ciphertext_2)
    Out[19]: b'ab48882d4339c6def9d5d06f608db5318a87a417566c0b20bd'
    In [20]: hexlify(tag_2)
    Out[20]: b'347f5a152dcc9ccc3c19fa936067c3d2'
    In [21]: ciphertext_3, tag_3 = KravSAE_wrapper.sae_wrap(message_3, metadata_3)
    In [22]: hexlify(ciphertext_3)
    Out[22]: b'bc461f40db74705c10b1400b6a9967dd7164cbf774c196d5b649faf2bd792339'
    In [23]: hexlify(tag_3)
    Out[23]: b'6ba2faee4d2aa5654a054222a049d926'
    In [24]: ciphertext_4, tag_4 = KravSAE_wrapper.sae_wrap(message_4, metadata_4)
    In [25]: hexlify(ciphertext_4)
    Out[25]: b'1f451f51d9882f9f7674c37dace4036efd9efe39d6b58ccdf6b012ef988e4e1f2617479f'
    In [26]: hexlify(tag_4)
    Out[26]: b'5f3511f140b4ea36412c0e4b22d1c218'

For decryption and validation, the ``sae_unwrap`` method accepts the
ciphertext, original metadata, and validation tag to not only decrypt
the plaintext, but return a boolean if the decrypted plaintext is valid
within the chain of messages.

Decrypt
~~~~~~~

.. code:: python

    In [27]: KravSAE_unwrapper = KravatteSAE(nonce, key)
    In [28]: plaintext_1, check_tag_1 = KravSAE_unwrapper.sae_unwrap(ciphertext_1, metadata_1, tag_1)
    In [29]: plaintext_1
    Out[29]: b'Directions to my house:'
    In [30]: check_tag_1
    Out[30]: True
    In [31]: plaintext_2, check_tag_2 = KravSAE_unwrapper.sae_unwrap(ciphertext_2, metadata_2, tag_2)
    In [32]: plaintext_2
    Out[32]: b'Turn right on main street'
    In [33]: check_tag_2
    Out[33]: True
    In [34]: plaintext_3, check_tag_3 = KravSAE_unwrapper.sae_unwrap(ciphertext_3, metadata_3, tag_3)
    In [35]: plaintext_3
    Out[35]: b'Continue straight for 3500 miles'
    In [36]: check_tag_3
    Out[36]: True
    In [37]: plaintext_4, check_tag_4 = KravSAE_unwrapper.sae_unwrap(ciphertext_4, metadata_4, tag_4)
    In [38]: plaintext_4
    Out[38]: b'You have arrived at your destination'
    In [39]: check_tag_4
    Out[39]: True

KravatteWBC
-----------

Kravatte Wide Block Cipher mode is a symmetric block cipher mode where the user can specify
the size of the block, an arbitrary ``tweak`` value input, and arbitrary secret key. The ``KravatteWBC``
object, once initialized, can encrypt/decrypt messages of the given block size (or smaller). ``KravatteWBC``
is splits messages into left and right components and uses a 4-stage Feistal sequence to encrypt/decrypt.

Encrypt and Decrypt
~~~~~~~~~~~~~~~~~~~

.. code:: python

    In [1]: from kravatte import KravatteWBC
    In [2]: block_size = 64
    In [3]: my_tweak = b'tweak can be anything'
    In [4]: my_key = b'\x00' * 24
    In [5]: my_wbc = KravatteWBC(block_size, my_tweak, my_key)
    In [6]: c_block = my_wbc.encrypt(b'This is some random 64-byte text string to use in this example!!')
    In [7]: from binascii import hexlify
    In [8]: hexlify(c_block)
    Out[8]: b'2368fae1271e5c784537df331586d5d4daeeb34a6fe4ebea03cc1df7f9c0d79fcc709a9ff2199514f431da685e27658dbf6c5afed11ce5c8172f7615c19db1b9'
    In [9]: my_wbc.decrypt(c_block)
    Out[9]: b'This is some random 64-byte text string to use in this example!!'


KravatteWBC-AE
--------------

``KravatteWBC-AE`` is a variant of ``KravatteWBC`` that extends the desired block size by 16 bytes and 
embeds authentication data. The tweak is replaced with arbitrary associated metadata. When the 
block is decrypted it is also validated as being encrypted with same secret key.

Encrypt and Decrypt
~~~~~~~~~~~~~~~~~~~

.. code:: python

    In [1]: from datetime import datetime
    In [2]: from binascii import hexlify
    In [3]: my_key = b"Doesn't look like anything to me"
    In [4]: metadata = str(datetime.now()).encode()
    In [5]: message = b'These violent delights have violent ends'
    In [6]: len(message)
    Out[6]: 40
    In [7]: my_WBC_AE = KravatteWBC_AE(40, my_key)
    In [8]: ctext_ae = my_WBC_AE.wrap(message, metadata)
    In [9]: len(ctext_ae)
    Out[9]: 56
    In [10]: hexlify(ctext_ae)
    Out[10]: b'388623f7a7d3c044cda574063b4ff16edbdfc95cb449f335a1c5ad5ed37897aa2470f3575825a55df04cc1dab34b4feb03aa6d35f6190d62'
    In [11]: plaintext, validated = my_WBC_AE.unwrap(ctext_ae, metadata)
    In [12]: plaintext
    Out[12]: b'These violent delights have violent ends'
    In [13]: validated
    Out[13]: True


KravatteOracle
--------------

``KravatteOracle`` is simple pseduo-random number generator built from the ``Kravatte`` PRF primitive. Initialized
with an authentication key, the ``KravatteOracle`` object absorbs an arbitrarily sized seed value into the
collector state. From there, streams of random bytes can be generated on demand via the ``random`` method.
The generator can be re-seeded at any point with the ``seed_generator`` method.

Generate Random Numbers
~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    In [1]: my_psrng = KravatteOracle(my_seed, my_key)
    In [2]: my_key = b'1234'
    In [3]: my_seed = b'watermelon'
    In [4]: my_psrng = KravatteOracle(my_seed, my_key)
    In [5]: random_bytes = my_psrng.random(24)
    In [6]: hexlify(random_bytes)
    Out[6]: b'14a42ab5756efe61eae73893570b6736b392d0031a87e36d'
    In [7]: random_bytes = my_psrng.random(42)
    In [8]: hexlify(random_bytes)
    Out[8]: b'77d6308e18d57fb124e75602ced2e863e7de34c69ea57bec47efae84e85d0075c3ebbf7e535ec0fb096f'

Re-seed Generator
~~~~~~~~~~~~~~~~~

.. code:: python

    In [9]: my_psrng.seed_generator(b'apple')
    In [10]: random_bytes = my_psrng.random(18)
    In [11]: hexlify(random_bytes)
    Out[11]: b'3e108c3f627f561943893b6a3184e5b76472'


Multi-Process Performance Mode
---------------------------------
The Farfalle PRF allows for significant parallelism in both the compression and expansion phases when
consuming or generating large numbers of blocks.  We can exploit that fact for increased performance
via Python's `multiprocessing <https://docs.python.org/3.5/library/multiprocessing.html>`__ module.
This allows us to spawn any number of identical worker subprocesses that can consume additional
CPU core resources. Enabling the multi-process mode is done at object creation time for ``Kravatte``,
or any of its operating modes, with the ``workers`` arguments:

.. code:: python

    In [1]: new_kravatte = Kravatte(my_key, workers=8)
    In [2]: my_kra_mac = mac(my_key, my_message, my_output_size, workers=16)
    In [3]: my_wbc = KravatteWBC(block_size, my_tweak, my_key, workers=4)

For optimal performance, the number of workers should match the number of CPU cores reported by
``os.cpu_count``. This is set automatically if ``workers`` is set to 0:

.. code:: python
    
    # Equivalent objects
    In [4]: my_psrng = KravatteOracle(my_seed, my_key, workers=0)
    In [5]: my_psrng = KravatteOracle(my_seed, my_key, workers=os.cpu_count())

Multi-process mode can be explicitly disabled by setting workers to ``None``:

.. code:: python
    
    In [5]: my_psrng = KravatteOracle(my_seed, my_key, workers=None)

There is a non-trivial performance cost associated with generating new Python processes. For small,
generally < 100KB, inputs and outputs, it can be faster to use the single process variant.

Testing
-------

A full test suite is available in ``test_kravatte.py``. Assuming the ``kravatte`` module is installed, 
tests can be invoked with pytest:

.. code:: bash

    $ pytest -xvvv test_kravatte.py

The same tests are run against the standard codepath and the multiprocess code path utilizing all available
CPU cores. Test vectors were generated using the
`KeccakTools <https://github.com/gvanas/KeccakTools>`__ C++ library available from the Keccak Team

Caveats
-------

-  Being a Python implementation, performance on large files or data
   sets may be inadequate (even with multi-processing enabeled).
-  The inputs and outputs of this implementation are limited to byte
   (8-bit) divisible sizes
-  While security was top of mind during development, this
   implementation has not been fully audited for timing attacks, side
   channel attacks or other vulnerabilities. Other bugs not caught by
   the test cases may be present. Use in a production environment is not
   encouraged.

If any of above are of concern, please check out the official
`KeccakTools <https://github.com/gvanas/KeccakTools>`__ and `Keccak Code
Package <https://github.com/gvanas/KeccakCodePackage>`__
