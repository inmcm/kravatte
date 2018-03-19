# Kravatte Achouffe Cipher Suite in Python/NumPy

A clean implementation, in Python, of the [Kravatte] pseudo-random function and associated modes based on the [Farafalle PRF] system. At its core, Kravatte accepts a user defined secret key and a sequence of input bytes to generate pseudo-random output of arbitrary size.

Kravatte makes use of the [Keccak] permutation, most notably used in NIST's [FIPS 202 SHA-3 algorithm]. Because the underlying structure of Keccak function works on a three-dimensional state of 1600 bits, it maps well to a 5x5 matrix of 64-bit unsigned integers. As such, the [NumPy] computational library is a natural fit to quickly manipulate such a structure and thus is a hard requirement.

This implementation reflects the updated, more secure Kravatte **Achouffe** released in late 2017. The older "Kravatte 6644" logic is available within this repo as well. 

## Kravatte Object

The basic Kravatte object operates on two Keecak-1600 state matrixes; the collector state and the key state. Instantiating a Kravatte object initializes the key state with provided user key and sets the collector state to zeros.

``` python
In [1]: from kravatte import Kravatte
In [2]: my_krav = Kravatte(b'1234567890')
```

The newly initialized Kravatte object is now ready to accept input strings of bytes for absorption into the collector state via the `collect_message` method. Repeated calls to `collect_message` are equivalent to `B ◦ A` sequences as described in the the Farafelle spec:

```python
In [3]: input_a = b'The quick brown fox jumps over the lazy dog'
In [4]: my_krav.collect_message(input_a)
In [5]: input_b = b'3533392d36302d35313235'
In [6]: my_krav.collect_message(input_b)
```
Once absorbing message strings is complete, the Kravatte object can produce an arbitrary number of pseudo-random output bytes via the `generate_digest` method. Those bytes are then available in the `digest` attribute:

```python
In [7]: output_bytes = 64
In [8]: my_krav.generate_digest(output_bytes)
In [9]: from binascii import hexlify
In [10]: hexlify(my_krav.digest)
Out[10]: b'8a0fc89899e058dedd368b60111bf4958f4f24216bbac76936471e6f7c3958b881c38c8e829ff07bf137701917b3e49ab392e93f3b2abfc714f90c0ca023124d'
```

The absorb/output sequence can be restarted with another call to `collect_message`. This clears the collector state and resets the key state to its initialized value. Alternatively, the user may change to a new secret key with the `update_key` method to reinitialize the key state used at the start of message absorption.

## MAC
The most basic mode of Kravatte is an authenticated pseudo-random function (PRF). Kravvate can absorb an arbitrary sized user message and key, and output an arbitrary collection of pseudo-random bytes that can act as a message authentication code.
``` python
In [1] from kravatte import mac
In [2] from binascii import hexlify
In [3] message = b'Attack at Dawn!'
In [4] key = b'something_secret'
In [5] mac_size = 64
In [6] g = mac(key, message, mac_size)
In [7] hexlify(g)
Out[7] b'24f61fc5fd38fef7f3d799ed72b24578c4479e1c035c70d8bc55ce23d74124255d5e8a0c5dd33aa36d5289f1e4e995a19be804d97bb338fa875e01e3c2d2dd51'
```


## Kravatte-SIV
Kravatte-SIV mode is a method of authenticated encryption with associated metadata (AEAD) that allows for encrypting a provided plaintest with a secret shared key and an arbitrary metadata value. Encryption generates an equal length ciphertext and fixed length tag that can be used to validate the plaintext at decryption. Metadata values can be shared for different key/message combinations with understanding that the more a value is used, the greater the chance of a tag collision.
### Encrypt
``` python
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
```
### Decrypt
``` python
In [10] plaintext, tag_valid = siv_unwrap(key, ciphertext, tag, metadata)
In [11] plaintext
Out[11] b'Attack at Dawn!'
In [12] tag_valid
Out[12] True
```


## Kravatte-SAE
Kravatte-SAE mode is a session based method of AEAD. Given a random nonce and secret key, this mode encrypts a sequence of plaintext messages and/or metadata into equal size ciphertexts and a validation tag. The sequence of plaintext/metadata is tracked as a history that builds a chain of authentication from message to message and requires all generated ciphertexts to be processed to fully decrypt and verify.

A separate `KravatteSAE` class is provided that adds the history tracking for each encryption operation done via the `sae_wrap` method.

### Encrypt
```python
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
```

For decryption and validation, the `sae_unwrap` method accepts the ciphertext, original metadata, and validation tag to not only decrypt the plaintext, but return a boolean if the decrypted plaintext is valid within the chain of messages. 

### Decrypt

```python
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
```


## Kravatte-WBC
### TODO


## Testing
A full test suite is available in `test_kravatte.py`. Tests can be invoked with pytest:

```bash
$ pytest -xvvv test_kravatte.py
```

Test vectors were generated using the [KeccakTools] C++ library available from the Keccak Team

## Caveats
 - Being a Python implementation, performance on large files or data sets may be inadequate.
 - The inputs and outputs of this implementation are limited to byte (8-bit) divisible sizes
 - While security was top of mind during development, this implementation has not been fully audited for timing attacks, side channel attacks or other vulnerabilities. Other bugs not caught by the test cases may be present. Use in a production environment is not encouraged.

If any of above are of concern, please check out the official [KeccakTools] and [Keccak Code Package]

[Kravatte]:https://keccak.team/kravatte.html
[Keccak]:https://keccak.team/files/Keccak-reference-3.0.pdf
[FIPS 202 SHA-3 algorithm]:https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
[Farafalle PRF]:https://eprint.iacr.org/2016/1188.pdf
[NumPy]:http://www.numpy.org
[KeccakTools]:https://github.com/gvanas/KeccakTools
[Keccak Code Package]:https://github.com/gvanas/KeccakCodePackage