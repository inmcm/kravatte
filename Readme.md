# Kravatte Achouffe Cipher Suite in Python/NumPy

A clean implementation of Kravatte encryption toolkit based on the Farafalle PRF

https://eprint.iacr.org/2016/1188.pdf


## MAC
The most basic mode of Kravatte is a pseudo-random function (PRF). Kravvate can absorb an arbitary sized user message and key and output a arbitary collection of pseudo-random bytes that can act as a message authenication code.
``` python
>>> from kravatte import mac
>>> from binascii import hexlify
>>> message = b'Attack at Dawn!'
>>> key = b'something_secret'
>>> mac_size = 64
>>> g = mac(key, message, mac_size)
>>> hexlify(g) b'24f61fc5fd38fef7f3d799ed72b24578c4479e1c035c70d8bc55ce23d74124255d5e8a0c5dd33aa36d5289f1e4e995a19be804d97bb338fa875e01e3c2d2dd51'
```



## Kravatte-SIV
Kravatte-SIV is a method of authenticated encryption with asscociated metadata (AEAD) that allows for encrypting a provided plaintest with a secret shared key and an arbitrary metadata value. Encryption generates an equal length ciphertext and fixed length tag that can be used to validate the plaintext at decryption. Metadata values can be shared for different key/message combinations with understanding that the more a value is used, the greater the chance of a tag collision.
### Encrypt
``` python
>>> from kravatte import siv_wrap, siv_unwrap
>>> from binascii import hexlify
>>> from datetime import datetime
>>> message = b'Attack at Dawn!'
>>> key = b'something_secret'
>>> metadata = str(datetime.now()).encode()
>>> ciphertext, tag = siv_wrap(key, message, metadata)
>>> hexlify(ciphertext)
b'79f7bd89a7cb7af1892ea51c531f4b'
>>> hexlify(tag)
b'37c7e11f0c9c744e7c113590fdfba7737cb38b629ef6901df22d6994340e89eas'
```
### Decrypt
``` python
>>> plaintext, tag_valid = siv_unwrap(key, ciphertext, tag, metadata)
>>> plaintext
b'Attack at Dawn!'
>>> tag_valid
True
```
