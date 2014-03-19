**List of available modules**

meaning of info:

1. password: encrypt file with password, is required for restore
1. decrypt: decryption of file is enabled
1. iv: create an extra file 'iv_' with some extra info for decryption
1. hash: create only hash of file
1. text: decryption of file is correct only with text file
1. BUGGED: on working

========
***set -k size for correct module***

[aes](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
> password, decrypt, iv
* -k 128 for aes128
* -k 192 for aes192
* -k 256 for aes256

[des](http://en.wikipedia.org/wiki/Data_Encryption_Standard)
> password, decrypt, iv
* -k 1 for des
* -k 3 for triple_des

[base](http://en.wikipedia.org/wiki/Base64)
> decrypt
* -k 16 for base16
* -k 32 for base32
* -k 64 for base64

[xor](http://en.wikipedia.org/wiki/XOR_cipher)
> password, decrypt

[hash](http://en.wikipedia.org/wiki/Cryptographic_hash_function)
> hash
* -k 0 for sha0
* -k 1 for sha1
* -k 3 for dsa
* -k 4 for md4
* -k 5 for md5
* -k 160 for ripemd160
* -k 224 for sha224
* -k 256 for sha256
* -k 384 for sha384
* -k 512 for sha512

[hmac](http://en.wikipedia.org/wiki/Hash-based_message_authentication_code)
> hash, password

[crc](http://it.wikipedia.org/wiki/Cyclic_redundancy_check)
> hash
* -k 31 for adler32
* -k 32 for crc32

[vige](http://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
> password, decrypt

[play](http://en.wikipedia.org/wiki/Playfair_cipher)
> password, text, decrypt

[blow](http://en.wikipedia.org/wiki/Blowfish_(cipher))
> BUGGED

[caes](http://en.wikipedia.org/wiki/Caesar_cipher)
> decrypt
* -k -1 for atbash
* -k 13 for rot13
* -k (any size)

[morse](http://en.wikipedia.org/wiki/Morse_code)
> text

[leet](http://en.wikipedia.org/wiki/Leet)
> text

[rc](http://en.wikipedia.org/wiki/RC2)
> password, decrypt
* -k 2 for rc2
* -k 4 for rc4

[otp](http://en.wikipedia.org/wiki/One-time_pad)
> iv, decrypt

[nihi](http://en.wikipedia.org/wiki/Nihilist_cipher)
> iv, password, decrypt

[vic](http://en.wikipedia.org/wiki/VIC_cipher)
> BUGGED

[auto](http://en.wikipedia.org/wiki/Autokey_cipher)
> password, decrypt

[sha3](http://en.wikipedia.org/wiki/SHA-3)
> hash
* -k 224 for sha3_224
* -k 256 for sha3_256
* -k 384 for sha3_384
* -k 512 for sha3_512