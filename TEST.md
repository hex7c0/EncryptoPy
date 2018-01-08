JPG file **5.4Mb** size

Python **3.4rc**

CPU dualcore **2.7Ghz** i7

OS **Unix**

_same password_

***

## Encryption

> python3 encryptopy.py -p a.jpg -E aes

``time: 08,15Min
size: 5.4Mb``

> python3 encryptopy.py -p a.jpg -E des

``time: 05,50Min
size: 5.4Mb``

> python3 encryptopy.py -p a.jpg -E base

``time: 00.00Min
size: 7.2Mb``

> python3 encryptopy.py -p a.jpg -E xor

``time: 00,01Min
size: 5.4Mb``

> python3 encryptopy.py -r a.jpg -E vige

``time: 00.01Min
size: 5.4Mb``

> python3 encryptopy.py -r a.jpg -E caes

``time: 00.00Min
size: 5.4Mb``

> python3 encryptopy.py -r a.jpg -E rc

``time: 00.01Min
size: 5.4Mb``

> python3 encryptopy.py -r a.jpg -E otp

``time: 00.03Min
size: 5.4Mb``

> python3 encryptopy.py -r a.jpg -E nihi

``time: 00.34Min
size: 5.4Mb``

> python3 encryptopy.py -r a.jpg -E auto

``time: 00.00Min
size: 5.4Mb``

========

## Decryption

> python3 encryptopy.py -p a.jpg.cr -D aes

``time: 08,24Min
``

> python3 encryptopy.py -p a.jpg.cr -D des

``time: 05.53Min
``

> python3 encryptopy.py -p a.jpg.cr -D base

``time: 00.00Min
``

> python3 encryptopy.py -p a.jpg.cr -D xor

``time: 00,01Min
``

> python3 encryptopy.py -p a.jpg.cr -D vige

``time: 00.01Min
``

> python3 encryptopy.py -p a.jpg.cr -D caes

``time: 00.00Min
``

> python3 encryptopy.py -p a.jpg.cr -D rc

``time: 00.01Min
``

> python3 encryptopy.py -p a.jpg.cr -D otp

``time: 00.02Min
``

> python3 encryptopy.py -p a.jpg.cr -D nihi

``time: 00.32Min
``

> python3 encryptopy.py -p a.jpg.cr -D auto

``time: 00.00Min
``

========

## Tips

with slow encryption (in python of course), try to compress original file with '-c' flag

> encryptopy.py -p a.jpg -Ec aes

if you use cascade encryption, remember to inverse the order for decryption

> encryptopy.py -p a.jpg -Ed aes des

> encryptopy.py -p a.jpg -Dd des aes
