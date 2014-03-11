'''
Rc4 class
Created on 10/mar/2014

@link http://en.wikipedia.org/wiki/RC4
@package EncryptoPy
@subpackage modules
@version 0.5
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


def crypt(data, key):
    '''
    crypt data with key
    cannot divide KSA from PRGA (boh??)

    @param bytes data:    read
    @param bytes key:    password
    '''

    l_key = len(key)
    S = [i for i in range(256)]
    j = 0
    out = bytearray()
    app = out.append

    # KSA
    for i in range(256):
        j = (j + S[i] + key[i % l_key]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA
    i = j = 0
    for c in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        app(c ^ S[(S[i] + S[j]) % 256])

    return out


class RC4(object):
    '''
    wrapper for rc4 class

    @param string psw:    password
    @return: object
    '''

    def __init__(self, psw):
        self.psw = psw.encode()

    def coding(self, data):
        return crypt(data, self.psw)
