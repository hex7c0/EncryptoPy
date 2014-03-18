'''
Autokey class
Created on 18/mar/2014

@link http://en.wikipedia.org/wiki/Autokey_cipher
@package EncryptoPy
@subpackage modules
@version 0.5
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


class Autokey(object):
    '''
    autokey class

    @param string psw:    password
    @return: object
    '''

    def __init__(self, psw):
        self._key = psw.encode()

    def encrypt(self, raw):
        '''
        encode raw data

        @param bytes raw:    data input
        @return bytes
        '''

        out = bytearray()
        app = out.append
        chiper = len(self._key)
        first = list(self._key)
        counter = 0

        for i in raw:
            if(first):
                i = (i + first.pop(0)) % 256
            else:
                i = (i + raw[counter - chiper]) % 256
            counter += 1
            app(i)
        return out

    def decrypt(self, raw):
        '''
        decode raw data

        @param bytes raw:    data input
        @return bytes
        '''

        out = bytearray()
        app = out.append
        chiper = len(self._key)
        first = list(self._key)
        counter = 0

        for i in raw:
            if(first):
                i = (i - first.pop(0)) % 256
            else:
                i = (i - out[counter - chiper]) % 256
            counter += 1
            app(i)
        return out
