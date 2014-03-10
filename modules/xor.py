'''
Xor class
Created on 10/set/2013

@link http://en.wikipedia.org/wiki/XOR_cipher
@package EncryptoPy
@subpackage modules
@version 0.4
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


from itertools import cycle


class Xor(object):
    '''
    xor

    @param string psw:    password
    @return object
    '''

    def __init__(self, psw):
        self.psw = psw
        self.cycle = cycle(self.psw)

    def coding(self, data):
        '''
        encode/decode data with xor

        @param byte data    binary data
        @return byte
        '''

        a = bytearray()
        app = a.append
        for(x, y) in zip(data, self.cycle):
            if(type(x) == str):
                x = ord(x)
            if(type(y) == str):
                y = ord(y)
            app(x ^ y)
        return a
