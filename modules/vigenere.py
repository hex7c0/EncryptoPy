'''
Vigenère class
Created on 17/set/2013

@link http://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher
@package EncryptoPy
@subpackage modules
@version 0.4
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


from itertools import cycle
LIMIT = 256


class Vigenere(object):
    '''
    vigenere

    @param string psw:    password
    @return: object
    '''

    def __init__(self, psw):
        self.key = cycle(psw)

    def encrypt(self, raw):
        '''
        encrypt function

        @param byte raw:    read file
        @return: byte
        '''

        temp = bytearray()
        app = temp.append

        for (ord_x, ord_y) in zip(raw, self.key):
            ord_y = ord(ord_y)
            if(ord_y >= LIMIT):
                ord_y = int(ord_y % LIMIT)
            try:
                app(ord_x + ord_y)
            except ValueError:
                app((ord_x - LIMIT) + ord_y)

        return temp

    def decrypt(self, raw):
        '''
        decrypt function function

        @param byte raw        read file
        @return: byte
        '''

        temp = bytearray()
        app = temp.append

        for (ord_x, ord_y) in zip(raw, self.key):
            ord_y = ord(ord_y)
            if(ord_y >= LIMIT):
                ord_y = int(ord_y % LIMIT)
            try:
                app(ord_x - ord_y)
            except ValueError:
                app((ord_x + LIMIT) - ord_y)

        return temp
