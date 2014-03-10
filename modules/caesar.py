'''
Caesar class
Created on 09/mar/2014

@link http://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher
@package EncryptoPy
@subpackage modules
@version 0.4
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


LIMIT = 256


class Caesar(object):
    '''
    caesar

    @param interger size:    number of round
    @return: object
    '''

    def __init__(self, size):
        self.flag = False
        if(size == -1):    # atbash
            self.flag = True
        self.round = int(size % LIMIT)

    def encrypt(self, raw):
        '''
        encrypt function

        @param byte raw:    read file
        @return: byte
        '''

        temp = bytearray()
        app = temp.append
        rround = self.round

        for ord_x in range(len(raw)):
            ord_x = raw[ord_x]
            if(ord_x >= LIMIT):
                ord_x = int(ord_x % LIMIT)
            if(self.flag):    # atbash
                app(LIMIT - 1 - ord_x)
            else:
                try:
                    app(ord_x + rround)
                except ValueError:
                    app((ord_x - LIMIT) + rround)

        return temp

    def decrypt(self, raw):
        '''
        decrypt function function

        @param byte raw        read file
        '''

        temp = bytearray()
        app = temp.append
        rround = self.round

        for ord_x in range(len(raw)):
            ord_x = raw[ord_x]
            if(ord_x >= LIMIT):
                ord_x = int(ord_x % LIMIT)
            if(self.flag):    # atbash
                app(LIMIT - 1 - ord_x)
            else:
                try:
                    app(ord_x - rround)
                except ValueError:
                    app((ord_x + LIMIT) - rround)

        return temp
