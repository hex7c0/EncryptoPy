'''
One time Pad class
Created on 11/mar/2013

@link http://en.wikipedia.org/wiki/One-time_pad
@package EncryptoPy
@subpackage modules
@version 0.4
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


LIMIT = 256


class Otp(object):
    '''
    otp

    @return: object
    '''

    def __init__(self):
        pass

    def encrypt(self, raw, ivv):
        '''
        encrypt function

        @param byte raw:    read file
        @param byte ivv:    iv
        @return: byte
        '''

        temp = bytearray()
        app = temp.append

        for (ord_x, ord_y) in zip(raw, ivv):
            if(ord_y >= LIMIT):
                ord_y = int(ord_y % LIMIT)
            try:
                app(ord_x + ord_y)
            except ValueError:
                app((ord_x - LIMIT) + ord_y)

        return temp

    def decrypt(self, raw, ivv):
        '''
        decrypt function function

        @param byte raw        read file
        @param byte ivv:    iv
        @return: byte
        '''

        temp = bytearray()
        app = temp.append

        for (ord_x, ord_y) in zip(raw, ivv):
            if(ord_y >= LIMIT):
                ord_y = int(ord_y % LIMIT)
            try:
                app(ord_x - ord_y)
            except ValueError:
                app((ord_x + LIMIT) - ord_y)

        return temp
