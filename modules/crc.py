'''
Crc class
Created on 17/set/2013

@link http://it.wikipedia.org/wiki/Cyclic_redundancy_check
@package EncryptoPy
@subpackage modules
@version 0.5
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


from zlib import adler32, crc32


class Crc(object):
    '''
    hmac

    @param integer size:        type of hash [31, 32]
    @return object
    '''

    def __init__(self, size):
        self.hash = 0
        if(size == 31):    # adler
            self.update = self.update_adler
        else:    # crc
            self.update = self.update_crc

    def update_adler(self, data):
        '''
        update hash

        @param byte data    data of file
        @return void
        '''

        self.hash += adler32(data)
        return

    def update_crc(self, data):
        '''
        update hash

        @param byte data    data of file
        @return void
        '''

        self.hash += crc32(data)
        return

    def hexdigest(self):
        '''
        return formatted string

        @return string
        '''

        return str(self.hash)
