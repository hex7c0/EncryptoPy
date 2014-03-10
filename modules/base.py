'''
Base class
Created on 10/set/2013

@link http://docs.python.org/3.3/library/base64.html
@package EncryptoPy
@subpackage modules
@version 0.4
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


from base64 import b16encode, b32encode, b64encode, \
                b16decode, b32decode, b64decode


class Base(object):
    '''
    base

    @param integer size:    type of module [16,32,64]
    @param char typ:    type of code [E,D]
    @return object
    '''

    def __init__(self, size, typ):
        if(typ == 'E'):
            if(size == 16):
                self.code = b16encode
            elif(size == 32):
                self.code = b32encode
            else:
                self.code = b64encode
        else:
            if(size == 16):
                self.code = b16decode
            elif(size == 32):
                self.code = b32decode
            else:
                self.code = b64decode

    def coding(self, data):
        '''
        encode/decode data with base

        @param byte data    binary data
        @return byte
        '''

        return self.code(data)
