'''
Nihilist class
Created on 17/mar/2014

@link http://en.wikipedia.org/wiki/Nihilist_cipher
@package EncryptoPy
@subpackage modules
@version 0.5
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


try:
    from modules.common.polybious import Polybious, MATRIX
except ImportError as error:
    print('In %s cannot load required libraries: %s!' \
          % (__name__, error))
    raise Exception


class Nihi(Polybious):
    '''
    nihilist class

    @param string psw:    password
    @param string ivv:    iv
    @param char typ:    'E' for encryption or 'D' for decryption
    @return: object
    '''

    def __init__(self, psw, ivv, typ):
        if(typ == 'E'):
            typ = True
        else:
            typ = False
        super().__init__(ivv, psw, typ)

    def _magic_p(self, lst_in, lst_out):
        '''
        encode buffer

        @param list lst_in:    buffer list
        @param bytearray lst_in:    out bytearray
        @return bytes
        '''

        if(len(lst_in) > 0):
            app = lst_out.append
            for (data, key) in zip(lst_in, self._key):
                x = data[0] + key[0]
                y = data[1] + key[1]
                try:
                    app(self.square[x][y])
                except IndexError:
                    if(x > MATRIX - 1):
                        x = x - MATRIX
                    if(y > MATRIX - 1):
                        y = y - MATRIX
                    app(self.square[x][y])
        return lst_out

    def _magic_m(self, lst_in, lst_out):
        '''
        decode buffer

        @param list lst_in:    buffer list
        @param bytearray lst_in:    out bytearray
        @return bytes
        '''

        if(len(lst_in) > 0):
            app = lst_out.append
            for (data, key) in zip(lst_in, self._key):
                x = data[0] - key[0]
                y = data[1] - key[1]
                try:
                    app(self.square[x][y])
                except IndexError:
                    if(x < 0):
                        x = x + MATRIX
                    if(y < 0):
                        y = y + MATRIX
                    app(self.square[x][y])
        return lst_out

    def coding(self, raw):
        '''
        code raw data

        @param bytes raw:    data input
        @return bytes
        '''

        out = bytearray()
        buffer = []
        app = buffer.append
        if(self.flag):
            magic = self._magic_p
        else:
            magic = self._magic_m

        for i in raw:
            plaintext = self.find(i)
            if(plaintext is None):
                out = magic(buffer, out)
                del(buffer[0:len(buffer)])
                out.append(i)
            else:
                app(plaintext)
        return magic(buffer, out)
