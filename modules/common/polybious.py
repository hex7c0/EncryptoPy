'''
Polybious square
Created on 17/mar/2014

@link http://en.wikipedia.org/wiki/Morse_code
@package EncryptoPy
@subpackage modules
@version 0.4
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


from itertools import cycle


MATRIX = 16
INDEX = 0


class Polybious(object):
    '''
    simple way to create Polibious square
    isn't a module for encryption, but it's a base for others modules

    @param string key:    mixed alphabet
    @param string psw:    password
    @pararam bool flag:    encode or decode
    @return object
    '''

    def __init__(self, key, psw, flag):
        self._key = list(key.encode())
        self._used = []
        self.square = [[0 for i in range(MATRIX)]for j in range(MATRIX)]
        self.flag = flag
        index = INDEX

        for ord_i in range(MATRIX):
            for ord_j in range(MATRIX):
                tmp, index = self.__get_key(index)
                self.square[ord_i][ord_j] = tmp
        self._password(psw.encode())

    def __get_key(self, inde):
        '''
        return next element for crate square

        @param integer inde:    index for creation
        @return list
        '''

        try:
            tmp = self._key.pop(0)
        except IndexError:
            tmp = inde
            inde += 1
        if(tmp in self._used):
            return self.__get_key(inde)
        else:
            self._used.append(tmp)
            return (tmp, inde)

    def _password(self, psw):
        '''
        build user password

        @return void
        '''

        app = self._key.append
        find = self.find

        for i in psw:
            app(find(i))
        self._key = cycle(self._key)
        return

    def find(self, char):
        '''
        return ordinates of char in lst

        @param integer char:    char to bytes
        @retun tuple
        '''

        for ord_i in range(MATRIX):
            try:
                return (ord_i, self.square[ord_i].index(char))
            except ValueError:
                pass
        # return None if not found, so the bytes remain the same
        return None
