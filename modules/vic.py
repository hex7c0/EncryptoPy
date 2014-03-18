'''
Vic class
Created on 17/mar/2014

@link http://en.wikipedia.org/wiki/VIC_cipher
@package EncryptoPy
@subpackage modules
@version 0.5
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


MATRIX = 5
S_MATR = ord('A')
E_MATR = ord('z')
S_CODE = 0
E_CODE = 9


class Vic(object):
    '''
    vic class with modification
    like upper and lower case, special mark

    @param string psw:    password
    @param string ivv:    iv
    @param char typ:    'E' for encryption or 'D' for decryption
    @return: object
    '''

    CHECKERBOARD = [
                    [69, 84, 32, 65, 79, 78, 32, 82, 73, 83],
                    [66, 67, 68, 70, 71, 72, 74, 75, 76, 77],
                    [80, 81, 79, 85, 86, 87, 88, 89, 90, 73],
                    [101, 116, 117, 97, 111, 110, 121, 114, 105, 115],
                    [98, 99, 100, 102, 103, 104, 119, 112, 108, 109]
                   ]
#==============================================================================
# A = [
#       ['E', 'T', ' ', 'A', ' ', 'N', ' ', 'R', ' ', 'S'],
#       ['B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M'], # 2
#       ['P', 'Q', 'O', 'U', 'V', 'W', 'X', 'Y', 'Z', 'I'], # 6
#
#       ['e', 't', 'u', 'a', 'o', 'n', 'y', 'r', 'i', 's'], # 4
#       ['b', 'c', 'd', 'f', 'g', 'h', 'w', 'p', 'l', 'm'], # 8
#     ]
# B=[[],[],[],[],[]]
# for i in range(5):
#     app=B[i].append
#     for j in range(10):
#         print('l %s: %s' % (A[i][j], ord(A[i][j])))
#         app(ord(A[i][j]))
#     print()
# print(B)
#==============================================================================

    def __init__(self, psw, typ):
        if(typ == 'E'):
            self.coding = self.encoding
        else:
            self.coding = self.decoding
        self._key = self.__password(psw.encode())
        self.bookmark = -1

    @staticmethod
    def __password(psw):
        '''
        encode buffer

        @param string psw:    password
        @return string
        '''

        tmp = 0
        for i in psw:
            tmp += i
        return str(tmp)

    def _get_add(self):
        '''
        transposition

        @return: integer
        '''

        try:
            self.bookmark += 1
            return int(self._key[self.bookmark])
        except IndexError:
            self.bookmark = 0
            return int(self._key[self.bookmark])

    def _magic_p(self, lst_in, lst_out):
        '''
        encode buffer

        @param list lst_in:    buffer list
        @param bytearray lst_in:    out bytearray
        @return bytes
        '''

        if(len(lst_in) > 0):
            app = lst_out.append
            add = self._get_add

            for data in lst_in:
                for inside in data:
                    app((inside + add()) % 10)
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
            add = self._get_add

            for data in lst_in:
                for inside in data:
                    app((inside - add()) % 10)
        return lst_out

    def find(self, char):
        '''
        return ordinates of char in lst

        @param integer char:    char to bytes
        @retun list
        '''

        for ord_i in range(MATRIX):
            try:
                res = self.CHECKERBOARD[ord_i].index(char)
                if(ord_i == 0):
                    go = [res]
                elif(ord_i == 1):
                    go = [2, res]
                elif(ord_i == 2):
                    go = [6, res]
                elif(ord_i == 3):
                    go = [4, res]
                elif(ord_i == 4):
                    go = [8, res]
                return go
            except ValueError:
                pass
        # return None if not found, so the bytes remain the same
        return None

    def restore(self, arr):
        '''
        transform bytearray to char

        @param bytes arr:    input
        @return bytes
        '''

        buff = bytearray()
        app = buff.append
        counter = 0

        while counter < len(arr):
            ii = arr[counter]
            if(ii >= S_CODE and ii <= E_CODE):
                if(ii == 2):
                    ord_x = 1
                elif(ii == 6):
                    ord_x = 2
                elif(ii == 4):
                    ord_x = 3
                elif(ii == 8):
                    ord_x = 3
                else:
                    app(self.CHECKERBOARD[0][ii])
                    counter += 1    # because use 'continue'
                    continue
                counter += 1
                try:
                    ord_y = arr[counter]
                    app(self.CHECKERBOARD[ord_x][ord_y])
                except IndexError:
                    app(ii)
                    counter -= 1    # restore
            else:
                app(ii)
            counter += 1
        return buff

    def encoding(self, raw):
        '''
        encode raw data

        @param bytes raw:    data input
        @return bytes
        '''

        out = bytearray()
        buffer = []
        app = buffer.append
        magic = self._magic_p

        for i in raw:
            if(i >= S_MATR and i <= E_MATR):
                plaintext = self.find(i)
                if(plaintext is None):
                    out = magic(buffer, out)
                    del(buffer[0:len(buffer)])
                    out.append(i)
                else:
                    app(plaintext)
            else:
                out = magic(buffer, out)
                del(buffer[0:len(buffer)])
                out.append(i)

        return self.restore(magic(buffer, out))

    def decoding(self, raw):
        '''
        decode raw data

        @param bytes raw:    data input
        @return bytes
        '''

        out = bytearray()
        buffer = []
        app = buffer.append
        magic = self._magic_m

        for i in raw:
            if(i >= S_MATR and i <= E_MATR):
                plaintext = self.find(i)
                if(plaintext is None):
                    out = magic(buffer, out)
                    del(buffer[0:len(buffer)])
                    out.append(i)
                else:
                    app(plaintext)
            else:
                out = magic(buffer, out)
                del(buffer[0:len(buffer)])
                out.append(i)

        return self.restore(magic(buffer, out))


a = Vic('ciao', 'E')
r = a.coding(b'ATTACK at DAWN')
print(a.bookmark)
print(r)
a = Vic('ciao', 'D')
print(a.coding(r))
print(a.bookmark)
