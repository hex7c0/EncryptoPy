'''
Playfair class
Created on 17/set/2013

@link http://en.wikipedia.org/wiki/Playfair_cipher
@package EncryptoPy
@subpackage modules
@version 0.5
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


from string import ascii_letters, digits
from base64 import b64encode
from collections import defaultdict


MATRIX = 8
LIMIT_E = MATRIX - 1
LIMIT_D = MATRIX - MATRIX
EXCEPT = 255
EXCEPT2 = 5


class Playfair(object):
    '''
    ONLY TEXT
    playfair

    @param string key:    password
    @return: object
    '''

    def __init__(self, psw):
        self.key = [[0 for i in range(MATRIX)]for j in range(MATRIX)]
        self.__build_ciph(psw)
        self.store = self.__build_dict()

    def encrypt(self, raw):
        '''
        encrypt function

        @param byte raw:    read file
        @return: byte
        '''

        temp = bytearray()
        app = temp.append
        data = self.__build_dig(raw)    # first step

        for ally in range(len(data)):
            x1 = x2 = False    # out range
            # fast operation
            if(data[ally][0] in self.store):
                x1 = [self.store[data[ally][0]][0], \
                      self.store[data[ally][0]][1]]
            if(data[ally][1] in self.store):
                x2 = [self.store[data[ally][1]][0], \
                      self.store[data[ally][1]][1]]

            if(not x1 or not x2):    # not found -> NORMAL
                app(data[ally][0])
                app(data[ally][1])

            elif(x1[0] == x2[0]):    # row
                # element shift right -> SHIFT Y
                if((x1[1] + 1) > LIMIT_E):    # first
                    app(self.key[x1[0]][LIMIT_D])
                else:
                    app(self.key[x1[0]][(x1[1]) + 1])    # same row (X)
                if((x2[1] + 1) > LIMIT_E):    # second
                    app(self.key[x1[0]][LIMIT_D])
                else:
                    app(self.key[x1[0]][(x2[1]) + 1])    # same row (X)

            elif(x1[1] == x2[1]):    # column
                # element shift down -> SHIFT X
                if((x1[0] + 1) > LIMIT_E):    # first
                    app(self.key[LIMIT_D][x1[1]])
                else:
                    app(self.key[(x1[0] + 1)][x1[1]])    # same column (Y)
                if((x2[0] + 1) > LIMIT_E):    # second
                    app(self.key[LIMIT_D][x1[1]])
                else:
                    app(self.key[(x2[0] + 1)][x1[1]])    # same column (Y)

            else:    # square
                app(self.key[(x1[0])][x2[1]])    # same row, opposite column
                app(self.key[(x2[0])][x1[1]])    # same row, opposite column

        return temp

    def decrypt(self, raw):
        '''
        decrypt function

        @param byte raw:    read file
        @return: byte
        '''

        temp = []
        app = temp.append
        data = self.__build_dig(raw)    # first step

        for ally in range(len(data)):
            x1 = x2 = False    # out range
            # fast operation
            if(data[ally][0] in self.store):
                x1 = [self.store[data[ally][0]][0], \
                      self.store[data[ally][0]][1]]
            if(data[ally][1] in self.store):
                x2 = [self.store[data[ally][1]][0], \
                      self.store[data[ally][1]][1]]

            #==================================================================
            # for i in range( MATRIX ):
            #     for j in range( MATRIX ):
            #         if( data[ally][0] == self.key[i][j] ):    # first
            #             x1 = [ i, j ]
            #         if( data[ally][1] == self.key[i][j] ):    # second
            #             x2 = [ i, j ]
            #         if( x1 and x2 ):break;    # save time
            #     if( x1 and x2 ):break;    # save time
            #==================================================================

            if(not x1 or not x2):    # not found
                app([data[ally][0], data[ally][1]])    # normal

            elif(x1[0] == x2[0]):    # row
                buffer = []
                app2 = buffer.append
                # element shift left -> SHIFT Y
                if((x1[1] - 1) < LIMIT_D):    # first
                    app2(self.key[x1[0]][LIMIT_E])
                else:
                    app2(self.key[x1[0]][(x1[1]) - 1])    # same row (X)
                if((x2[1] - 1) < LIMIT_D):    # second
                    app2(self.key[x1[0]][LIMIT_E])
                else:
                    app2(self.key[x1[0]][(x2[1]) - 1])    # same row (X)
                app(buffer)

            elif(x1[1] == x2[1]):    # column
                buffer = []
                app2 = buffer.append
                # element shift up -> SHIFT X
                if((x1[0] - 1) < LIMIT_D):    # first
                    app2(self.key[LIMIT_E][x1[1]])
                else:
                    app2(self.key[(x1[0] - 1)][x1[1]])    # same column (Y)
                if((x2[0] - 1) < LIMIT_D):    # second
                    app2(self.key[LIMIT_E][x1[1]])
                else:
                    app2(self.key[(x2[0] - 1)][x1[1]])    # same column (Y)
                app(buffer)

            else:    # square
                app([self.key[(x1[0])][x2[1]], \
                     self.key[(x2[0])][x1[1]]])    # same row,opposite column

        return self.rebuild(temp)

    @staticmethod
    def rebuild(arr):
        '''
        rebuild original message
        because on original we've use '0'
        for duplicate letters or single char

        @param list arr    result of decrypt 2D
        @return: byte
        '''

        temp = bytearray()
        app = temp.append

        for i in range(len(arr)):
            if(arr[i][1] == EXCEPT or arr[i][1] == EXCEPT2):
                before = False
                after = True
                try:
                    before = arr[i][0]    # if first string
                except IndexError:
                    before = False
                else:
                    try:
                        after = arr[i + 1][0]
                    except IndexError:
                        after = False

                # EXCEPT char for divide same letters
                if(arr[i][1] == EXCEPT and type(before) != bool and before == after):
                    app(arr[i][0])
                # exception of exception :)
                elif(arr[i][1] == EXCEPT2 and type(before) != bool and before == after == EXCEPT):
                    app(arr[i][0])
                # last element
                elif(before and not after and (i + 1) >= len(arr)):
                    app(arr[i][0])
                # false positive
                else:
                    app(arr[i][0])
                    app(arr[i][1])
            else:
                app(arr[i][0])
                app(arr[i][1])

        return temp

    def __build_dict(self):
        '''
        build a dictionary for fast view

        @return: dict'''

        cache = defaultdict(list)
        for i in range(MATRIX):
            for j in range(MATRIX):
                cache[self.key[i][j]].append(i)
                cache[self.key[i][j]].append(j)
        return cache

    def __build_ciph(self, key):
        '''
        build key matrix with A-Za-z0-9.
        see the wiki for the build of this chiper.
        It's different from wiki, I've insert all base64 char (except '=')
        for a 8x8 matrix with more char hit.
        I haven't built the multidimensional array (table[][])
        due to the limits of Python (not NumPy)

        @param string key    hash of password
        @return: void
        '''

        alpha = ascii_letters + digits + '+/'
        a = point = 0
        tmp = []    # temporary list
        app = tmp.append

        # strip same char
        key = b64encode(key.encode())
        key = key.decode()
        key = ''.join(sorted(set(key), key=key.index))

        # add more different random char
        for i in range(MATRIX * MATRIX):
            try:
                char = key[i]
            except IndexError:
                char = '/'
            if(char not in tmp and char != '='):
                app(char)
            else:    # already set
                for r in range(point, len(alpha)):
                    if(alpha[r] not in tmp):
                        app(alpha[r])
                        point = r    # set bookmark
                        break

        # build multidimensional array
        for i in range(MATRIX):
            for j in range(MATRIX):
                self.key[i][j] = ord(tmp[a])
                a += 1

        return

    @staticmethod
    def __build_dig(raw):
        '''
        build 2D matrix with bytes of text
        see the wiki for the build of this digraphs

        @param byte raw:    read file
        @return: list
        '''

        digrafo = []
        app = digrafo.append
        a = 0

        for i in range(len(raw)):
            # not 'int( len( raw ) / 2 )' because
            # with shift elements, can lost some elements
            if(a >= len(raw)):
                break
            first = raw[a]
            # last element, put EXCEPT char
            try:
                second = raw[a + 1]
            except IndexError:
                second = EXCEPT
            if(first != second):
                app([first, second])
                a += 2
            else:    # equal
                # shift second element, and add EXCEPT char
                if(second == EXCEPT):
                    # exception of exception :)
                    app([first, EXCEPT2])
                else:
                    app([first, EXCEPT])
                a += 1
        return digrafo
