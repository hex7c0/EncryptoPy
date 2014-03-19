'''
Keccak class
Created on 19/mar/2014

Implementation                Renaud Bauvin
@license http://creativecommons.org/publicdomain/zero/1.0/ CC License
Ported from C by              Laurent Haan (http://www.progressive-coding.com)

@link http://en.wikipedia.org/wiki/SHA-3
@package EncryptoPy
@subpackage modules
@version 0.5
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


from math import log


SPOONGE = 1600
MATRIX = 5


class Hash(object):
    '''
    hash

    @param integer size:        type of hash [224,256,384,512]
    @return object
    '''

    def __init__(self, size):
        self.__typ = size
        self.__increase = self.__typ * 2
        self.__round = SPOONGE - self.__increase

        self.hash = Keccak(SPOONGE)
        self.store = b''
        self.hash.update = self.update
        self.hash.hexdigest = self.hexdigest

    def update(self, raw):
        '''
        update the hash signature

        @param bytes raw:    data
        @return void
        '''

        blob = self.store + raw
        length = len(blob)
        self.store = self.hash.keccak((length, blob), \
                                    self.__round, self.__increase, self.__typ)
        return

    def hexdigest(self):
        '''
        return calculate hash

        @param string
        '''

        if(len(self.store) <= 0):
            self.update(b'')
        return str(self.store)


class Keccak(object):
    '''
    Class implementing the keccak sponge function
    implementation from Renaud, with some 0x7c0 modification

    @param integer b:    [25, 50, 100, 200, 400, 800, 1600]
    '''

    # round constants
    RC = [
            0x0000000000000001,
            0x0000000000008082,
            0x800000000000808A,
            0x8000000080008000,
            0x000000000000808B,
            0x0000000080000001,
            0x8000000080008081,
            0x8000000000008009,
            0x000000000000008A,
            0x0000000000000088,
            0x0000000080008009,
            0x000000008000000A,
            0x000000008000808B,
            0x800000000000008B,
            0x8000000000008089,
            0x8000000000008003,
            0x8000000000008002,
            0x8000000000000080,
            0x000000000000800A,
            0x800000008000000A,
            0x8000000080008081,
            0x8000000000008080,
            0x0000000080000001,
            0x8000000080008008
        ]
    # Rotation offsets
    r = [
            [0, 36, 3, 41, 18],
            [1, 44, 10, 45, 2],
            [62, 6, 43, 15, 61],
            [28, 55, 25, 21, 56],
            [27, 20, 39, 8, 14]
       ]

    def __init__(self, b=SPOONGE):
        # Update all the parameters based on the used value of b
        self.b = self.w = self.l = self.nr = 0
        self.set_b(b)

    def set_b(self, b):
        '''
        Set the value of the parameter b (and thus w,l and nr)

        @param integer b:    [25, 50, 100, 200, 400, 800, 1600]
        '''

        #======================================================================
        # if b not in [25, 50, 100, 200, 400, 800, 1600]:
        #     raise Exception('b value not supported')
        #======================================================================

        # Update all the parameters based on the used value of b
        self.b = b
        self.w = b // 25
        self.l = int(log(self.w, 2))
        self.nr = 12 + 2 * self.l

    def rot(self, x, n):
        '''
        Bitwise rotation (to the left) of n bits considering the
        string of bits is w bits long

        @return bytes
        '''

        n = n % self.w
        return ((x >> (self.w - n)) + (x << n)) % (1 << self.w)

    def round(self, A, RCfixed):
        '''
        Perform one round of computation as defined in the keccak-f permutation

        @param list A:    current state (5x5 matrix)
        @param integer RCfixed:    value of round constant to use
        '''

        # Initialisation of temporary variables
        B = [[0 for i in range(MATRIX)]for j in range(MATRIX)]
        C = [0 for i in range(MATRIX)]
        D = [0 for i in range(MATRIX)]

        # Theta step
        for x in range(MATRIX):
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]

        for x in range(MATRIX):
            D[x] = C[(x - 1) % MATRIX] ^ self.rot(C[(x + 1) % MATRIX], 1)

        for x in range(MATRIX):
            for y in range(MATRIX):
                A[x][y] = A[x][y] ^ D[x]

        # Rho and Pi steps
        for x in range(MATRIX):
            for y in range(MATRIX):
                B[y][(2 * x + 3 * y) % MATRIX] = self.rot(A[x][y], self.r[x][y])

        # Chi step
        for x in range(MATRIX):
            for y in range(MATRIX):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % MATRIX][y]) & B[(x + 2) % MATRIX][y])

        # Iota step
        A[0][0] = A[0][0] ^ RCfixed

        return A

    @staticmethod
    def __from_hex_to_lane(string):
        '''
        Convert a string of bytes written in hexadecimal to a lane value

        @param string string:    input
        @return integer
        '''

        # Check that the string has an even number of characters i.e.
        # whole number of bytes
        #======================================================================
        # if len(string) % 2 != 0:
        #     raise Exception('Provided string does not end with a full byte')
        #======================================================================

        # Perform the modification
        temp = b''
        nrBytes = len(string) // 2
        for i in range(nrBytes):
            offset = (nrBytes - i - 1) * 2
            temp += string[offset:offset + 2]
        # return int(str(temp[1]), 16)
        return int.from_bytes(temp, 'big')

    def __from_lane_to_hex(self, lane):
        '''
        Convert a lane value to a string of bytes written in hexadecimal

        @param integer lane:    value
        @return string
        '''

        laneHexBE = (('%%0%dX' % (self.w // 4)) % lane)
        # Perform the modification
        temp = ''
        nrBytes = len(laneHexBE) // 2
        for i in range(nrBytes):
            offset = (nrBytes - i - 1) * 2
            temp += laneHexBE[offset:offset + 2]
        return temp.upper()

    def _convert_str_to_table(self, string):
        '''
        Convert a string of bytes to its 5x5 matrix representation

        @param string string:    bytes of hex-coded bytes
        @return list
        '''

        # Check that input paramaters
        #======================================================================
        # if(self.w % 8 != 0):
        #     raise Exception('w is not a multiple of 8')
        # if(len(string) != 2 * (self.b) // 8):
        #     raise Exception('string can\'t be divided in 25 blocks of bits')
        #======================================================================

        # Convert
        output = [[0 for i in range(MATRIX)]for j in range(MATRIX)]
        for x in range(MATRIX):
            for y in range(MATRIX):
                offset = 2 * ((MATRIX * y + x) * self.w) // 8
                output[x][y] = self.__from_hex_to_lane(\
                                    string[offset:offset + (2 * self.w // 8)])
        return output

    def _convert_table_to_str(self, table):
        '''
        Convert a 5×5 matrix representation to its string representation

        @param list table:    matrix
        @return string
        '''

        # Check input format
        #======================================================================
        # if(self.w % 8 != 0):
        #     raise Exception('w is not a multiple of 8')
        # if((len(table) != MATRIX) or (False in [len(row) == MATRIX for row in table])):
        #     raise Exception('table must be 5x5')
        #======================================================================

        # Convert
        output = ['' for i in range(MATRIX * MATRIX)]
        for x in range(MATRIX):
            for y in range(MATRIX):
                output[MATRIX * y + x] = self.__from_lane_to_hex(table[x][y])
        output = ''.join(output).upper()
        return output

    @staticmethod
    def pad_10_star1(M, n):
        '''
        Pad M with the pad10*1 padding rule to reach a length multiple of r bit

        @param string M:    message pair (string of hex characters)
        @param integer n:    length in bits (must be a multiple of 8)
        '''

        [my_string_length, my_string] = M

        # Check the parameter n
        #======================================================================
        # if(n % 8 != 0):
        #     raise Exception('n must be a multiple of 8')
        #======================================================================

        # Check the length of the provided string
        if(len(my_string) % 2 != 0):
            # Pad with one '0' to reach correct length (don't know test
            # vectors coding)
            my_string = my_string + b'0'
        #======================================================================
        # if(my_string_length > (len(my_string) // 2 * 8)):
        #     raise Exception('the string is too short to contain \
        #                     the number of bits announced')
        #======================================================================

        nr_bytes_filled = my_string_length // 8
        nbr_bits_filled = my_string_length % 8
        l = my_string_length % n

        if ((n - 8) <= l <= (n - 2)):
            if (nbr_bits_filled == 0):
                my_byte = 0
            else:
                my_byte = int(my_string[nr_bytes_filled * 2:nr_bytes_filled * 2 + 2], 16)
            my_byte = (my_byte >> (8 - nbr_bits_filled))
            my_byte = my_byte + 2 ** (nbr_bits_filled) + 2 ** 7
            my_byte = '%02X' % my_byte
            temp = bytearray(my_string[0:nr_bytes_filled * 2])
            temp.append(int(my_byte))
            my_string = temp
            # my_string = my_string[0:nr_bytes_filled * 2] + my_byte
        else:
            if (nbr_bits_filled == 0):
                my_byte = 0
            else:
                my_byte = int(my_string[nr_bytes_filled * 2:nr_bytes_filled * 2 + 2], 16)
            my_byte = (my_byte >> (8 - nbr_bits_filled))
            my_byte = my_byte + 2 ** (nbr_bits_filled)
            my_byte = '%02X' % my_byte
            temp = bytearray(my_string[0:nr_bytes_filled * 2])
            temp.append(int(my_byte))
            my_string = temp
            # my_string = my_string[0:nr_bytes_filled * 2] + my_byte
            while((8 * len(my_string) // 2) % n < (n - 8)):
                my_string = my_string + b'00'
            my_string = my_string + b'80'

        return my_string

    def keccak_f(self, A):
        '''
        Perform keccak-f function on the state A

        @param list A:    5x5 matrix containing the state
        '''

        for i in range(self.nr):
            # NB: result is truncated to lane size
            A = self.round(A, self.RC[i] % (1 << self.w))

        return A

    def keccak(self, M, r=1024, c=576, n=1024):
        '''
        Compute the keccak[r,c,d] sponge function on message M

        @param string M:    message pair (string of hex characters)
        @param integer r:    bitrate in bits
        @param integer c:    capacity in bits
        @param integer n:    length of output in bits
        @return list
        '''

        # Check the inputs
        #======================================================================
        # if(r < 0) or (r % 8 != 0):
        #     raise Exception('r must be a multiple of 8 in this implementation')
        # if(n % 8 != 0):
        #     raise Exception('outputLength must be a multiple of 8')
        # self.set_b(r + c)
        #======================================================================

        # Compute lane length (in bits)
        # w = (r + c) // 25

        # Initialisation of state
        S = [[0 for i in range(MATRIX)]for j in range(MATRIX)]

        # Padding of messages
        P = self.pad_10_star1(M, r)

        # Absorbing phase
        for i in range((len(P) * 8 // 2) // r):
            Pi = self._convert_str_to_table(P[i * (2 * r // 8):(i + 1) * (2 * r // 8)] + b'00' * (c // 8))

            for y in range(MATRIX):
                for x in range(MATRIX):
                    S[x][y] = S[x][y] ^ Pi[x][y]
            S = self.keccak_f(S)

        # Squeezing phase
        Z = ''
        outputLength = n
        while outputLength > 0:
            string = self._convert_table_to_str(S)
            Z = Z + string[:r * 2 // 8]
            outputLength -= r
            if outputLength > 0:
                S = self.keccak_f(S)

            # NB: done by block of length r, could have to be cut if output
            # Length is not a multiple of r

        return Z[:2 * n // 8]

    @staticmethod
    def print_state(state, info):
        '''
        Print on screen the state of the sponge function preceded by string inf

        @param state:    state of the sponge function
        @param string info:    characters used as identifier
        @return void
        '''

        print('Current value of state: %s' % (info))
        for y in range(MATRIX):
            line = []
            app = line.append
            for x in range(MATRIX):
                app(hex(state[x][y]))
            print('\t%s' % line)
        return
