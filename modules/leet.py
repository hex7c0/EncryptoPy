'''
Leet class
Created on 09/mar/2014

@link http://en.wikipedia.org/wiki/Leet
@package EncryptoPy
@subpackage modules
@version 0.5
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


TAB = {
        'A': '@', 'a': '@',
        'B': 'ß', 'b': 'ß',
        'C': '©', 'c': '©',
        'D': 'D', 'd': 'd',
        'E': '€', 'e': '€',
        'F': 'ƒ', 'f': 'ƒ',
        'G': '6', 'g': '6',
        'H': '4', 'h': ' 4',
        'I': '!', 'i': '!',
        'J': 'J', 'j': 'j',
        'K': 'K', 'k': 'k',
        'L': '£', 'l': '£',
        'M': 'M', 'm': 'n',
        'N': 'И', 'n': 'И',
        'O': '0', 'o': '0',
        'P': 'P', 'p': 'p',
        'Q': 'Q', 'q': 'q',
        'R': '®', 'r': '®',
        'S': '$', 's': '$',
        'T': 'T', 't': 't',
        'U': 'Ü', 'u': 'ü',
        'V': 'V', 'v': 'v',
        'W': 'VV', 'w': 'vv',
        'X': '><', 'x': '><',
        'Y': 'Ŷ', 'y': 'ŷ',
        'Z': 'Z', 'z': 'z',
}


class Leet(object):
    '''
    ONLY TEXT
    leet

    @return: object
    '''

    def __init__(self):
        pass

    @staticmethod
    def coding(raw):
        '''
        encrypt function

        @param byte raw:    read file
        @return: byte
        '''

        res = ''

        for ord_x in raw:
            try:
                char = TAB[chr(ord_x)]
                res = '%s%s' % (res, char)
            except KeyError:
                res = '%s%s' % (res, chr(ord_x))

        return res.encode()
