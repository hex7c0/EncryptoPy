'''
Morse class
Created on 09/mar/2014

@link http://en.wikipedia.org/wiki/Morse_code
@package EncryptoPy
@subpackage modules
@version 0.4
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


from string import ascii_letters, ascii_uppercase, digits


EXCEPT = '\x01'
EXCEPT2 = '\x02'
PTECXE = ord(EXCEPT)
PTECXE2 = ord(EXCEPT2)
ALPHA = ascii_letters + digits + "+,.?;:'-/()_ +="
UPPER = ascii_uppercase
TAB = {
        'A': '.-', 'a': '.-',
        'B': '-...', 'b': '-...',
        'C': '-.-.', 'c': '-.-.',
        'D': '-..', 'd': '-..',
        'E': '.', 'e': '.',
        'F': '..-.', 'f': '..-.',
        'G': '--.', 'g': '--.',
        'H': '....', 'h': '....',
        'I': '..', 'i': '..',
        'J': '.---', 'j': '.---',
        'K': '-.-', 'k': '-.-',
        'L': '.-..', 'l': '.-..',
        'M': '--', 'm': '--',
        'N': '-.', 'n': '-.',
        'O': '---', 'o': '---',
        'P': '.--.', 'p': '.--.',
        'Q': '--.-', 'q': '--.-',
        'R': '.-.', 'r': '.-.',
        'S': '...', 's': '...',
        'T': '-', 't': '-',
        'U': '..-', 'u': '..-',
        'V': '...-', 'v': '...-',
        'W': '.--', 'w': '.--',
        'X': '-..-', 'x': '-..-',
        'Y': '-.--', 'y': '-.--',
        'Z': '--..', 'z': '--..',
        '0': '-----', ',': '--..--',
        '1': '.----', '.': '.-.-.-',
        '2': '..---', '?': '..--..',
        '3': '...--', ';': '-.-.-.',
        '4': '....-', ':': '---...',
        '5': '.....', "'": '.----.',
        '6': '-....', '-': '-....-',
        '7': '--...', '/': '-..-.',
        '8': '---..', '(': '-.--.-',
        '9': '----.', ')': '-.--.-',
        ' ': ' ', '_': '..--.-',
        '+': '.-.-.', '=': '-...-',
}
BAT = {
        '.-': 'a',
        '-...': 'b',
        '-.-.': 'c',
        '-..': 'd',
        '.': 'e',
        '..-.': 'f',
        '--.': 'g',
        '....': 'h',
        '..': 'i',
        '.---': 'j',
        '-.-': 'k',
        '.-..': 'l',
        '--': 'm',
        '-.': 'n',
        '---': 'o',
        '.--.': 'p',
        '--.-': 'q',
        '.-.': 'r',
        '...': 's',
        '-': 't',
        '..-': 'u',
        '...-': 'v',
        '.--': 'w',
        '-..-': 'z',
        '-.--': 'y',
        '--..': 'z',
        '-----': '0', '--..--': ',',
        '.----': '1',  '.-.-.-': '.',
        '..---': '2', '..--..': '?',
        '...--': '3', '-.-.-.': ';',
        '....-': '4', '---...': ':',
        '.....': '5', '.----.': "'",
        '-....': '6', '-....-': '-',
        '--...': '7', '-..-.': '/',
        '---..': '8', '-.--.-': '(',
        '----.': '9', '-.--.-': ')',
        ' ': ' ', '..--.-': '_',
        '.-.-.': '+', '-...-': '=',
}


class Morse(object):
    '''
    ONLY TEXT
    morse

    @return: object
    '''

    def __init__(self):
        pass

    @staticmethod
    def encrypt(raw):
        '''
        encrypt function

        @param byte raw:    read file
        @return: byte
        '''

        res = ''

        for ord_x in raw:
            try:
                char = TAB[chr(ord_x)]
                if(chr(ord_x) in UPPER):
                    char = '%c%s' % (EXCEPT2, char)
                res = '%s%s%c' % (res, char, EXCEPT)
            except KeyError:
                res = '%s%s' % (res, chr(ord_x))

        return res.encode()

    @staticmethod
    def decrypt(raw):
        '''
        decrypt function function

        @param byte raw        read file
        @return: byte
        '''

        phr = res = ''
        upper = False

        for ord_x in raw:
            if(ord_x == PTECXE2):
                upper = True
            elif(ord_x == PTECXE):
                try:
                    char = BAT[phr]
                    if(upper):
                        char = char.upper()
                        upper = False
                    res = '%s%s' % (res, char)
                except KeyError:
                    res = '%s%s' % (res, phr)
                phr = ''
            elif(chr(ord_x) in ALPHA):
                phr = '%s%s' % (phr, chr(ord_x))
            else:
                res = '%s%s' % (res, chr(ord_x))

        return res.encode()
