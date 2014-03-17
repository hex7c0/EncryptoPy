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


from modules.polybious import Polybious


class Nihi(object):
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
        cla = Polybious(ivv, psw, typ)
        self.coding = cla.coding
