'''
Rc class
Created on 10/mar/2014

@link http://en.wikipedia.org/wiki/RC2
@package EncryptoPy
@subpackage modules
@version 0.5
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


class RC(object):
    '''
    wrapper for rc class

    @param string psw:    password
    @param string ivv:    iv
    @param char typ:    'E' for encryption or 'D' for decryption
    @param inter size:    type of module
    @return: object
    '''

    def __init__(self, psw, ivv, typ, size):

        if(size == 2):
            from modules.rc.rc2 import RC2
            cla = RC2(psw, ivv, typ)
        elif(size == 4):
            from modules.rc.rc4 import RC4
            cla = RC4(psw)

        self.coding = cla.coding

