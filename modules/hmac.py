'''
Hmac class
Created on 17/set/2013

@link http://docs.python.org/3.3/library/hmac.html
@package EncryptoPy
@subpackage modules
@version 0.4
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


from hmac import new


class Hmac(object):
    '''
    hash

    @param string psw:    password
    @return object
    '''

    def __init__(self, psw):
        self.hash = new(psw.encode())
