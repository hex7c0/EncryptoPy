'''
Hash class
Created on 17/set/2013

@link http://docs.python.org/3.3/library/hashlib.html
@package EncryptoPy
@subpackage modules
@version 0.5
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


from hashlib import new


class Hash(object):
    '''
    hash

    @param integer size:        type of hash [0,1,3,4,5,160,224,256,384,512]
    @return object
    '''

    def __init__(self, size):
        if(size == 0):    # sha0
            self.hash = new('SHA')
        elif(size == 1):    # dsa
            self.hash = new('SHA1')
        elif(size == 3):    # dsa
            self.hash = new('DSA')
        elif(size == 4):
            self.hash = new('MD4')
        elif(size == 160):    # ripemd
            self.hash = new('RIPEMD160')
        elif(size == 224):    # sha2
            self.hash = new('SHA224')
        elif(size == 256):
            self.hash = new('SHA256')
        elif(size == 384):
            self.hash = new('SHA384')
        elif(size == 512):
            self.hash = new('SHA512')
        else:    # md5
            self.hash = new('MD5')
