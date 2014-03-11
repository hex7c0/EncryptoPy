'''
Des3 class
Created on 10/set/2013

From the pyDes project, http://twhiteman.netfirms.com/des.html
Author                        Todd Whiteman
@license: Public Domain - free to do as you wish

@link http://en.wikipedia.org/wiki/Data_Encryption_Standard
@package EncryptoPy
@subpackage modules
@version 0.4
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


try:
    from modules.des.des import DesBase, CBC, ECB, \
                                PAD_NORMAL, PAD_PKCS5, ENCRYPT, DECRYPT
    from modules.des.des1 import Des1
except ImportError:
    raise Exception


class Des3(DesBase):
    '''
    Triple DES encryption/decrytpion class

    This algorithm uses the DES-EDE3 (when a 24 byte key is supplied) or
    the DES-EDE2 (when a 16 byte key is supplied) encryption methods.
    Supports ECB (Electronic Code Book) and CBC (Cypher Block Chaining) modes.

    pyDes.des(key, [mode], [IV])

    key  -> Bytes containing the encryption key, must be either 16 or
            24 bytes long
    mode -> Optional argument for encryption type, can be either pyDes.ECB
        (Electronic Code Book), pyDes.CBC (Cypher Block Chaining)
    IV   -> Optional Initial Value bytes, must be supplied if using CBC mode.
        Must be 8 bytes in length.
    pad  -> Optional argument, set the pad character (PAD_NORMAL) to use
        during all encrypt/decrpt operations done with this instance.
    padmode -> Optional argument, set the padding mode (PAD_NORMAL or
        PAD_PKCS5) to use during all encrypt/decrpt operations done
        with this instance.
    '''

    def __init__(self, key, mode=ECB, IV=None, pad=None, padmode=PAD_NORMAL):
        DesBase.__init__(self, mode, IV, pad, padmode)
        self.set_key(key)

    def set_key(self, key):
        '''
        Will set the crypting key for this object. Either 16 or 24 bytes long.
        '''

        self.key_size = 24    # Use DES-EDE3 mode
        if len(key) != self.key_size:
            if len(key) == 16:    # Use DES-EDE2 mode
                self.key_size = 16
            else:
                raise ValueError('Key must be either 16 or 24 bytes long.')
        if self.get_mode() == CBC:
            if not self.get_iv():
                # Use the first 8 bytes of the key
                self._iv = key[:self.block_size]
            if len(self.get_iv()) != self.block_size:
                raise ValueError('Invalid IV, must be 8 bytes in length')
        self.__key1 = Des1(key[:8], self._mode, self._iv,
                  self._padding, self._padmode)
        self.__key2 = Des1(key[8:16], self._mode, self._iv,
                  self._padding, self._padmode)
        if self.key_size == 16:
            self.__key3 = self.__key1
        else:
            self.__key3 = Des1(key[16:], self._mode, self._iv,
                      self._padding, self._padmode)
        DesBase.set_key(self, key)

        return

    def set_mode(self, mode):
        '''
        Sets the type of crypting mode, pyDes.ECB or pyDes.CBC
        '''

        DesBase.set_mode(self, mode)
        for key in (self.__key1, self.__key2, self.__key3):
            key.set_mode(mode)
        return

    def set_padding(self, pad):
        '''
        set_padding() -> bytes of length 1. Padding character.
        '''

        DesBase.set_padding(self, pad)
        for key in (self.__key1, self.__key2, self.__key3):
            key.set_padding(pad)
        return

    def set_pad_mode(self, mode):
        '''
        Sets the type of padding mode, pyDes.PAD_NORMAL or pyDes.PAD_PKCS5
        '''

        DesBase.set_pad_mode(self, mode)
        for key in (self.__key1, self.__key2, self.__key3):
            key.set_pad_mode(mode)
        return

    def set_iv(self, IV):
        '''
        Will set the Initial Value, used in conjunction with CBC mode
        '''

        DesBase.set_iv(self, IV)
        for key in (self.__key1, self.__key2, self.__key3):
            key.set_iv(IV)
        return

    def encrypt(self, data, pad=None, padmode=PAD_PKCS5):
        '''
        encrypt(data, [pad], [padmode]) -> bytes

        data : bytes to be encrypted
        pad  : Optional argument for encryption padding. Must only be one byte
        padmode : Optional argument for overriding the padding mode.

        The data must be a multiple of 8 bytes and will be encrypted
        with the already specified key. Data does not have to be a
        multiple of 8 bytes if the padding character is supplied, or
        the padmode is set to PAD_PKCS5, as bytes will then added to
        ensure the be padded data is a multiple of 8 bytes.
        '''

        data = self._guard_against_unicode(data)
        if pad is not None:
            pad = self._guard_against_unicode(pad)
        # Pad the data accordingly.
        data = self._pad_data(data, pad, padmode)
        if self.get_mode() == CBC:
            self.__key1.set_iv(self.get_iv())
            self.__key2.set_iv(self.get_iv())
            self.__key3.set_iv(self.get_iv())
            i = 0
            result = []
            while i < len(data):
                block = self.__key1.crypt(data[i:i + 8], ENCRYPT)
                block = self.__key2.crypt(block, DECRYPT)
                block = self.__key3.crypt(block, ENCRYPT)
                self.__key1.set_iv(block)
                self.__key2.set_iv(block)
                self.__key3.set_iv(block)
                result.append(block)
                i += 8
            return bytes.fromhex('').join(result)
        else:
            data = self.__key1.crypt(data, ENCRYPT)
            data = self.__key2.crypt(data, DECRYPT)
            return self.__key3.crypt(data, ENCRYPT)

    def decrypt(self, data, pad=None, padmode=PAD_PKCS5):
        '''
        decrypt(data, [pad], [padmode]) -> bytes

        data : bytes to be encrypted
        pad  : Optional argument for decryption padding. Must only be one byte
        padmode : Optional argument for overriding the padding mode.

        The data must be a multiple of 8 bytes and will be decrypted
        with the already specified key. In PAD_NORMAL mode, if the
        optional padding character is supplied, then the un-encrypted
        data will have the padding characters removed from the end of
        the bytes. This pad removal only occurs on the last 8 bytes of
        the data (last data block). In PAD_PKCS5 mode, the special
        padding end markers will be removed from the data after
        decrypting, no pad character is required for PAD_PKCS5.
        '''

        data = self._guard_against_unicode(data)
        if pad is not None:
            pad = self._guard_against_unicode(pad)
        if self.get_mode() == CBC:
            self.__key1.set_iv(self.get_iv())
            self.__key2.set_iv(self.get_iv())
            self.__key3.set_iv(self.get_iv())
            i = 0
            result = []
            while i < len(data):
                iv = data[i:i + 8]
                block = self.__key3.crypt(iv, DECRYPT)
                block = self.__key2.crypt(block, ENCRYPT)
                block = self.__key1.crypt(block, DECRYPT)
                self.__key1.set_iv(iv)
                self.__key2.set_iv(iv)
                self.__key3.set_iv(iv)
                result.append(block)
                i += 8
            data = bytes.fromhex('').join(result)
        else:
            data = self.__key3.crypt(data, DECRYPT)
            data = self.__key2.crypt(data, ENCRYPT)
            data = self.__key1.crypt(data, DECRYPT)
        return self._unpad_data(data, pad, padmode)
