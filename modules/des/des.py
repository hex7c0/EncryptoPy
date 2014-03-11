'''
Des class
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


# Modes of crypting / cyphering
ECB = 0
CBC = 1
# Modes of padding
PAD_NORMAL = 1
PAD_PKCS5 = 2
# Type of crypting being done
ENCRYPT = 0x00
DECRYPT = 0x01


# PAD_PKCS5: is a method that will unambiguously remove all padding
#            characters after decryption, when originally encrypted with
#            this padding mode.
# For a good description of the PKCS5 padding technique, see:
# http://www.faqs.org/rfcs/rfc1423.html

# The base class shared by des and triple des.
class DesBase(object):
    '''
    Pure python implementation of the DES and TRIPLE DES encryption algorithms.
    pyDes.des(key, [mode], [IV], [pad], [padmode])
    pyDes.triple_des(key, [mode], [IV], [pad], [padmode])

    key -> Bytes containing the encryption key. 8 bytes for DES, 16 or 24 bytes
           for Triple DES
    mode -> Optional argument for encryption type, can be either
            pyDes.ECB or pyDes.CBC
    IV -> Optional Initial Value bytes, must be supplied if using CBC mode.
          Length must be 8 bytes.
    pad -> Optional argument, set the pad character (PAD_NORMAL) to use during
           all encrypt/decrpt operations done with this instance.
    padmode -> Optional argument, set the padding mode(PAD_NORMAL or PAD_PKCS5)
               to use during all encrypt/decrypt operations done with this
               instance.

    I recommend to use PAD_PKCS5 padding, as then you never need to worry about
    any padding issues, as the padding can be removed unambiguously upon
    decrypting data that was encrypted using PAD_PKCS5 padmode.

    encrypt(data, [pad], [padmode])
    decrypt(data, [pad], [padmode])

    data    -> Bytes to be encrypted/decrypted
    pad     -> Optional argument. Only when using padmode of PAD_NORMAL. For
             encryption, adds this characters to the end of the data block when
             data is not a multiple of 8 bytes. For decryption, will remove the
             trailing characters that match this pad character from the last 8
             bytes of the unencrypted data block.
    padmode -> Optional argument, set the padding mode, must be one of
               PAD_NORMAL or PAD_PKCS5). Defaults to PAD_NORMAL.

    data = 'Please encrypt my data'
    k = des('DESCRYPT', CBC, '\0\0\0\0\0\0\0\0', \
            pad=None, padmode=PAD_PKCS5)
    # For Python3, you'll need to use bytes, i.e.:
    #   data = b'Please encrypt my data'
    #   k = des(b'DESCRYPT', CBC, b'\0\0\0\0\0\0\0\0', \
    #           pad=None, padmode=PAD_PKCS5)
    d = k.encrypt(data)
    print 'Encrypted: %r' % d
    print 'Decrypted: %r' % k.decrypt(d)
    assert k.decrypt(d, padmode=PAD_PKCS5) == data
    '''

    def __init__(self, mode=ECB, IV=None, pad=None, padmode=PAD_NORMAL):
        if IV:
            IV = self._guard_against_unicode(IV)
        if pad:
            pad = self._guard_against_unicode(pad)
        self.block_size = 8
        # Sanity checking of arguments.
        if(pad and padmode == PAD_PKCS5):
            raise ValueError('Cannot use a pad character with PAD_PKCS5')
        if(IV and len(IV) != self.block_size):
            raise ValueError('Invalid Initial Value, must be a multiple of ' \
                              + str(self.block_size) + ' bytes')

        # Set the passed in variables
        self.__key = None
        self._mode = mode
        self._iv = IV
        self._padding = pad
        self._padmode = padmode

    def get_key(self):
        '''
        get_key() -> bytes
        '''

        return self.__key

    def set_key(self, key):
        '''
        Will set the crypting key for this object.
        '''

        key = self._guard_against_unicode(key)
        self.__key = key

    def get_mode(self):
        '''get_mode() -> pyDes.ECB or pyDes.CBC'''
        return self._mode

    def set_mode(self, mode):
        '''
        Sets the type of crypting mode, pyDes.ECB or pyDes.CBC
        '''

        self._mode = mode

    def get_padding(self):
        '''
        get_padding() -> bytes of length 1. Padding character.
        '''

        return self._padding

    def set_padding(self, pad):
        '''
        set_padding() -> bytes of length 1. Padding character.
        '''

        if(pad is not None):
            pad = self._guard_against_unicode(pad)
        self._padding = pad

    def get_pad_mode(self):
        '''
        get_pad_mode() -> pyDes.PAD_NORMAL or pyDes.PAD_PKCS5
        '''

        return self._padmode

    def set_pad_mode(self, mode):
        '''
        Sets the type of padding mode, pyDes.PAD_NORMAL or pyDes.PAD_PKCS5
        '''

        self._padmode = mode

    def get_iv(self):
        '''
        get_iv() -> bytes
        '''

        return self._iv

    def set_iv(self, IV):
        '''
        Will set the Initial Value, used in conjunction with CBC mode
        '''

        if not IV or len(IV) != self.block_size:
            raise ValueError('Invalid Initial Value, must be a multiple of ' \
                             + str(self.block_size) + ' bytes')
        IV = self._guard_against_unicode(IV)
        self._iv = IV

    def _pad_data(self, data, pad, padmode):
        '''
        Pad data depending on the mode
        '''

        if(padmode is None):
            # Get the default padding mode.
            padmode = self.get_pad_mode()
        if(pad and padmode == PAD_PKCS5):
            raise ValueError('Cannot use a pad character with PAD_PKCS5')

        if(padmode == PAD_NORMAL):
            if len(data) % self.block_size == 0:
                # No padding required.
                return data

            if not pad:
                # Get the default padding.
                pad = self.get_padding()
            if not pad:
                raise ValueError('Data must be a multiple of ' + \
                                 str(self.block_size) + \
                                 ' bytes in length.')
            data += (self.block_size - (len(data) % self.block_size)) * pad

        elif padmode == PAD_PKCS5:
            pad_len = 8 - (len(data) % self.block_size)
            data += bytes([pad_len] * pad_len)

        return data

    def _unpad_data(self, data, pad, padmode):
        '''
        Unpad data depending on the mode.
        '''

        if(not data):
            return data
        if(pad and padmode == PAD_PKCS5):
            raise ValueError('Cannot use a pad character with PAD_PKCS5')
        if(padmode is None):
            # Get the default padding mode.
            padmode = self.get_pad_mode()

        if(padmode == PAD_NORMAL):
            if not pad:
                # Get the default padding.
                pad = self.get_padding()
            if pad:
                data = data[:-self.block_size] + \
                       data[-self.block_size:].rstrip(pad)

        elif padmode == PAD_PKCS5:
            pad_len = data[-1]
            data = data[:-pad_len]

        return data

    @staticmethod
    def _guard_against_unicode(data):
        '''
        Only accept byte strings or ascii unicode values, otherwise
        there is no way to correctly decode the data into bytes.
        '''

        if isinstance(data, str):
            # Only accept ascii unicode values.
            try:
                return data.encode('ascii')
            except UnicodeEncodeError:
                pass
            raise ValueError('pyDes can only work with encoded strings.')

        return data


class Des(object):
    '''
    wrapper for des and triple_des class

    @param string psw:    password
    @param string ivv:    iv
    @param char typ:    'E' for encryption or 'D' for decryption
    @param integet size:    for encryption module
    '''

    def __init__(self, psw, ivv, typ, size):
        if(size == 24):
            from modules.des.des3 import Des3
            cla = Des3(psw[2:size + 2], CBC, ivv)
        else:
            from modules.des.des1 import Des1
            cla = Des1(psw[2:size + 2], CBC, ivv)

        if(typ == 'E'):
            self.coding = cla.encrypt
        else:
            self.coding = cla.decrypt
