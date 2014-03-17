'''
Process classes
Created on 20/set/2013

@package EncryptoPy
@subpackage module
@version 0.4
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


from queue import Empty
from multiprocessing import Process
from pickle import loads, dumps
from core.utility import u_ut_iv


TIMEOUT = 1
CBC = 1
IV_S = 5
IV_E = 15


class AesCrypto(Process):
    '''
    wrapper class for encoding with aes encryption

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que
        self.boool = self.info[2][0] == 'E'

        f_iv = 'iv_%s' % info[5][IV_S:IV_E]
        if(who == 0 and self.boool):    # first proc
            self.ivv = u_ut_iv(info[1])
            with open(f_iv, 'wb') as file:
                file.write(dumps(self.ivv))
        else:
            try:
                with open(f_iv, 'rb') as file:
                    self.ivv = loads(file.read())
            except FileNotFoundError:
                pass

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.aes import AESModeOfOperation, make_hex
            gett = self.que[0].get    # read
            putt = self.que[1].put_nowait    # write
            crypto = AESModeOfOperation()
            if(self.boool):
                code = crypto.encrypt
            else:
                code = crypto.decrypt
            hexx = make_hex(self.info[0], self.info[1])
            size = self.info[1]
            ivv = self.ivv

            while True:
                # data from read
                data, seq = gett()
                if(not data):
                    break
                if(self.boool):
                    ciph = code(data, CBC, hexx, size, ivv)
                else:
                    ciph = code(data, None, CBC, hexx, size, ivv)
                putt((ciph, seq))

            self.que[0].cancel_join_thread()
            self.que[1].close()
        except Empty:
            pass
        except ImportError:
            pass
        except AttributeError:    # no selv.if
            self.que[1].put_nowait((False, 0))
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return


class DesCrypto(Process):
    '''
    wrapper class for encoding with des encryption

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

        f_iv = 'iv_%s' % info[5][IV_S:IV_E]
        if(who == 0 and self.info[2][0] == 'E'):    # first proc
            self.ivv = u_ut_iv(info[1], 'S')
            with open(f_iv, 'wb') as file:
                file.write(dumps(self.ivv))
        else:
            try:
                with open(f_iv, 'rb') as file:
                    self.ivv = loads(file.read())
            except FileNotFoundError:
                pass

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.des.des import Des
            gett = self.que[0].get    # read
            putt = self.que[1].put_nowait    # write
            crypto = Des(self.info[0], self.ivv, self.info[2][0], self.info[1])
            code = crypto.coding

            while True:
                # data from read
                data, seq = gett()
                if(not data):
                    break
                putt((code(data), seq))

            self.que[0].cancel_join_thread()
            self.que[1].close()
        except Empty:
            pass
        except ImportError:
            pass
        except AttributeError:    # no selv.if
            self.que[1].put_nowait((False, 0))
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return


class BasCrypto(Process):
    '''
    wrapper class for encoding with base

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.base import Base
            crypto = Base(self.info[1], self.info[2][0])
            gett = self.que[0].get    # read
            putt = self.que[1].put_nowait    # write
            code = crypto.coding

            while True:
                # data from read
                data, seq = gett(timeout=TIMEOUT)
                if(not data):
                    break
                putt((code(data), seq))

            self.que[0].cancel_join_thread()
            self.que[1].close()
        except Empty:
            pass
        except ImportError:
            pass
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return


class XorCrypto(Process):
    '''
    wrapper class for encoding with xor encryption

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.xor import Xor
            gett = self.que[0].get    # read
            putt = self.que[1].put_nowait    # write
            crypto = Xor(self.info[0])
            code = crypto.coding

            while True:
                # data from read
                data, seq = gett(timeout=TIMEOUT)
                if(not data):
                    break
                putt((code(data), seq))

            self.que[0].cancel_join_thread()
            self.que[1].close()

        except Empty:
            pass
        except ImportError:
            pass
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return


class HasCrypto(Process):
    '''
    wrapper class for encoding with hash

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.hash import Hash
            gett = self.que[0].get    # read
            crypto = Hash(self.info[1])
            code = crypto.hash.update

            while True:
                # data from read
                data = gett(timeout=TIMEOUT)
                if(not data[0]):
                    break
                code(data[0])

            print(crypto.hash.hexdigest())
            self.que[0].cancel_join_thread()
            self.que[1].close()
            self.que[1].cancel_join_thread()
        except Empty:
            pass
        except ImportError:
            pass
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return


class MacCrypto(Process):
    '''
    wrapper class for encoding with hmac

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.hmac import Hmac
            gett = self.que[0].get    # read
            crypto = Hmac(self.info[0])
            code = crypto.hash.update

            while True:
                # data from read
                data = gett(timeout=TIMEOUT)
                if(not data[0]):
                    break
                code(data[0])

            print(crypto.hash.hexdigest())
            self.que[0].cancel_join_thread()
            self.que[1].close()
            self.que[1].cancel_join_thread()
        except Empty:
            pass
        except ImportError:
            pass
        except KeyboardInterrupt:    # Ctrl + C
            pass


class CrcCrypto(Process):
    '''
    wrapper class for encoding with crc

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.crc import Crc
            gett = self.que[0].get    # read
            crypto = Crc(self.info[1])
            code = crypto.update

            while True:
                # data from read
                data = gett(timeout=TIMEOUT)
                if(not data[0]):
                    break
                code(data[0])

            print(crypto.hexdigest())
            self.que[0].cancel_join_thread()
            self.que[1].close()
            self.que[1].cancel_join_thread()
        except Empty:
            pass
        except ImportError:
            pass
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return


class VigCrypto(Process):
    '''
    wrapper class for encoding with vigenère

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.vigenere import Vigenere
            gett = self.que[0].get    # read
            putt = self.que[1].put_nowait    # write
            crypto = Vigenere(self.info[0])
            if(self.info[2][0] == 'E'):
                code = crypto.encrypt
            else:
                code = crypto.decrypt

            while True:
                # data from read
                data, seq = gett()
                if(not data):
                    break
                putt((code(data), seq))

            self.que[0].cancel_join_thread()
            self.que[1].close()
        except Empty:
            pass
        except ImportError:
            pass
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return


class PlaCrypto(Process):
    '''
    wrapper class for encoding with playfair

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.playfair import Playfair
            gett = self.que[0].get    # read
            putt = self.que[1].put_nowait    # write
            crypto = Playfair(self.info[0])
            if(self.info[2][0] == 'E'):
                code = crypto.encrypt
            else:
                code = crypto.decrypt

            while True:
                # data from read
                data, seq = gett()
                if(not data):
                    break
                putt((code(data), seq))

            self.que[0].cancel_join_thread()
            self.que[1].close()
        except Empty:
            pass
        except ImportError:
            pass
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return


class CaeCrypto(Process):
    '''
    wrapper class for encoding with caesar

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.caesar import Caesar
            gett = self.que[0].get    # read
            putt = self.que[1].put_nowait    # write
            crypto = Caesar(self.info[1])
            if(self.info[2][0] == 'E'):
                code = crypto.encrypt
            else:
                code = crypto.decrypt

            while True:
                # data from read
                data, seq = gett()
                if(not data):
                    break
                putt((code(data), seq))

            self.que[0].cancel_join_thread()
            self.que[1].close()
        except Empty:
            pass
        except ImportError:
            pass
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return


#==============================================================================
# class BloCrypto(Process):
#     '''
#     wrapper class for encoding with blowfish
#
#     # inside info
#     string psw    user password
#     int size    for encryption module
#     char action    'E' for encryption or 'D' for decryption
#     char typ    type of encryption module
#     integer proc    number of process for crypto
#     string ash    header hash
#
#     # inside que
#     queue    queue for read data
#     queue    queue for write data
#
#     @param integer who:    number of process
#     @param tuple info:    see above
#     @param list que:    see above
#     @return object
#     '''
#
#     def __init__(self, who, info, que):
#         Process.__init__(self)
#         self.info = info
#         self.que = que
#
#     def run(self):
#         '''
#         start process
#
#         @return void
#         '''
#
#         try:
#             from modules.blowfish import Blowfish
#             self.crypto = Blowfish(self.info[0])
#             gett = self.que[0].get    # read
#             putt = self.que[1].put_nowait    # write
#
#             temp = bytearray()
#             app = temp.append
#             rev = dat = ''
#
#             if(self.info[2][0] == 'E'):
#                 code = self.crypto.encrypt
#                 while True:
#                     # data from read
#                     data, seq = gett()
#                     if(not data):
#                         break
#                     for ord_i in data:
#                         app(ord_i)
#                         if(len(temp) == 8):
#                             dat += code(temp)
#                             del temp[0:8]
#
#                     putt((dat.encode(), seq))
#                     dat = ''
#
#             else:
#                 code = self.crypto.decrypt
#                 while True:
#                     # data from read
#                     data, seq = gett()
#                     if(not data):
#                         break
#                     for ord_i in data:
#                         rev += chr(ord_i)
#                         if(len(rev) == 8):
#                             dat += code(rev)
#                             rev = ''
#
#                     for ord_i in dat:
#                         app(ord(ord_i))
#                     print(len(temp))
#                     putt((temp, seq))
#                     dat = ''
#                     del temp[0:len(temp)]
#
#             self.que[0].cancel_join_thread()
#             self.que[1].close()
#         except Empty:
#             pass
#         except ImportError:
#             pass
#         except KeyboardInterrupt:    # Ctrl + C
#             pass
#
#         return
#==============================================================================


class MorCrypto(Process):
    '''
    wrapper class for encoding with morse

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.morse import Morse
            gett = self.que[0].get    # read
            putt = self.que[1].put_nowait    # write
            crypto = Morse()
            if(self.info[2][0] == 'E'):
                code = crypto.encrypt
            else:
                code = crypto.decrypt

            while True:
                # data from read
                data, seq = gett()
                if(not data):
                    break
                putt((code(data), seq))

            self.que[0].cancel_join_thread()
            self.que[1].close()
        except Empty:
            pass
        except ImportError:
            pass
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return


class LetCrypto(Process):
    '''
    wrapper class for encoding with leet

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.leet import Leet
            gett = self.que[0].get    # read
            putt = self.que[1].put_nowait    # write
            crypto = Leet()
            code = crypto.coding

            while True:
                # data from read
                data, seq = gett()
                if(not data):
                    break
                putt((code(data), seq))

            self.que[0].cancel_join_thread()
            self.que[1].close()
        except Empty:
            pass
        except ImportError:
            pass
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return


class RccCrypto(Process):
    '''
    wrapper class for encoding with rc encryption

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

        f_iv = 'iv_%s' % info[5][IV_S:IV_E]
        if(who == 0 and self.info[2][0] == 'E' and self.info[1] == 2):
            self.ivv = u_ut_iv(128)
            with open(f_iv, 'wb') as file:
                file.write(dumps(self.ivv))
        else:
            try:
                with open(f_iv, 'rb') as file:
                    self.ivv = loads(file.read())
            except FileNotFoundError:
                self.ivv = None

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.rc.rc import RC
            gett = self.que[0].get    # read
            putt = self.que[1].put_nowait    # write
            crypto = RC(self.info[0], self.ivv, self.info[2][0], self.info[1])
            code = crypto.coding

            while True:
                # data from read
                data, seq = gett()
                if(not data):
                    break
                putt((code(data), seq))

            self.que[0].cancel_join_thread()
            self.que[1].close()
        except Empty:
            pass
        except ImportError:
            pass
        except AttributeError:    # no selv.if
            self.que[1].put_nowait((False, 0))
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return


class OtpCrypto(Process):
    '''
    wrapper class for encoding with otp encryption

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.otp import Otp
            gett = self.que[0].get    # read
            putt = self.que[1].put_nowait    # write
            crypto = Otp()
            boool = self.info[2][0] == 'E'
            f_iv = 'iv_%s' % self.info[5][IV_S:IV_E]

            if(boool):
                file = open(f_iv, 'wb')
                std = file.write
                code = crypto.encrypt
            else:
                file = open(f_iv, 'rb')
                std = file.read
                code = crypto.decrypt

            while True:
                # data from read
                data, seq = gett()
                if(not data):
                    break
                l_data = len(data)
                if(boool):
                    ivv = u_ut_iv(l_data, 'S', True)
                    std(ivv)
                else:
                    ivv = std(l_data)
                putt((code(data, ivv), seq))

            file.close()
            self.que[0].cancel_join_thread()
            self.que[1].close()
        except Empty:
            pass
        except ImportError:
            pass
        except AttributeError:    # no selv.if
            self.que[1].put_nowait((False, 0))
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return

class NihCrypto(Process):
    '''
    wrapper class for encoding with nihilist encryption

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside que
    queue    queue for read data
    queue    queue for write data

    @param integer who:    number of process
    @param tuple info:    see above
    @param list que:    see above
    @return object
    '''

    def __init__(self, who, info, que):
        Process.__init__(self)
        self.info = info
        self.que = que

        f_iv = 'iv_%s' % info[5][IV_S:IV_E]
        if(who == 0 and self.info[2][0] == 'E'):
            self.ivv = u_ut_iv(info[1], 'S')
            with open(f_iv, 'wb') as file:
                file.write(dumps(self.ivv))
        else:
            try:
                with open(f_iv, 'rb') as file:
                    self.ivv = loads(file.read())
            except FileNotFoundError:
                self.ivv = None

    def run(self):
        '''
        start process

        @return void
        '''

        try:
            from modules.nihilist import Nihi
            gett = self.que[0].get    # read
            putt = self.que[1].put_nowait    # write
            crypto = Nihi(self.info[0], self.ivv, self.info[2][0])
            code = crypto.coding

            while True:
                # data from read
                data, seq = gett()
                if(not data):
                    break
                putt((code(data), seq))

            self.que[0].cancel_join_thread()
            self.que[1].close()
        except Empty:
            pass
        except ImportError:
            pass
        except AttributeError:    # no selv.if
            self.que[1].put_nowait((False, 0))
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return