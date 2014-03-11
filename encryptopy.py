#!/usr/bin/python3
# -*- coding: utf-8 -*-

'''
Main File
Created on 10/set/2013

@package EncryptoPy
@subpackage main
@version 0.4
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


try:
    import gc
    from time import time
    from os import path
    from queue import Queue as pthread
    from multiprocessing import Queue, cpu_count
    from argparse import ArgumentParser, ArgumentTypeError
    # personal
    from core.thread import BUFFER, IRead, IWrit, IMngr
    from core.utility import u_dir_abs, u_user_input, u_user_check, \
                            u_file_exists, u_file_del, u_file_size, \
                            u_ut_crono, u_ut_crypto
except ImportError as error:
    print('In %s cannot load required libraries: %s!' \
        % (__name__, error))
    quit()


VERSION = 0.4
THREADS = cpu_count()
NAME = 'EncryptoPy'
EXT = '.cr'
MODULES = [
            'aes', 'des', 'base', 'xor',
            'hash', 'hmac', 'crc', 'vige',
            'play', 'blow', 'caes', 'morse',
            'leet', 'rc',
            ]
SIZE = [
            0, 1, 3, 4, 5,
            16, 31, 32, 64,
            128, 192, 160,
            224, 256, 384, 512,
            ]


class Main(object):
    '''
    main class for initialize correct encrypt class, queue, read and write file

    # inside file
    string root    root of read file
    string name    root of write file

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decription
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside others
    bool purge    purge root file
    integer cycle    number of cycle for reading/writing
    bool ash    flag if is a hash function

    @param tuple file:    see above
    @param tuple info:    see above
    @param tuple others:    see above
    @return object
    '''

    def __init__(self, file, info, others):
        thread_que = pthread()
        self.que = [Queue(), Queue()]
        self.time = 0
        self.file = file
        self.others = others
        self.class_r = IRead(file[0], self.que[0], thread_que, info)
        self.class_w = IWrit(file[1], self.que[1], thread_que, info, others[2])
        self.class_c = IMngr(info, self.que)

    def run(self):
        '''
        starting programm

        @return void
        '''

        self.time = time()
        print('reading... ', end='')

        # start
        self.class_r.start()
        self.class_c.start()
        self.class_w.start()

        # wait
        self.class_r.join()
        if(self.others[0]):
            self.__delete()
        print('file read in %s.' % (u_ut_crono(self.time)))
        self.time = time()    # reset
        if(not self.others[2]):
            print('working... ', end='')
        self.class_c.join()
        self.class_w.join()
        return

    def end(self):
        '''
        check created file and print elapsed time
        only if isn't a hash function

        @return void
        '''

        if(not self.others[2]):
            if(u_file_exists(self.file[1])):
                print('file write in %s.\a' % (u_ut_crono(self.time)))
            else:
                print('file error!\a')
        return

    def __delete(self):
        '''
        delete original file

        @return bool
        '''

        return u_file_del(self.file[0])


if __name__ == '__main__':

    def m_ext(name_ext):
        '''
        return true if file extension is .cr

        @param string name_ext:    path of file
        @return bool
        '''

        if(name_ext[-3:] == EXT):
            return True
        else:
            return False

    def m_file(root_file):
        '''
        type for argparse

        @param string root_file:    path of file
        @return string
        '''

        roo = u_dir_abs(root_file)
        if(not u_file_exists(roo)):
            raise ArgumentTypeError('File not found!')
        else:
            return roo

    def m_quit(bye=True):
        '''
        close program

        @param bool bye:    if print bye
        @return quit
        '''

        if(bye):
            print('Bye!')
        quit()

    PARSER = ArgumentParser(description='Run %s' % (NAME,))
    PARSER.add_argument('-v', '--version', action='version', \
                        version='%s version %s' % (NAME, VERSION,))
    PARSER.add_argument('type', type=str, choices=MODULES, default=['aes'])
    PARSER.add_argument('-p', metavar='Path', nargs=1, type=m_file, \
                        help='insert path of your file', required=True)

    GROUP_0 = PARSER.add_mutually_exclusive_group(required=True)
    GROUP_0.add_argument('-e', '--encrypt', action='store_true', \
                         default=False, help='encrypt your file')
    GROUP_0.add_argument('-d', '--decrypt', action='store_true', \
                         default=False, help='decrypt your file')

    GROUP_1 = PARSER.add_argument_group(title='optional flag')
    GROUP_1.add_argument('-r', '--remove', action='store_true', \
                         default=False, help='purge original file')
    GROUP_1.add_argument('-c', '--compress', action='store_true', \
                         default=False, help='compress your file')
    GROUP_1.add_argument('-f', '--force', action='store_true', \
                         default=False, help='force True option')
    GROUP_1.add_argument('-k', metavar='Key', nargs=1, type=int, \
                         default=[0], help='set the type of the key')
    GROUP_1.add_argument('-t', metavar='Threads', nargs=1, type=int, \
                         default=[THREADS], help='set number of threads')
    GROUP_1.add_argument('-n', metavar='Name', nargs=1, type=str, \
                         help='set name of your new file')

    ARGS = PARSER.parse_args()

    try:
        SIZE = 0
        FLAG = True
        ASH = False
        PSW = None

        # name problem
        FORCE = ARGS.force
        ROOT = ARGS.p[0]
        if(ARGS.n):    # if I got a new NAME
            NAME = path.join(path.dirname(ROOT), ARGS.n[0])
        elif(ARGS.decrypt and m_ext(ROOT)):    # if decrypt FLAG and *.cr
            NAME = ROOT[:-3]
        elif(ARGS.encrypt):    # if encrypt
            NAME = '%s%s' % (ROOT, EXT)

        # thread problem
        THREADS = int(u_file_size(ROOT) / BUFFER)
        if(int(u_file_size(ROOT) % BUFFER) > 0):
            CYCLE = THREADS + 1
        else:
            CYCLE = THREADS
        if(THREADS > ARGS.t[0]):
            THREADS = ARGS.t[0]
        elif(THREADS == 0):
            THREADS = 1

        # FLAG problem
        if(ARGS.encrypt):
            ACTION = 'E'
            QUESTION = 'encrypt'
        else:
            ACTION = 'D'
            QUESTION = 'decrypt'
        if(ARGS.compress):
            ACTION = '%c%c' % (ACTION, '+')

        # module problem
        TYPE = ARGS.type
        SIZE = ARGS.k[0]
        if(TYPE == 'aes'):
            TYP = 'A'
            if(SIZE == 192):    # 256
                SIZE = 24
                TYPE = 'aes192'
            elif(SIZE == 256):    # 256
                SIZE = 32
                TYPE = 'aes256'
            else:    # 128
                SIZE = 16
                TYPE = 'aes128'
        elif(TYPE == 'des'):
            TYP = 'D'
            if(SIZE == 3):    # triple_des
                SIZE = 24
                TYPE = 'triple_des'
            else:    # des
                SIZE = 8
        elif(TYPE == 'base'):
            FLAG = False
            TYP = 'B'
            if(SIZE == 16):
                SIZE = 16
                TYPE = 'base16'
            elif(SIZE == 32):
                SIZE = 32
                TYPE = 'base32'
            else:
                SIZE = 64
                TYPE = 'base64'
        elif(TYPE == 'xor'):
            TYP = 'X'
        elif(TYPE == 'hash'):
            ASH = True
            FLAG = False
            TYP = 'H'
            if(SIZE == 0):    # sha0
                SIZE = 0
                TYPE = 'sha0'
            elif(SIZE == 1):    # sha1
                SIZE = 1
                TYPE = 'sha1'
            elif(SIZE == 3):    # dsa
                SIZE = 3
                TYPE = 'dsa'
            elif(SIZE == 4):    # md4
                SIZE = 4
                TYPE = 'md4'
            elif(SIZE == 160):    # ripemd
                SIZE = 160
                TYPE = 'ripemd160'
            elif(SIZE == 224):    # sha2
                SIZE = 224
                TYPE = 'sha224'
            elif(SIZE == 256):
                SIZE = 256
                TYPE = 'sha256'
            elif(SIZE == 384):
                SIZE = 384
                TYPE = 'sha384'
            elif(SIZE == 512):
                SIZE = 512
                TYPE = 'sha512'
            else:    # md5
                SIZE = 5
                TYPE = 'md5'
        elif(TYPE == 'hmac'):
            ASH = True
            TYP = 'M'
        elif(TYPE == 'crc'):
            ASH = True
            FLAG = False
            TYP = 'C'
            if(SIZE == 31):    # adler
                SIZE = 31
                TYPE = 'adler32'
            else:    # crc
                SIZE = 32
                TYPE = 'crc32'
        elif(TYPE == 'vige'):
            TYP = 'V'
            TYPE = 'vigenère'
        elif(TYPE == 'play'):
            TYP = 'P'
            TYPE = 'playfair'
        #======================================================================
        # elif(TYPE == 'blow'):
        #     TYP = 'F'
        #     TYPE = 'blowfish'
        #======================================================================
        elif(TYPE == 'caes'):
            FLAG = False
            TYP = 'E'
            if(SIZE == 13):    # rot13
                TYPE = 'rot13'
            if(SIZE == -1):    # atbash
                TYPE = 'atbash'
            else:
                TYPE = 'caesar'
        elif(TYPE == 'morse'):
            FLAG = False
            TYP = 'O'
        elif(TYPE == 'leet'):
            FLAG = False
            ACTION = 'E'    # override
            QUESTION = 'encrypt'
            TYP = 'L'
            TYPE = 'l33t'
        elif(TYPE == 'rc'):
            TYP = 'R'
            if(SIZE == 2):    # rc2
                TYPE = 'rc2'
            else:    # rc4
                SIZE = 4
                TYPE = 'rc4'

        # question problem
        if(ASH):
            ACTION = 'E'    # override
            QUESTION = 'encrypt'
            THREADS = 1
        if(u_file_exists(NAME) and NAME != ROOT and not FORCE and not ASH):
            if(not u_user_input(\
                r'New file already exist, do you wanna proceed? [Y/N] ')):
                m_quit()
        if(FLAG):
            PSW = u_user_check(r'[A-Za-z0-9@#$%^&+=]{6,20}', \
                              'Insert your password: ')
        if(FORCE or u_user_input('Do you wanna %s your file with %s? [Y/N] '\
                        % (QUESTION, TYPE))):
            FILE = (ROOT, NAME)
            INFO = (PSW, SIZE, ACTION, TYP, THREADS, \
                    u_ut_crypto('%s%s%s' % (ARGS.compress, TYPE, PSW)))
            OTHERS = (ARGS.remove, CYCLE, ASH)
            RUN = Main(FILE, INFO, OTHERS)

            # clean
            del BUFFER, ARGS, PARSER, GROUP_0, GROUP_1, \
                FILE, INFO, OTHERS, \
                ROOT, NAME, PSW, SIZE, ACTION, TYP, FLAG, FORCE, \
                QUESTION, TYPE, CYCLE, THREADS, ASH
            del path, cpu_count, ArgumentParser, ArgumentTypeError, \
                u_user_input, u_user_check, u_file_size, u_dir_abs, \
                u_ut_crypto, m_file, m_ext
            gc.collect()

            RUN.run()    # goo!!
            RUN.end()
        m_quit(False)

    except KeyboardInterrupt:    # Ctrl + C
        print()
        m_quit()
