#!/usr/bin/python3
# -*- coding: utf-8 -*-

'''
Main File
Created on 10/set/2013

@package EncryptoPy
@subpackage main
@version 0.5
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


try:
    import gc
    from time import time
    from os.path import dirname, join
    from tempfile import NamedTemporaryFile
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


VERSION = 0.5
THREADS = cpu_count()
NAME = 'EncryptoPy'
EXT = '.cr'
MODULES = [
            'aes', 'des', 'base', 'xor',
            'hash', 'hmac', 'crc', 'vige',
            'play', 'blow', 'caes', 'morse',
            'leet', 'rc', 'otp', 'nihi',
            'vic',
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
    integer size    for encryption module
    char action    'E' for encryption or 'D' for decription
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    # inside others
    bool purge    purge root file
    integer cycle    number of cycle for reading/writing
    list ash    flag if is a hash function
    integer cc   counter for cascade
    bool stat    print statistics

    @param tuple file:    see above
    @param list info:    see above
    @param tuple others:    see above
    @return object
    '''

    def __init__(self, file, info, others):
        self.__stat = [0, 0]
        self.__time = 0

        self._tmp_r = []
        self._tmp_w = []
        self._counter = 0

        self.file = file
        self.info = info
        self.others = others
        self.class_r = []    # read class
        self.class_w = []    # write class
        self.class_c = []    # process class

        for ii in range(1, others[3]):
            t = NamedTemporaryFile(prefix=__name__, suffix='_r', delete=False)
            self._tmp_r.append(t.name)
            t = NamedTemporaryFile(prefix=__name__, suffix='_w', delete=False)
            self._tmp_w.append(t.name)
        self.magic()

    def magic(self):
        '''
        do some magic with file

        @return: void
        '''

        count = self._counter
        inside = outsid = ''

        if(count == 0):
            inside = self.file[0]
        else:
            inside = self._tmp_w[count - 1]

        if(count + 1 == self.others[3]):
            outsid = self.file[1]
        else:
            outsid = self._tmp_w[count]

        self.refresh(inside, outsid)
        self.run()
        return

    def refresh(self, inside, outsid):
        '''
        refresh class with correct filename

        @param string inside:    file to be read
        @param string outsid:    file to be write
        @return: void
        '''

        count = self._counter
        que = [Queue(), Queue()]
        t_que = pthread()

        self.class_r.append(IRead(inside, que[0], t_que, \
                             self.info[count]))
        self.class_w.append(IWrit(outsid, que[1], t_que, \
                             self.info[count], self.others[2][count]))
        self.class_c.append(IMngr(self.info[count], que))
        return

    def run(self):
        '''
        starting programm

        @return void
        '''

        count = self._counter
        ash = not self.others[2][count]    # typ hash
        self.__time = time()
        print('reading %s° round... ' % (count + 1), end='')

        # start
        self.class_r[count].start()
        self.class_c[count].start()
        self.class_w[count].start()

        # wait
        self.class_r[count].join()
        if(self.others[0]):
            self.__delete()
        print('file read in %s.' % (u_ut_crono(self.__time)))
        self.__stat[0] += time() - self.__time
        self.__time = time()    # reset

        if(ash):
            print('working %s° round... ' % (count + 1), end='')
        self.class_c[count].join()
        self.class_w[count].join()
        if(ash):
            print('file write in %s.' % (u_ut_crono(self.__time)))
        self.__stat[1] += time() - self.__time

        self._counter += 1
        if(self._counter < self.others[3]):
            self.magic()

        return

    def end(self):
        '''
        check created file and print elapsed time
        only if isn't a hash function

        @return void
        '''

        tot = self.others[3]
        for iii in range(0, tot - 1):    # remove temporary file
            u_file_del(self._tmp_r[iii])
            u_file_del(self._tmp_w[iii])

        if(self.others[4]):    # stats
            print()
            print('Reading average time: %.3f sec' % (self.__stat[0] / tot))
            print('Working average time: %.3f sec' % (self.__stat[1] / tot))
            print('Total time: %.3f sec' % (self.__stat[0] + self.__stat[1]))

        if(not self.others[2][self._counter - 1]):    # end info
            if(not u_file_exists(self.file[1])):
                print('File error!\a')
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
    PARSER.add_argument('type', type=str, choices=MODULES, nargs='*')
    PARSER.add_argument('-p', metavar='Path', nargs=1, type=m_file, \
                        help='insert path of your file', required=True)

    GROUP_0 = PARSER.add_mutually_exclusive_group(required=True)
    GROUP_0.add_argument('-E', '--encrypt', action='store_true', \
                         default=False, help='encrypt your file')
    GROUP_0.add_argument('-D', '--decrypt', action='store_true', \
                         default=False, help='decrypt your file')

    GROUP_1 = PARSER.add_argument_group(title='optional flag')
    GROUP_1.add_argument('-r', '--remove', action='store_true', \
                         default=False, help='purge original file')
    GROUP_1.add_argument('-c', '--compress', action='store_true', \
                         default=False, help='compress your file')
    GROUP_1.add_argument('-s', '--stat', action='store_true', \
                         default=False, help='show statistics')
    GROUP_1.add_argument('-d', '--default', action='store_true', \
                         default=False, help='use default key')
    GROUP_1.add_argument('-f', '--force', action='store_true', \
                         default=False, help='force True option')

    GROUP_2 = PARSER.add_argument_group(title='optional parameters')
    GROUP_2.add_argument('-t', metavar='Threads', nargs=1, type=int, \
                         default=[THREADS], help='set number of threads')
    GROUP_2.add_argument('-n', metavar='Name', nargs=1, type=str, \
                         help='set name of your new file')
    GROUP_2.add_argument('-k', metavar='Key', nargs='*', type=int, \
                         default=[0], help='set the type of the key')

    ARGS = PARSER.parse_args()

    try:
        # init
        COUNTER = SIZE = 0
        ROOT = NAME = PSW = ''
        ACTION = QUESTION = ''
        TYPE = TYP = ''
        FORCE = FLAG = ASH = False
        CASCADE = []
        HASH = []
        L_TYPE = []
        app1 = CASCADE.append
        app2 = HASH.append
        app3 = L_TYPE.append

        # name problem
        FORCE = ARGS.force
        ROOT = ARGS.p[0]
        if(ARGS.n):    # if I got a new NAME
            NAME = join(dirname(ROOT), ARGS.n[0])
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
        for module in ARGS.type:
            TYPE = module
            try:
                SIZE = ARGS.k[COUNTER]
            except IndexError:
                if(not ARGS.default):
                    print('Missing -k for %s° module' % (COUNTER + 1))
                    break
                else:
                    SIZE = 0

            if(TYPE == 'aes'):
                FLAG = True
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
                FLAG = True
                TYP = 'D'
                if(SIZE == 3):    # triple_des
                    SIZE = 24
                    TYPE = 'triple_des'
                else:    # des
                    SIZE = 8
                    TYPE = TYPE

            elif(TYPE == 'base'):
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
                FLAG = True
                TYP = 'X'
                TYPE = TYPE
                SIZE = 0

            elif(TYPE == 'hash'):
                ASH = True
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
                FLAG = True
                ASH = True
                TYP = 'M'
                TYPE = TYPE
                SIZE = 0

            elif(TYPE == 'crc'):
                ASH = True
                TYP = 'C'
                if(SIZE == 31):    # adler
                    SIZE = 31
                    TYPE = 'adler32'
                else:    # crc
                    SIZE = 32
                    TYPE = 'crc32'

            elif(TYPE == 'vige'):
                FLAG = True
                TYP = 'V'
                TYPE = 'vigenère'
                SIZE = 0

            elif(TYPE == 'play'):
                FLAG = True
                TYP = 'P'
                TYPE = 'playfair'
                SIZE = 0

            #==================================================================
            # elif(TYPE == 'blow'):
            #     TYP = 'F'
            #     TYPE = 'blowfish'
            #     SIZE = 0
            #==================================================================

            elif(TYPE == 'caes'):
                TYP = 'E'
                if(SIZE == 13):    # rot13
                    SIZE = 13
                    TYPE = 'rot13'
                if(SIZE == -1):    # atbash
                    SIZE = -1
                    TYPE = 'atbash'
                else:
                    SIZE = SIZE
                    TYPE = 'caesar'

            elif(TYPE == 'morse'):
                TYP = 'S'
                TYPE = TYPE
                SIZE = 0

            elif(TYPE == 'leet'):
                ACTION = 'E'    # override
                QUESTION = 'encrypt'
                TYP = 'L'
                TYPE = 'l33t'
                SIZE = 0

            elif(TYPE == 'rc'):
                FLAG = True
                TYP = 'R'
                if(SIZE == 2):    # rc2
                    SIZE = SIZE
                    TYPE = 'rc2'
                else:    # rc4
                    SIZE = 4
                    TYPE = 'rc4'

            elif(TYPE == 'otp'):
                TYP = 'O'
                TYPE = 'one_time_pad'
                SIZE = 0
                THREADS = 1

            elif(TYPE == 'nihi'):
                FLAG = True
                TYP = 'N'
                TYPE = 'nihilist'
                SIZE = 0

            elif(TYPE == 'vic'):
                FLAG = True
                TYP = 'I'
                TYPE = 'vic'
                SIZE = 0

            COUNTER += 1
            app1((PSW, SIZE, ACTION, TYP, THREADS, ASH))
            app2(ASH)
            app3(TYPE)
            if(ASH):
                break

        # question problem
        if(True in HASH):
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
        QUESTION = 'Do you wanna %s your file with ' % QUESTION
        for i in range(COUNTER):    # reset

            if(i > 0):
                QUESTION = '%s%s' % (QUESTION, ', ')
            QUESTION = '%s%s' % (QUESTION, L_TYPE[i])

            # all same
            if(L_TYPE[i] in L_TYPE[0:i] or \
               L_TYPE[i] in L_TYPE[i + 1:len(L_TYPE)]):
                if(ACTION == 'E'):
                    sal = i
                else:
                    sal = COUNTER - 1 - i
            else:
                sal = 0
            ah = u_ut_crypto('%s%s%s%s' % (ARGS.compress, sal, L_TYPE[i], PSW))
            CASCADE[i] = PSW, CASCADE[i][1], ACTION, CASCADE[i][3], THREADS, ah

        QUESTION = '%s%s' % (QUESTION, '? [Y/N] ')

        # ready
        if(FORCE or u_user_input(QUESTION)):
            FILE = (ROOT, NAME)
            OTHERS = (ARGS.remove, CYCLE, HASH, COUNTER, ARGS.stat)
            RUN = Main(FILE, CASCADE, OTHERS)

            # clean
            del BUFFER, EXT, MODULES, VERSION, \
                ARGS, PARSER, GROUP_0, GROUP_1, GROUP_2, \
                FILE, CASCADE, OTHERS, \
                ROOT, NAME, PSW, SIZE, ACTION, FLAG, FORCE, \
                QUESTION, TYPE, TYP, CYCLE, THREADS, ASH, COUNTER, \
                HASH, L_TYPE, app1, app2, app3, ah, i
            del dirname, join, cpu_count, ArgumentParser, ArgumentTypeError, \
                u_user_input, u_user_check, u_file_size, u_dir_abs, \
                u_ut_crypto, m_file, m_ext
            gc.collect()

            RUN.end()
        m_quit(False)

    except KeyboardInterrupt:    # Ctrl + C
        print()
        m_quit()
