'''
Common functions
Created on 10/set/2013

@package EncryptoPy
@subpackage core
@version 0.4
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


from re import match
from os import urandom
from getpass import getpass
from os import path, remove
from hashlib import md5, sha512
from time import time, gmtime, strftime


def u_dir_abs(root):
    '''
    check if path is absolute
    otherwise return abs path

    @param string root:        pathname
    @return: string
    '''

    if(path.isabs(root)):
        return root
    else:
        return path.abspath(root)


def u_file_exists(root):
    '''
    check file

    @param string root:        pathname
    @return: bool
    '''

    return path.exists(root) and path.isfile(root)


def u_file_del(root):
    '''
    rm file

    @param string root:        pathname
    @return: bool
    '''

    if (u_file_exists(root)):
        remove(root)
    return True


def u_file_size(root):
    '''
    return file size

    @param string root    root of file
    '''

    if (u_file_exists(root)):
        return path.getsize(root)
    return


def u_ut_crono(start, pprint=True):
    '''
    given the initial unix time
    return time spent

    @param time start:        stating time
    @param bool pprint:        if print to output
    @return: string
    '''

    if(pprint):
        end = time() - start
        microsecond = int((end - int(end)) * 1000)
        if (end < 60):    # sec
            return '%s sec and %s ms' % (strftime('%S', \
                                             gmtime(end)), microsecond)
        elif (end < 3600):    # min
            return '%s min and %s ms' % (strftime('%M,%S', \
                                             gmtime(end)), microsecond)
        else:    # hr
            return '%s hr and %s ms' % (strftime('%H.%M,%S', \
                                             gmtime(end)), microsecond)
    else:
        return int(strftime('%S', gmtime(start)))


def u_ut_crypto(psw):
    '''
    encode string with hash

    @param string psw    password
    @return string
    '''

    ash = md5(psw.encode())
    ash = sha512(ash.digest())
    return ash.hexdigest()


def u_ut_iv(size, tty='L'):
    '''
    make random iv for aes block

    @param integer size:        type of aes [16,24,32]
    @param char tty:    type of return
    @return list
    '''

    if(tty == 'L'):
        ivv = []
        app = ivv.append

        for i in range(0, size):
            try:
                app(int.from_bytes(urandom(1), 'little'))
            except IndexError:
                app(i)
    elif(tty == 'S'):
        LIMIT = 8
        ivv = ''

        for i in range(0, size):
            try:
                ivv = '%s%s' % (ivv, int.from_bytes(urandom(1), 'little'))
            except IndexError:
                ivv = '%s%s' % (ivv, i)
        if(len(ivv) > LIMIT):
            ivv = ivv[0:LIMIT]

    return ivv


def u_user_check(regex, question):
    '''
    read stdin and return if match regex

    @param string regex:        regolar expression
    @param string question:        output question
    @param bool password:        enable getpass module
    @return: string
    '''

    while True:
        temp = getpass(question)
        if(match(regex, temp)):
            return u_ut_crypto(temp)
        print('Provide a correct alfanum password.')


def u_user_input(question):
    '''
    question about action
    yes or no question

    @param string question:        output question
    @return: bool
    '''

    while True:
        action = input(question)
        if(action.upper() == 'Y'):
            return True
        elif(action.upper() == 'N'):
            return False
