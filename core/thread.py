'''
Thread classes
Created on 10/set/2013

@package EncryptoPy
@subpackage core
@version 0.4
@author 0x7c0 <0x7c0@teboss.tk>
@copyright Copyright (c) 2013, 0x7c0
@license http://www.gnu.org/licenses/gpl.html GPL v3 License
'''


try:
    from threading import Thread
    from gzip import GzipFile
    from shutil import copyfileobj
    from tempfile import NamedTemporaryFile
    # personal
    from core.utility import u_file_del
except ImportError as error:
    print('In %s cannot load required libraries: %s!' \
        % (__name__, error))
    quit()


BUFFER = 131072    # 128kb
BUFFER_PICK = 6
BUFFER_HEAD = 128 - BUFFER_PICK
FIRST = 0


class IRead(Thread):
    '''
    class for read normal/encrypted file

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    @param string file:    root of read file
    @param queue que:    queue for read data
    @param queue thread:    queue between thread
    @param tuple info:    see above
    @return object
    '''

    def __init__(self, file, que, thread, info):
        Thread.__init__(self, name='%s_%s' % (__name__, file))
        self.__thread = thread
        self.__info = info
        self._error = True
        self.file = file
        self.que = que

    def run(self):
        '''
        starting thread

        @return void
        '''

        try:
            with open(self.file, 'rb') as file:
                boool = (len(self.__info[2]) == 2 and self.__info[2][0] == 'E')
                if(boool):    # compress
                    gzip = NamedTemporaryFile(prefix='comp_', delete=False)
                    with GzipFile(gzip.name, 'wb') as comp:
                        copyfileobj(file, comp)
                    file = gzip    # override
                # not_dots fx
                putt = self.que.put_nowait
                count = FIRST
                fread = file.read

                if(self.__info[2][0] == 'E'):    # encrypt
                    while True:
                        tmp = fread(BUFFER)
                        if(not tmp):
                            break
                        putt((tmp, count))
                        count += 1

                else:    # decrypt
                    try:
                        buffer = int(fread(BUFFER_PICK))    # pickle buffer
                        header = fread(BUFFER_HEAD).decode()    # header
                        if(header == self.__info[5][0:BUFFER_HEAD]):
                            while True:
                                tmp = fread(buffer)
                                if(not tmp):
                                    break
                                putt((tmp, count))
                                count += 1
                    except ValueError:
                        pass

            for i in range(self.__info[4]):    # end of queue
                putt((False, i))
            if(boool):    # remove compress
                gzip.close()
                u_file_del(gzip.name)

            self._error = False
        except KeyboardInterrupt:    # Ctrl + C
            pass

        if(self._error):    # error
            self.__thread.put_nowait(0)
        else:    # for write
            self.__thread.put_nowait(count)

        return


class IWrit(Thread):
    '''
    class for write encrypted/normal file

    # inside info
    string psw    user password
    int size    for encryption module
    char action    'E' for encryption or 'D' for decryption
    char typ    type of encryption module
    integer proc    number of process for crypto
    string ash    header hash

    @param string file:    root of write file
    @param queue que:    queue for write data
    @param queue thread:    queue between thread
    @param tuple info:    see above
    @param bool ash    flag if is a hash function
    @return object
    '''

    def __init__(self, file, que, thread, info, ash):
        Thread.__init__(self, name='%s_%s' % (__name__, file))
        self.__thread = thread
        self.__info = info
        self._error = True
        self.file = file
        self.que = que

        self._ash = ash
        self._fwrite = None
        self.buffer = {}    # dict

    def run(self):
        '''
        starting thread

        @return void
        '''

        try:
            cyc = self.__thread.get()
            if(self._ash):    # header part
                pass
            elif(cyc > 0):
                with open(self.file, 'wb') as file:
                    boool = (len(self.__info[2]) == 2 and \
                            self.__info[2][0] == 'D')
                    if(boool):    # decompress
                        gzip = NamedTemporaryFile(prefix='comp_', delete=False)
                        backup = file
                        file = gzip    # override
                    # not_dots fx
                    gett = self.que.get
                    count = FIRST
                    self._fwrite = fwrite = file.write

                    if(self.__info[2][0] == 'E'):    # encrypt
                        raw, seq = gett()
                        self.buffer[seq] = raw
                        first = str(len(raw)).zfill(BUFFER_PICK)
                        fwrite(first.encode())
                        fwrite(self.__info[5][0:BUFFER_HEAD].encode())
                        cyc -= 1
                        del first

                        while cyc > 0:
                            raw, seq = gett()
                            if(not raw):
                                break
                            elif(count == seq):
                                fwrite(raw)
                                count += 1
                            else:
                                self.buffer[seq] = raw
                                count = self.controll(count)
                            cyc -= 1

                    else:    # decrypt
                        while cyc > 0:
                            raw, seq = gett()
                            if(not raw):
                                break
                            elif(count == seq):
                                fwrite(raw)
                                count += 1
                            else:
                                self.buffer[seq] = raw
                                count = self.controll(count)
                            cyc -= 1

                    self.last(count)
                    if(boool):
                        gzip.close()
                        with GzipFile(gzip.name, 'rb') as comp:
                            copyfileobj(comp, backup)
                        u_file_del(gzip.name)
        except KeyboardInterrupt:    # Ctrl + C
            pass

        return

    def controll(self, ticket):
        '''
        RECURSIVE
        try to write ticket seq to file
        if a valid sequence

        @integer ticket:    number of packet
        @return integer
        '''

        try:
            data = self.buffer[ticket]
            del self.buffer[ticket]
            self._fwrite(data)
            ticket += 1
            return self.controll(ticket)
        except KeyError:
            return ticket

    def last(self, ticket):
        '''
        recevive last element
        close queue and try to build file

        @integer ticket:    number of packet
        @return void
        '''

        self.que.close()
        self.que.cancel_join_thread()
        self.controll(ticket)
        return


class IMngr(Thread):
    '''
    manager class for build process

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

    @param tuple info    see above
    @param list que    see above
    @retun object
    '''

    def __init__(self, info, que):
        Thread.__init__(self, name=info[5])
        self.__info = info
        self._cry = []    # crypto
        self.who = info[4]
        app = self._cry.append
        typ = info[3]

        try:
            if   (typ == 'A'):
                from core.process import AesCrypto as Crypto
            elif (typ == 'D'):
                from core.process import DesCrypto as Crypto
            elif (typ == 'B'):
                from core.process import BasCrypto as Crypto
            elif (typ == 'X'):
                from core.process import XorCrypto as Crypto
            elif (typ == 'H'):
                from core.process import HasCrypto as Crypto
            elif (typ == 'M'):
                from core.process import MacCrypto as Crypto
            elif (typ == 'C'):
                from core.process import CrcCrypto as Crypto
            elif (typ == 'V'):
                from core.process import VigCrypto as Crypto
            elif (typ == 'P'):
                from core.process import VigCrypto as Crypto
            #==================================================================
            # elif (typ == 'F'):
            #     from core.process import BloCrypto as Crypto
            #==================================================================
            elif (typ == 'E'):
                from core.process import VigCrypto as Crypto
            elif (typ == 'S'):
                from core.process import VigCrypto as Crypto
            elif (typ == 'L'):
                from core.process import LetCrypto as Crypto
            elif (typ == 'R'):
                from core.process import RccCrypto as Crypto
            elif (typ == 'O'):
                from core.process import OtpCrypto as Crypto
            elif (typ == 'N'):
                from core.process import NihCrypto as Crypto
            elif (typ == 'I'):
                from core.process import VicCrypto as Crypto
            elif (typ == 'U'):
                from core.process import VigCrypto as Crypto

            for i in range(self.who):
                cry = Crypto((i, typ), info, que)
                app(cry)
        except ImportError:
            raise Exception

    def run(self):
        '''
        starting thread

        @return void
        '''

        who = self.who
        cry = self._cry
        try:
            # start process
            for i in range(who):
                cry[i].start()
            # wait for exit
            for i in range(who):
                cry[i].join()

        except KeyboardInterrupt:    # Ctrl + C
            for i in range(who):
                pid = cry[i]
                if(pid.is_alive()):
                    pid.terminate()

        return
