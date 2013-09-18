#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
Main File
Created on 10/set/2013
Licensed under GPL License, Version 3.0 (http://www.gnu.org/licenses/gpl.html)

@version: 0.2
@author: 0x7c0
'''

NAME = 'EncryptoPy'
VERSION = 0.2
EXT = '.cr'

from queue import Queue
from time import time
from os import path
from core.thread import IRead, IWrit


class Main( object ):
	'''
	main class for inizialize correct encrypt class, queue, read and write file
	@param string root	root of read file
	@param string name	root of write file
	@param string psw	user password
	@param int size		for encryption module
	@param char action	'E' for encryption or 'D' for decription
	@param char typ		type of encryption module
	@param bool purge	purge root file
	'''

	def __init__( self, root, name, psw, size, action, typ, purge = False ):
		self.root = root
		self.name = name
		self.time = time()
		self.threads = []
		self.r = Queue()    # for read
		self.w = Queue()    # for write
		if( typ == 'A' ):
			from core.thread import AesCrypto
			self.cr = AesCrypto( psw, size, action, self.r, self.w )
		if( typ == 'D' ):
			from core.thread import DesCrypto
			self.cr = DesCrypto( psw, action, self.r, self.w )
		elif( typ == 'B' ):
			from core.thread import BasCrypto
			self.cr = BasCrypto( size, action, self.r, self.w )
		elif ( typ == 'X' ):
			from core.thread import XorCrypto
			self.cr = XorCrypto( psw, action, self.r, self.w )
		elif ( typ == 'H' ):
			from core.thread import HasCrypto
			self.cr = HasCrypto( size, self.r, self.w )
		elif ( typ == 'M' ):
			from core.thread import MacCrypto
			self.cr = MacCrypto( psw, self.r, self.w )
		elif ( typ == 'C' ):
			from core.thread import CrcCrypto
			self.cr = CrcCrypto( size, self.r, self.w )
		elif ( typ == 'V' ):
			from core.thread import VigCrypto
			self.cr = VigCrypto( action, psw, self.r, self.w )
		elif ( typ == 'P' ):
			from core.thread import PlaCrypto
			self.cr = PlaCrypto( action, psw, self.r, self.w )
		self.rd = IRead( root, self.r, action )    # read
		self.wd = IWrit( name, self.w, action )    # write
		self.go( purge )
		self.end()
	def go( self, purge ):
		print( 'working...' )
		self.rd.start()
		self.cr.start()
		self.wd.start()
		self.rd.join()
		if( purge ):print( 'purge original file.' );self.delete()
		self.cr.join()
		self.wd.join()
	def delete( self ):
		from core.utility import u_FilePurge
		u_FilePurge( self.root )
	def end( self ):
		from core.utility import u_FileExists, u_UtCrono
		if( u_FileExists( self.name ) ):
			print( 'Done in %s' % ( u_UtCrono( self.time ) ) )
		else:
			print( 'Error!' )

if __name__ == '__main__':

	def M_ext( name ):
		''' return true if file extension is .cr '''
		if( name[-3:] == EXT ):
			return True
		else:
			return False
	def M_file( v ):
		''' type for argparse '''
		from argparse import ArgumentTypeError
		root = u_DirAbs( path.join( v ) )
		if( not u_FileExists( root ) ): raise ArgumentTypeError( 'File not found!' )
		else: return root

	import argparse
	from core.utility import u_UserInput,u_UserCheck, u_FileExists, u_DirAbs

	parser = argparse.ArgumentParser( description = 'Run %s' % ( NAME, ) )
	parser.add_argument( '-V', '--version', action = 'version', version = '%s version %s' % ( NAME, VERSION, ) )


	group1 = parser.add_argument_group( title = 'required flag' )
	group1.add_argument( '-r', metavar = 'Root', nargs = 1, type = M_file, help = 'insert root of your file', required = True )

	group2 = parser.add_subparsers()
	enc = group2.add_parser( 'T', help = 'type of encryption/decryption' )
	enc.add_argument( 'type', nargs = 1, type = str, choices = ['aes', 'des', 'base', 'xor', 'hash', 'hmac', 'crc', 'vige', 'play'], default = ['aes'] )

	group3 = parser.add_mutually_exclusive_group( required = True )
	group3.add_argument( '-E', '--encrypt', action = 'store_true', default = False, help = 'encrypt your file' )
	group3.add_argument( '-D', '--decrypt', action = 'store_true', default = False, help = 'decrypt your file' )

	group4 = parser.add_argument_group( title = 'optional flag' )
	group4.add_argument( '-k', metavar = 'Key', nargs = 1, type = int, choices = [1, 5, 16, 31, 32, 64, 128, 192, 160, 224, 256, 384, 512], default = [128], help = 'set the size of the key' )
	group4.add_argument( '-n', metavar = 'Name', nargs = 1, type = str, help = 'set name of your new file' )
	group4.add_argument( '-p', action = 'store_true', default = False, help = 'purge original file after the process' )

	args = parser.parse_args()
	del argparse

	try:
		name = '';psw = '';size = '';action = ''; purge = ''; typ = ''
		flag = False

		root = args.r[0]
		if( args.n ):    # se ho name
			name = path.join( path.dirname( root ), args.n[0] )
		elif( args.decrypt and M_ext( root ) ):    # se decrypt e nome .cr
			name = root[:-3]
		elif( args.encrypt ):    # if encrypt
			name = '%s%s' % ( root, EXT )
		else:
			name = path.join( path.dirname( root ), '%s%s' % ( '2_', path.basename( root ) ) )
		if(u_FileExists( name ) ):
			if( not u_UserInput( 'new file already exist, do you wanna proceed? [Y/N] ' ) ):
				print( 'Change file name at start' )
				quit()

		if( args.decrypt ): action = 'D';question = 'decrypt'
		elif( args.encrypt ): action = 'E';question = 'encrypt'

		try:
			if( args.type[0] == 'aes' ):
				typ = 'A';flag = True
				if( args.k[0] == 128 ): size = 16
				elif( args.k[0] == 192 ): size = 24
				elif( args.k[0] == 256 ): size = 32
				else: size = 16
			elif( args.type[0] == 'des' ):
				typ = 'D';flag = True
				size = 0
			elif( args.type[0] == 'base' ):
				typ = 'B'
				if( args.k[0] == 16 ): size = 16
				elif( args.k[0] == 32 ): size = 32
				elif( args.k[0] == 64 ): size = 64
				else: size = 64
			elif( args.type[0] == 'xor' ):
				typ = 'X';flag = True
				size = 0
			elif( args.type[0] == 'hash' ):
				typ = 'H';action = 'E';question = 'encrypt'
				if( args.k[0] == 1 ): size = 1    # dsa
				elif( args.k[0] == 5 ): size = 5    # md5
				elif( args.k[0] == 160 ): size = 160    # ripemd
				elif( args.k[0] == 224 ): size = 224    # sha2
				elif( args.k[0] == 256 ): size = 256
				elif( args.k[0] == 384 ): size = 384
				elif( args.k[0] == 512 ): size = 512
				else:size = 5
			elif( args.type[0] == 'hmac' ):
				typ = 'M';action = 'E';question = 'encrypt';flag = True
				size = 0
			elif( args.type[0] == 'crc' ):
				typ = 'C';action = 'E';question = 'encrypt'
				if( args.k[0] == 31 ): size = 31    # adler
				elif( args.k[0] == 32 ): size = 32    # crc
				else:size = 32
			elif( args.type[0] == 'vige' ):
				typ = 'V';flag = True
				size = 0
			elif( args.type[0] == 'play' ):
				typ = 'P';flag = True
				size = 0
			else:
				typ = 'A';flag = True
				size = 16
		except AttributeError:
			typ = 'A';flag = True
			size = 16

		if( flag ):
			psw = u_UserCheck( r'[A-Za-z0-9@#$%^&+=]{6,20}', 'Insert your password: ' )

	except KeyboardInterrupt:    # Ctrl + C
		print()
		quit()

	if( u_UserInput( 'do you wanna %s your file with %s? [Y/N] ' % ( question, args.type[0] ) ) ):
		go = Main( root = root, name = name, psw = psw, size = size, action = action, purge = args.p, typ = typ )
	else:
		print('Quit')
		quit()
