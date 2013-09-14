#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
Main File
Created on 10/set/2013
Licensed under GPL License, Version 3.0 (http://www.gnu.org/licenses/gpl.html)

@version: 0.1
@author: 0x7c0
'''

VERSION = 0.1
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
		elif( typ == 'B' ):
			from core.thread import BasCrypto
			self.cr = BasCrypto( psw, size, action, self.r, self.w )
		elif ( typ == 'X' ):
			from core.thread import XorCrypto
			self.cr = XorCrypto( psw, action, self.r, self.w )
		elif ( typ == 'H' ):
			pass
			# from core.thread import HasCrypto
			# self.cr = HasCrypto( psw, size, action, self.r, self.w )
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

	parser = argparse.ArgumentParser( description = 'Run CryptoPhy.' )
	parser.add_argument( '-V', '--version', action = 'version', version = VERSION )

	group1 = parser.add_argument_group( title = 'required flag' )
	group1.add_argument( '-r', metavar = 'Root', nargs = 1, type = M_file, help = 'insert root of your file', required = True )

	group2 = parser.add_subparsers()
	enc = group2.add_parser( 'T', help = 'type of encryption/decryption' )
	enc.add_argument( 'type', nargs = 1, type = str, choices = ['aes', 'base', 'xor', 'hash'], default = ['aes'] )

	group3 = parser.add_mutually_exclusive_group( required = True )
	group3.add_argument( '-E', '--encrypt', action = 'store_true', default = False, help = 'encrypt your file' )
	group3.add_argument( '-D', '--decrypt', action = 'store_true', default = False, help = 'decrypt your file' )

	group4 = parser.add_argument_group( title = 'optional flag' )
	group4.add_argument( '-k', metavar = 'Key', nargs = 1, type = int, choices = [16, 32, 64, 128, 192, 256], default = [128], help = 'set the size of the key' )
	group4.add_argument( '-n', metavar = 'Name', nargs = 1, type = str, help = 'set name of your new file' )
	group4.add_argument( '-p', action = 'store_true', default = False, help = 'purge original file after the process' )

	args = parser.parse_args()
	del argparse

	try:
		name = '';psw = '';size = '';action = ''; purge = ''; typ = ''

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

		psw = u_UserCheck( r'[A-Za-z0-9@#$%^&+=]{6,20}', 'Insert your password: ' )

		try:
			if( args.type[0] == 'aes' ):
				typ = 'A'
				if( args.k[0] == 128 ): size = 16
				elif( args.k[0] == 192 ): size = 24
				elif( args.k[0] == 256 ): size = 32
				else: size = 16
			elif( args.type[0] == 'base' ):
				typ = 'B'
				if( args.k[0] == 16 ): size = 16
				elif( args.k[0] == 32 ): size = 32
				elif( args.k[0] == 64 ): size = 64
				else: size = 64
			elif( args.type[0] == 'xor' ):
				typ = 'X'
				size = 0
			elif( args.type[0] == 'hash' ):
				typ = 'H'
				size = 0
			else:
				typ = 'A'
				size = 16
		except AttributeError:
			typ = 'A'
			size = 16

		if( args.decrypt ): action = 'D';question='decrypt'
		elif( args.encrypt ): action = 'E';question='encrypt'
	except KeyboardInterrupt:    # Ctrl + C
		print()
		quit()

	if( u_UserInput( 'do you wanna %s your file? [Y/N] ' % ( question, ) ) ):
		go = Main( root = root, name = name, psw = psw, size = size, action = action, purge = args.p, typ = typ )
	else:
		print('Quit')
		quit()
