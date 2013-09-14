'''
Thread classes
Created on 10/set/2013
Licensed under GPL License, Version 3.0 (http://www.gnu.org/licenses/gpl.html)

@version: 0.1
@author: 0x7c0
'''

BUFFER = 4096
from queue import Empty
from threading import Thread

class AesCrypto( Thread ):
	'''
	class for encoding with aes encryption
	@param string psw	user password
	@param int size		type of aes, [16,24,32]
	@param char typ		type of encryption module
	@param queue r		queue for read data
	@param queue q		queue for write data
	'''

	def __init__( self, psw, size, typ, r, w ):
		from core.aes import AESModeOfOperation
		Thread.__init__( self, name = 'T_Crypto', args = ( r, w, ) )
		self.crypto = AESModeOfOperation()
		self.queR = r
		self.queW = w
		self.psw = psw
		self.size = size
		self.type = typ
		self.mode = 1
		self.hex = []
		self.iv = []
		self.makeHex()
	def terminate( self ):
		self._running = False
	def run( self ):
		''' start thread '''
		try:
			if( self.type == 'E' ):
				self.makeIv()
				self.queW.put( self.iv )
				while True:
					try:tmp = self.queR.get( timeout = 1 )
					except Empty:break
					if not tmp:break
					else:ciph = self.crypto.encrypt( tmp, self.mode, self.hex, self.size, self.iv );self.queW.put( ciph[2] );
			elif( self.type == 'D' ):
				try:IV = self.queR.get( timeout = 1 )    # iv
				except Empty:return
				while True:
					try:tmp = self.queR.get( timeout = 1 );
					except Empty:break
					if not tmp:break
					else:self.queW.put( self.crypto.decrypt( tmp, None, self.mode, self.hex, self.size, IV ) )
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: crypt!' )
		self._running = True
		return
	def makeHex( self ):
		''' hex user password '''
		for i in range( 0, self.size ):
			try:
				self.hex.append( int( ord( self.psw[i] ) ) )
			except IndexError:
				self.hex.append( i )
		return
	def makeIv( self ):
		''' make random iv for aes block '''
		from os import urandom
		for i in range( 0, self.size ):
			try:
				self.iv.append( int.from_bytes( urandom( 1 ), 'little' ) )
			except IndexError:
				self.iv.append( i )
		return
class BasCrypto( Thread ):
	'''
	class for encoding with base
	@param string psw	user password
	@param int size		type of aes, [16,32,64]
	@param char typ		type of encryption module
	@param queue r		queue for read data
	@param queue q		queue for write data
	'''

	def __init__( self, psw, size, typ, r, w ):
		Thread.__init__( self, name = 'T_Crypto', args = ( r, w, ) )
		self.queR = r
		self.queW = w
		self.psw = psw
		self.size = size
		self.type = typ
	def terminate( self ):
		self._running = False
	def run( self ):
		''' start thread '''
		try:
			if( self.type == 'E' ):
				self.queW.put( self.psw )
				while True:
					try:tmp = self.queR.get( timeout = 1 )
					except Empty:break
					if not tmp:break
					else:
						try:self.queW.put( self.encode( tmp ) );
						except TypeError:print( 'File not correct!' );return
			elif( self.type == 'D' ):
				try:IV = self.queR.get( timeout = 1 )    # iv
				except Empty:return
				if( IV != self.psw ):print( 'Password Wrong!' );return
				while True:
					try:tmp = self.queR.get( timeout = 1 );
					except Empty:break
					if not tmp:break
					else:
						try:self.queW.put( self.decode( tmp ) )
						except TypeError:print( 'File not correct!' );return
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: crypt!' )
		self._running = True
		return
	def encode(self, i):
		'''
		encode data with select base
		@param bin i	binary data
		'''
		if(self.size==16):
			from base64 import b16encode;return b16encode( i )
		elif( self.size == 32 ):
			from base64 import b32encode;return b32encode( i )
		else:
			from base64 import b64encode;return b64encode( i )
	def decode( self, i ):
		'''
		decode data with select base
		@param bin i	binary data
		'''
		if( self.size == 16 ):
			from base64 import b16decode;return b16decode( i )
		elif( self.size == 32 ):
			from base64 import b32decode;return b32decode( i )
		else:
			from base64 import b64decode;return b64decode( i )
class XorCrypto( Thread ):
	'''
	class for encoding with xor encryption
	@param string psw	user password
	@param char typ		type of encryption module
	@param queue r		queue for read data
	@param queue q		queue for write data
	'''
	def __init__( self, psw, typ, r, w ):
		Thread.__init__( self, name = 'T_Crypto', args = ( r, w, ) )
		self.queR = r
		self.queW = w
		self.psw = psw
		self.type = typ
	def terminate( self ):
		self._running = False
	def run( self ):
		''' start thread '''
		try:
			if( self.type == 'E' ):
				self.queW.put( '%' )    # useless
				while True:
					try:tmp = self.queR.get( timeout = 1 )
					except Empty:break
					if not tmp:break
					else:self.queW.put( self.xor( tmp ) )
			elif( self.type == 'D' ):
				try:self.queR.get( timeout = 1 )    # useless
				except Empty:return
				while True:
					try:tmp = self.queR.get( timeout = 1 );
					except Empty:break
					if not tmp:break
					else:self.queW.put( self.xor( tmp ) )
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: crypt!' )
		self._running = True
		return
	def xor( self, data ):
		'''
		encode/decode data with xor
		@param bin dara	binary data
		'''
		from itertools import cycle
		a = bytearray()
		for ( x, y ) in zip( data, cycle( self.psw ) ):
			if( type( x ) == str ):x = ord( x )
			if( type( y ) == str ):y = ord( y )
			a.append( x ^ y )
		return a
class IRead( Thread ):
	'''
	class for read normal/encrypted file
	@param string file	root of write file
	@param queue r		queue for read data
	@param char typ		type of encryption module
	'''

	def __init__( self, file, r, typ ):
		Thread.__init__( self, name = 'T_R_%s' % ( file, ), args = ( r, ) )
		self.file = file
		self.que = r
		self.type = typ
	def terminate( self ):
		self._running = False
	def run( self ):
		try:
			with open( self.file, 'r+b' ) as File:
				if( self.type == 'E' ):
					while True:
						tmp = File.read( BUFFER )
						if not tmp: break
						else: self.que.put( tmp );
				elif( self.type == 'D' ):
					from pickle import load, UnpicklingError
					try:self.que.put( load( File ) )    # iv
					except UnpicklingError: print( 'File not correct!' );return
					while True:
						try:
							tmp = load( File )
							if not tmp: break
							self.que.put( tmp )
						except EOFError: break
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: read!' )
		self._running = True
		return
class IWrit( Thread ):
	'''
	class for write encrypted/normal file
	@param string file	root of write file
	@param queue q		queue for write data
	@param char typ		type of encryption module
	'''

	def __init__( self, file, q, typ ):
		Thread.__init__( self, name = 'T_W_%s' % ( file, ), args = ( q, ) )
		self.file = file
		self.que = q
		self.type = typ
	def terminate( self ):
		self._running = False
	def run( self ):
		try:
			with open( self.file, 'w+b' ) as File:
				if( self.type == 'E' ):
					from pickle import dump
					while True:
						try:tmp = self.que.get( timeout = 2 )
						except Empty:break
						if not tmp:break
						else:dump( tmp, File );
				elif( self.type == 'D' ):
					while True:
						try:tmp = self.que.get( timeout = 2 )
						except Empty:break
						if not tmp:break
						else:File.write( tmp )
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: write!' )
		# print( 'Write done.' )
		self._running = True
		return
