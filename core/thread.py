'''
Thread classes
Created on 10/set/2013
Licensed under GPL License, Version 3.0 (http://www.gnu.org/licenses/gpl.html)

@version: 0.3
@author: 0x7c0
'''

BUFFER = 4096
from queue import Empty
from threading import Thread

class AesCrypto( Thread ):
	'''
	wrapper class for encoding with aes encryption
	@param string psw	user password
	@param int size		type of aes, [16,24,32]
	@param char typ		type of encryption module
	@param queue r		queue for read data
	@param queue q		queue for write data
	'''

	def __init__( self, psw, size, typ, r, w ):
		from modules.aes import AESModeOfOperation,makeHex,makeIv
		Thread.__init__( self, name = 'T_Crypto', args = ( r, w, ) )
		self.crypto = AESModeOfOperation()
		self.queR = r
		self.queW = w
		self.size = size
		self.type = typ
		self.mode = 1
		self.hex = makeHex(psw,size)
		self.iv = makeIv( size )
	def terminate( self ):
		self._running = False
	def run( self ):
		''' start thread '''
		try:
			if( self.type == 'E' ):
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
class DesCrypto( Thread ):
	'''
	wrapper class for encoding with des encryption
	@param string psw	user password
	@param char typ		type of encryption module
	@param queue r		queue for read data
	@param queue q		queue for write data
	'''

	def __init__( self, psw, typ, r, w ):
		from modules.des import Des, makeHex
		Thread.__init__( self, name = 'T_Crypto', args = ( r, w, ) )
		self.crypto = Des( '', makeHex( psw ), typ )
		self.queR = r
		self.queW = w
		self.type = typ
	def terminate( self ):
		self._running = False
	def run( self ):
		''' start thread '''
		try:
			if( self.type == 'E' ):
				while True:
					try:tmp = self.queR.get( timeout = 1 )
					except Empty:break
					if not tmp:break
					else:self.crypto._message = tmp;self.queW.put( self.crypto.crypt() );
			elif( self.type == 'D' ):
				while True:
					try:tmp = self.queR.get( timeout = 1 );
					except Empty:break
					if not tmp:break
					else:self.crypto._message = tmp;self.queW.put( self.crypto.crypt() )
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: crypt!' )
		self._running = True
		return
class BasCrypto( Thread ):
	'''
	wrapper class for encoding with base
	@param int size		type of base, [16,32,64]
	@param char typ		type of encryption module
	@param queue r		queue for read data
	@param queue q		queue for write data
	'''

	def __init__( self, size, typ, r, w ):
		from modules.base import Base
		Thread.__init__( self, name = 'T_Crypto', args = ( r, w, ) )
		self.crypto = Base( size )
		self.queR = r
		self.queW = w
		self.type = typ
	def terminate( self ):
		self._running = False
	def run( self ):
		''' start thread '''
		try:
			if( self.type == 'E' ):
				while True:
					try:tmp = self.queR.get( timeout = 1 )
					except Empty:break
					if not tmp:break
					else:
						try:self.queW.put( self.crypto.encode( tmp ) );
						except TypeError:print( 'File not correct!' );return
			elif( self.type == 'D' ):
				while True:
					try:tmp = self.queR.get( timeout = 1 );
					except Empty:break
					if not tmp:break
					else:
						try:self.queW.put( self.crypto.decode( tmp ) )
						except TypeError:print( 'File not correct!' );return
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: crypt!' )
		self._running = True
		return
class XorCrypto( Thread ):
	'''
	wrapper class for encoding with xor encryption
	@param string psw	user password
	@param char typ		type of encryption module
	@param queue r		queue for read data
	@param queue q		queue for write data
	'''
	
	def __init__( self, psw, typ, r, w ):
		from modules.xor import Xor
		Thread.__init__( self, name = 'T_Crypto', args = ( r, w, ) )
		self.crypto = Xor( psw )
		self.queR = r
		self.queW = w
		self.type = typ
	def terminate( self ):
		self._running = False
	def run( self ):
		''' start thread '''
		try:
			if( self.type == 'E' ):
				while True:
					try:tmp = self.queR.get( timeout = 1 )
					except Empty:break
					if not tmp:break
					else:self.queW.put( self.xor( tmp ) )
			elif( self.type == 'D' ):
				while True:
					try:tmp = self.queR.get( timeout = 1 );
					except Empty:break
					if not tmp:break
					else:self.queW.put( self.xor( tmp ) )
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: crypt!' )
		self._running = True
		return
class HasCrypto( Thread ):
	'''
	wrapper class for encoding with hash
	@param int size		type of hash, [1,5,160,224,256,384,512]
	@param queue r		queue for read data
	@param queue q		queue for write data
	'''

	def __init__( self, size, r, w ):
		Thread.__init__( self, name = 'T_Crypto', args = ( r, w, ) )
		self.queR = r
		self.queW = w
		self.hash = ''
		self.build( size )
	def terminate( self ):
		self._running = False
	def run( self ):
		''' start thread '''
		try:
			while True:
				try:tmp = self.queR.get( timeout = 1 );
				except Empty:break
				if not tmp:break
				else:self.hash.update( tmp )
			self.queW.put( self.hash.digest() )
			print( 'Hash: %s' % ( self.hash.hexdigest(), ) )
			return
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: crypt!' )
		self._running = True
		return
	def build( self, size ):
		'''
		build correct hash algorithm
		@param int size	type of algorithms
		'''
		import hashlib
		if( size == 1 ): self.hash = hashlib.new( 'DSA' )    # dsa
		elif( size == 5 ): self.hash = hashlib.new( 'MD5' )    # md5
		elif( size == 160 ): self.hash = hashlib.new( 'RIPEMD160' )    # ripemd
		elif( size == 224 ): self.hash = hashlib.new( 'SHA224' )    # sha2
		elif( size == 256 ): self.hash = hashlib.new( 'SHA256' )
		elif( size == 384 ): self.hash = hashlib.new( 'SHA384' )
		elif( size == 512 ): self.hash = hashlib.new( 'SHA512' )
		return
class MacCrypto( Thread ):
	'''
	wrapper class for encoding with hmac
	@param string psw	user password
	@param queue r		queue for read data
	@param queue q		queue for write data
	'''

	def __init__( self, psw, r, w ):
		import hmac
		Thread.__init__( self, name = 'T_Crypto', args = ( r, w, ) )
		self.queR = r
		self.queW = w
		self.hash = hmac.new( str.encode( psw ) )
	def terminate( self ):
		self._running = False
	def run( self ):
		''' start thread '''
		try:
			while True:
				try:tmp = self.queR.get( timeout = 1 );
				except Empty:break
				if not tmp:break
				else:self.hash.update( tmp )
			self.queW.put( self.hash.digest() )
			print( 'Hash: %s' % ( self.hash.hexdigest(), ) )
			return
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: crypt!' )
		self._running = True
		return
class CrcCrypto( Thread ):
	'''
	wrapper class for encoding with crc
	@param int size		type of hash, [31,32]
	@param queue r		queue for read data
	@param queue q		queue for write data
	'''

	def __init__( self, size, r, w ):
		Thread.__init__( self, name = 'T_Crypto', args = ( r, w, ) )
		self.queR = r
		self.queW = w
		self.size = size
		self.hash = 0
	def terminate( self ):
		self._running = False
	def run( self ):
		''' start thread '''
		try:
			while True:
				try:tmp = self.queR.get( timeout = 1 );
				except Empty:break
				if not tmp:break
				else:self.update( tmp )
			self.queW.put( self.hash )
			print( 'Checksum: %s' % ( self.hash, ) )
			return
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: crypt!' )
		self._running = True
		return
	def update( self, data ):
		'''
		build correct hash algorithm
		@param byte data	data of file
		'''
		import zlib
		if( self.size == 31 ): self.hash += zlib.adler32( data )    # adler
		elif( self.size == 32 ): self.hash += zlib.crc32( data )    # crc
		return
class VigCrypto( Thread ):
	'''
	wrapper class for encoding with Vigenère
	@param char typ		type of encryption module
	@param string psw	user password
	@param queue r		queue for read data
	@param queue q		queue for write data
	'''

	def __init__( self, typ, psw, r, w ):
		from modules.vigenere import Vigenere
		Thread.__init__( self, name = 'T_Crypto', args = ( r, w, ) )
		self.crypto = Vigenere( psw )
		self.type = typ
		self.queR = r
		self.queW = w
	def terminate( self ):
		self._running = False
	def run( self ):
		''' start thread '''
		try:
			if( self.type == 'E' ):
				while True:
					try:tmp = self.queR.get( timeout = 1 )
					except Empty:break
					if not tmp:break
					else:self.queW.put( self.crypto.encrypt( tmp ) );
			elif( self.type == 'D' ):
				while True:
					try:tmp = self.queR.get( timeout = 1 );
					except Empty:break
					if not tmp:break
					else:self.queW.put( self.crypto.decrypt( tmp ) )
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: crypt!' )
		self._running = True
		return
class PlaCrypto( Thread ):
	'''
	wrapper class for encoding with Vigenère
	@param char typ		type of encryption module
	@param string psw	user password
	@param queue r		queue for read data
	@param queue q		queue for write data
	'''

	def __init__( self, typ, psw, r, w ):
		from modules.playfair import Playfair
		Thread.__init__( self, name = 'T_Crypto', args = ( r, w, ) )
		self.crypto = Playfair( psw )
		self.type = typ
		self.queR = r
		self.queW = w
	def terminate( self ):
		self._running = False
	def run( self ):
		''' start thread '''
		try:
			if( self.type == 'E' ):
				while True:
					try:tmp = self.queR.get( timeout = 1 )
					except Empty:break
					if not tmp:break
					else:self.queW.put( self.crypto.encrypt( tmp ) )
			elif( self.type == 'D' ):
				while True:
					try:tmp = self.queR.get( timeout = 1 );
					except Empty:break
					if not tmp:break
					else:self.queW.put( self.crypto.decrypt( tmp ) )
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: crypt!' )
		self._running = True
		return

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
			tmp = self.que.get( timeout = 2 )
			if( not tmp ):
				with open( self.file, 'w+b' ) as File:
					if( self.type == 'E' ):
						from pickle import dump
						dump( tmp, File );
						while True:
							try:tmp = self.que.get( timeout = 2 )
							except Empty:break
							if not tmp:break
							else:dump( tmp, File );
					elif( self.type == 'D' ):
						File.write( tmp )
						while True:
							try:tmp = self.que.get( timeout = 2 )
							except Empty:break
							if not tmp:break
							else:File.write( tmp )
		except Empty:return
		except KeyboardInterrupt:    # Ctrl + C
			print( 'Not finished: write!' )
		# print( 'Write done.' )
		self._running = True
		return
