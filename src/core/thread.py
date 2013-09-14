'''
Thread classes
Created on 10/set/2013

@version: 0.1
@author: 0x7c0
'''

BUFFER = 4096
from queue import Empty
from threading import Thread

class AesCrypto( Thread ):
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
		for i in range( 0, self.size ):
			try:
				self.hex.append( int( ord( self.psw[i] ) ) )
			except IndexError:
				self.hex.append( i )
		return
	def makeIv( self ):
		from os import urandom
		for i in range( 0, self.size ):
			try:
				self.iv.append( int.from_bytes( urandom( 1 ), 'little' ) )
			except IndexError:
				self.iv.append( i )
		return
class BasCrypto( Thread ):
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
		if(self.size==16):
			from base64 import b16encode;return b16encode( i )
		elif( self.size == 32 ):
			from base64 import b32encode;return b32encode( i )
		else:
			from base64 import b64encode;return b64encode( i )
	def decode( self, i ):
		if( self.size == 16 ):
			from base64 import b16decode;return b16decode( i )
		elif( self.size == 32 ):
			from base64 import b32decode;return b32decode( i )
		else:
			from base64 import b64decode;return b64decode( i )
class XorCrypto( Thread ):
	def __init__( self, psw, typ, r, w ):
		Thread.__init__( self, name = 'T_Crypto', args = ( r, w, ) )
		self.queR = r
		self.queW = w
		self.psw = psw
		self.type = typ
	def terminate( self ):
		self._running = False
	def run( self ):
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
		from itertools import cycle
		a = bytearray()
		for ( x, y ) in zip( data, cycle( self.psw ) ):
			if( type( x ) == str ):x = ord( x )
			if( type( y ) == str ):y = ord( y )
			a.append( x ^ y )
		return a
class IRead( Thread ):
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
