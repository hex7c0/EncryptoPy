'''
vigene.py: implements Vigenère cypher
http://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher
Author			0x7c0 (http://hex7c0.tk/)
Licensed under GPL License, Version 3.0 (http://www.gnu.org/licenses/gpl.html)

Created on 17/set/2013
@version: 0.1
@author: 0x7c0
'''

from itertools import cycle

class Vigenere( object ):
	def __init__( self, key ):
		self.key = key
	
	def encrypt( self, raw ):
		
		t = bytearray()
		for ( x, y ) in zip( raw, cycle( self.key ) ):
			y = ord( y )
			if( y >= 256 ):y -= 256
			try:t.append( x + y )
			except ValueError:t.append( ( x - 256 ) + y )
		return t
	def decrypt( self, raw ):

		t = bytearray()
		for ( x, y ) in zip( raw, cycle( self.key ) ):
			y = ord( y )
			if( y >= 256 ):y -= 256
			try:t.append( x - y )
			except ValueError:t.append( ( x + 256 ) - y )
		return t
