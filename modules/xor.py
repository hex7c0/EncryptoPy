'''
xor.py: implements xor encryption
http://en.wikipedia.org/wiki/XOR_cipher
Author			0x7c0 (http://hex7c0.tk/)
Licensed under GPL License, Version 3.0 (http://www.gnu.org/licenses/gpl.html)

Created on 10/set/2013
@version: 0.1
@author: 0x7c0
'''

from itertools import cycle

class Xor( object ):
	def __init__( self, psw ):
		'''
		costructor
		@param string psw	user password
		'''

		self.psw = psw

	def coding( self, data ):
		'''
		encode/decode data with xor
		@param bin dara	binary data
		'''

		a = bytearray()
		for ( x, y ) in zip( data, cycle( self.psw ) ):
			if( type( x ) == str ):x = ord( x )
			if( type( y ) == str ):y = ord( y )
			a.append( x ^ y )
		return a
