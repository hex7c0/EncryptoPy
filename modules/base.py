'''
base.py: implements base encoding
http://docs.python.org/3.3/library/base64.html
Author			0x7c0 (http://hex7c0.tk/)
Licensed under GPL License, Version 3.0 (http://www.gnu.org/licenses/gpl.html)

Created on 10/set/2013
@version: 0.1
@author: 0x7c0
'''

import base64

class Base( object ):
	def __init__( self, size ):
		'''
		costructor
		@param int size		type of base, [16,32,64]
		'''

		self.size = size

	def encode( self, i ):
		'''
		encode data with select base
		@param bin i	binary data
		'''

		if( self.size == 16 ):
			return base64.b16encode( i )
		elif( self.size == 32 ):
			return base64.b32encode( i )
		else:
			return base64.b64encode( i )
	def decode( self, i ):
		'''
		decode data with select base
		@param bin i	binary data
		'''

		if( self.size == 16 ):
			return base64.b16decode( i )
		elif( self.size == 32 ):
			return base64.b32decode( i )
		else:
			return base64.b64decode( i )
