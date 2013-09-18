'''
hmac.py: implements protected Hashing method
http://docs.python.org/3.3/library/hmac.html
Author			0x7c0 (http://hex7c0.tk/)
Licensed under GPL License, Version 3.0 (http://www.gnu.org/licenses/gpl.html)

Created on 17/set/2013
@version: 0.1
@author: 0x7c0
'''

import hmac

class Hmac( object ):
	def __init__( self, psw ):
		'''
		costructor
		@param string psw	user password
		'''

		self.hash = hmac.new( str.encode( psw ) )

	def out( self ):
		''' simple output print '''

		print( 'Hash: %s' % ( self.hash.hexdigest(), ) )
