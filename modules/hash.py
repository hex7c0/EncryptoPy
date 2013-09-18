'''
hash.py: implements Hashing method
http://docs.python.org/3.3/library/hashlib.html
Author			0x7c0 (http://hex7c0.tk/)
Licensed under GPL License, Version 3.0 (http://www.gnu.org/licenses/gpl.html)

Created on 17/set/2013
@version: 0.1
@author: 0x7c0
'''

import hashlib

class Hash( object ):
	def __init__( self, size ):
		'''
		costructor
		@param int size		type of hash, [1,5,160,224,256,384,512]
		'''

		if( size == 1 ): self.hash = hashlib.new( 'DSA' )    # dsa
		elif( size == 5 ): self.hash = hashlib.new( 'MD5' )    # md5
		elif( size == 160 ): self.hash = hashlib.new( 'RIPEMD160' )    # ripemd
		elif( size == 224 ): self.hash = hashlib.new( 'SHA224' )    # sha2
		elif( size == 256 ): self.hash = hashlib.new( 'SHA256' )
		elif( size == 384 ): self.hash = hashlib.new( 'SHA384' )
		elif( size == 512 ): self.hash = hashlib.new( 'SHA512' )

	def out( self ):
		''' simple output print '''

		print( 'Hash: %s' % ( self.hash.hexdigest(), ) )
