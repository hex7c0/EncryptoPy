'''
crc.py: implements Checksum methods
http://docs.python.org/3.3/library/zlib.html
Author			0x7c0 (http://hex7c0.tk/)
Licensed under GPL License, Version 3.0 (http://www.gnu.org/licenses/gpl.html)

Created on 17/set/2013
@version: 0.1
@author: 0x7c0
'''

import zlib

class Crc( object ):
	def __init__( self, size ):
		'''
		costructor
		@param int size		type of hash, [31,32]
		'''

		self.size = size
		self.hash = 0

	def out( self ):
		''' simple output print '''

		print( 'Checksum: %s' % ( self.hash, ) )
	def update( self, data ):
		'''
		build correct hash algorithm
		@param byte data	data of file
		'''

		if( self.size == 31 ): self.hash += zlib.adler32( data )    # adler
		elif( self.size == 32 ): self.hash += zlib.crc32( data )    # crc
		return
