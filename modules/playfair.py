'''
playfair.py: implements Playfair cypher
http://en.wikipedia.org/wiki/Playfair_cipher
Author			0x7c0 (http://hex7c0.tk/)
Licensed under GPL License, Version 3.0 (http://www.gnu.org/licenses/gpl.html)

due limitation of chiper, use this module only with normal text

Created on 17/set/2013
@version: 0.1
@author: 0x7c0
'''

MATRIX = 8
LIMIT_E = MATRIX - 1
LIMIT_D = MATRIX - MATRIX
EXCEPT = 255
EXCEPT2 = 5

class Playfair( object ):
	def __init__( self, key ):
		'''
		costructor
		@param string key	user passoword
		'''

		self.key = [ [ 0 for i in range( MATRIX ) ] for j in range( MATRIX ) ]
		self.buildCiph(key)
		self.store = self.buildDict()
		'''self.test = [ 0 for i in range( 256 ) ]'''

	def encrypt( self, raw ):
		'''
		encrypt function
		@param byte raw		read file
		'''

		t = bytearray()
		data = self.buildDig( raw )
		for all in range( len( data ) ):
			x1 = x2 = False    # out range
			# fast operation
			if( data[all][0] in self.store ):
				x1 = [self.store[data[all][0]][0], self.store[data[all][0]][1]]
			if( data[all][1] in self.store ):
				x2 = [self.store[data[all][1]][0], self.store[data[all][1]][1]]
			if( not x1 or not x2 ):    # not found
				t.append( data[all][0] )    # normal
				t.append( data[all][1] )    # normal
			elif( x1[0] == x2[0] ):    # row
				# element shift right # SHIFT Y
				if( ( x1[1] + 1 ) > LIMIT_E ): t.append( self.key[ x1[0] ][ LIMIT_D ] )
				else:
					t.append( self.key[ x1[0] ][ ( x1[1] ) + 1 ] )    # same row (X)
				if( ( x2[1] + 1 ) > LIMIT_E ): t.append( self.key[ x1[0] ][ LIMIT_D ] )
				else:
					t.append( self.key[ x1[0] ][ ( x2[1] ) + 1 ] )    # same row (X)
			elif( x1[1] == x2[1] ):    # column
				# element shift down # SHIFT X
				if( ( x1[0] + 1 ) > LIMIT_E ): t.append( self.key[ LIMIT_D ][ x1[1] ] )
				else:
					t.append( self.key[ ( x1[0] + 1 ) ][ x1[1] ] )    # same column (Y)
				if( ( x2[0] + 1 ) > LIMIT_E ): t.append( self.key[ LIMIT_D ][ x1[1] ] )
				else:
					t.append( self.key[ ( x2[0] + 1 ) ][ x1[1] ] )    # same column (Y)
			else:    # square
				t.append( self.key[ ( x1[0] ) ][ x2[1] ] )    # same row,opposite column
				t.append( self.key[ ( x2[0] ) ][ x1[1] ] )    # same row,opposite column
		return t
	def decrypt( self, raw ):
		'''
		decrypt function
		@param byte raw		read file
		'''

		t = [];
		data = self.buildDig( raw )
		for all in range( len( data ) ):
			x1 = x2 = False    # out range
			# fast operation
			if( data[all][0] in self.store ):
				x1 = [self.store[data[all][0]][0], self.store[data[all][0]][1]]
			if( data[all][1] in self.store ):
				x2 = [self.store[data[all][1]][0], self.store[data[all][1]][1]]
			'''for i in range( MATRIX ):
				for j in range( MATRIX ):
					if( data[all][0] == self.key[i][j] ):    # first
						x1 = [ i, j ]
					if( data[all][1] == self.key[i][j] ):    # second
						x2 = [ i, j ]
					if( x1 and x2 ):break;    # save time
				if( x1 and x2 ):break;    # save time'''
			if( not x1 or not x2 ):    # not found
				t.append( [ data[all][0], data[all][1] ] )    # normal
			elif( x1[0] == x2[0] ):    # row
				buffer = []
				# element shift left # SHIFT Y
				if( ( x1[1] - 1 ) < LIMIT_D ):buffer.append( self.key[ x1[0] ][ LIMIT_E ] )
				else:
					buffer.append( self.key[ x1[0] ][ ( x1[1] ) - 1 ] )    # same row (X)
				if( ( x2[1] - 1 ) < LIMIT_D ): buffer.append( self.key[ x1[0] ][ LIMIT_E ] )
				else:
					buffer.append( self.key[ x1[0] ][ ( x2[1] ) - 1 ] )    # same row (X)
				t.append( buffer )
			elif( x1[1] == x2[1] ):    # column
				buffer = []
				# element shift up # SHIFT X
				if( ( x1[0] - 1 ) < LIMIT_D ): buffer.append( self.key[ LIMIT_E ][ x1[1] ] )
				else:
					buffer.append( self.key[ ( x1[0] - 1 ) ][ x1[1] ] )    # same column (Y)
				if( ( x2[0] - 1 ) < LIMIT_D ): buffer.append( self.key[ LIMIT_E ][ x1[1] ] )
				else:
					buffer.append( self.key[ ( x2[0] - 1 ) ][ x1[1] ] )    # same column (Y)
				t.append( buffer )
			else:    # square
				t.append( [ self.key[ ( x1[0] ) ][ x2[1] ], self.key[ ( x2[0] ) ][ x1[1] ] ] )    # same row,opposite column
		return self.rebuild( t )
	def rebuild( self, arr ):
		'''
		rebuild original message
		because on original we've use '0'
		for duplicate letters or single char
		@param array arr	result of decrypt 2D
		'''

		t = bytearray()
		for i in range( len( arr ) ):
			if( arr[i][1] == EXCEPT or arr[i][1] == EXCEPT2 ):
				before = False;after = True
				try:before = arr[i][0]    # if first string
				except IndexError:before = False
				else:
					try:after = arr[i + 1][0]
					except IndexError:after = False
				if( arr[i][1] == EXCEPT and type( before ) != bool and before == after ):    # EXCEPT char for divide same letters
					t.append( arr[i][0] );
				elif( arr[i][1] == EXCEPT2 and type( before ) != bool and before == after == EXCEPT ):    # exception of exception :)
					t.append( arr[i][0] );
				elif( before and not after and ( i + 1 ) >= len( arr ) ):    # last element
					t.append( arr[i][0] );
				else:    # false positive
					t.append( arr[i][0] );t.append( arr[i][1] )
			else:
				t.append( arr[i][0] );t.append( arr[i][1] )
		return t
	def buildDict(self):
		''' build a dictionary for fast view '''

		from collections import defaultdict
		d = defaultdict( list )
		for i in range( MATRIX ):
			for j in range( MATRIX ):
				d[self.key[i][j]].append( i )
				d[self.key[i][j]].append( j )
		return d
	def buildCiph( self, key ):
		'''
		build key matrix with A-Za-z0-9.
		see the wiki for the build of this chiper
		different from wiki, I've insert all base64 chat (except '=')
		for a 8x8 matrix with more char hit.
		I have not built the multidimensional array (table[][])
		due to the limits of Python (not NumPy)
		#self.key = [ [ 0 for i in range(5) ] for j in range(5) ]
		@param string key	hash of password
		'''

		from string import ascii_letters, digits
		from base64 import b64encode
		alpha = ascii_letters + digits + '+/'
		point = 0
		tmp = []    # temporary list
		# strip same char and add more different random char
		key = b64encode( b64encode( key.encode() ) )
		key = key.decode()
		key = ''.join( sorted( set( key ), key = key.index ) )
		for i in range( MATRIX * MATRIX ):
			try:char = key[i]
			except IndexError:char = '/'
			if( char not in tmp and char != '=' ):
				tmp.append( char )
			else:
				for r in range( point, len( alpha ) ):
					if( alpha[r] not in tmp ):
						tmp.append( alpha[r] )
						point = r
						break
		# build multidimensional array
		a = 0
		for i in range( MATRIX ):
			for j in range( MATRIX ):
				self.key[i][j] = ord( tmp[a] )
				a += 1
		return
	def buildDig( self, raw ):
		'''
		build 2D matrix with bytes of text
		see the wiki for the build of this digraphs
		'''

		digrafo = []
		a = 0
		for i in range( len( raw ) ):
			# not 'int( len( raw ) / 2 )' bacause
			# with shift elements, can lost some elements
			if( a >= len( raw ) ):break;
			'''self.test[raw[a]] += 1'''
			first = raw[a]
			try:second = raw[a + 1]    # last element, put EXCEPT char
			except IndexError:second = EXCEPT
			if( first != second ):
				digrafo.append( [first, second] );a += 2
			else:    # equal
				# shift second element, and add EXCEPT char
				if( second == EXCEPT ):
					digrafo.append( [first, EXCEPT2] )    # exception of exception :)
				else:
					digrafo.append( [first, EXCEPT] )
				a += 1
		return digrafo
