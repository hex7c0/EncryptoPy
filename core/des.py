'''
des.py: implements DES - Data Encryption Standard
from the DES project, https://github.com/sfyoung/DES
author			S.F.Young (https://github.com/sfyoung)
Tweak by		0x7c0 (http://hex7c0.tk/)
License: Public Domain - free to do as you wish
Created on 2013-5-28
Version: 1.0

Created on 10/set/2013
@version: 0.1
@author: 0x7c0
'''

class Des( object ):

	# Some manipulations of Key
	# The Key of DES is 64bits, but exactly we only use 56bits of them. The remaining 8bits are parity bits.
	# choose 56bits from 64bits key, permuted choice 1:
	__PC1 = [56, 48, 40, 32, 24, 16, 8,
			0, 57, 49, 41, 33, 25, 17,
			9, 1, 58, 50, 42, 34, 26,
			18, 10, 2, 59, 51, 43, 35,
			62, 54, 46, 38, 30, 22, 14,
			6, 61, 53, 45, 37, 29, 21,
			13, 5, 60, 52, 44, 36, 28,
			20, 12, 4, 27, 19, 11, 3]

	# Then the exactly 56bits key was devided to two parts, each parts is 28bits.
	# generate 16 rounds key with left-rotating operation of the key:
	__left_rotations = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

	# Each round, choose 48 bits from 56 bits, permuted choice 2:
	__PC2 = [13, 16, 10, 23, 0, 4,
			2, 27, 14, 5, 20, 9,
			22, 18, 11, 3, 25, 7,
			15, 6, 26, 19, 12, 1,
			40, 51, 30, 36, 46, 54,
			29, 39, 50, 44, 32, 47,
			43, 48, 38, 55, 33, 52,
			45, 41, 49, 35, 28, 31]
# Manipulations of Key end.

	# Some manipulation of Message:
	# For the message, you must do initial permutation on it:
	__IP = [57, 49, 41, 33, 25, 17, 9, 1,
			59, 51, 43, 35, 27, 19, 11, 3,
			61, 53, 45, 37, 29, 21, 13, 5,
			63, 55, 47, 39, 31, 23, 15, 7,
			56, 48, 40, 32, 24, 16, 8, 0,
			58, 50, 42, 34, 26, 18, 10, 2,
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6]

	# Then the new message was devided to two parts, each part is 32bits long.
	# For the right parts, it must be expanded to 48bits.
	__E = [31, 0, 1, 2, 3, 4,
		   3, 4, 5, 6, 7, 8,
		   7, 8, 9, 10, 11, 12,
		   11, 12, 13, 14, 15, 16,
		   15, 16, 17, 18, 19, 20,
		   19, 20, 21, 22, 23, 24,
		   23, 24, 25, 26, 27, 28,
		   27, 28, 29, 30, 31, 0]

	# And then S-Boxes:
	__sbox = [
			  # S1
			[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
			0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
			4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
			15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

			# S2
			[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
			3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
			0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
			13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

			  # S3
			[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
			13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
			13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
			1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

			  # S4
			[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
			13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
			10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
			3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

			  # S5
			[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
			14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
			4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
			11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

			  # S6
			[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
			10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
			9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
			4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

			  # S7
			[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
			13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
			1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
			6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

			  # S8
			[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
			1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
			7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
			2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
			  ]

	# Apply 32 bits permutation on the output of S-Boxes:
	__P = [
		   15, 6, 19, 20, 28, 11,
		   27, 16, 0, 14, 22, 25,
		   4, 17, 30, 9, 1, 7,
		   23, 13, 31, 26, 2, 8,
		   18, 12, 29, 5, 21, 10,
		   3, 24
		   ]

	# Then the final permutation, it is the inverse of IP
	__FP = [
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25,
			32, 0, 40, 8, 48, 16, 56, 24
			]
	# Manipulations of Message end.

	def __init__( self, message = bytes( [0] * 8 ), key = bytes( [0] * 8 ), crypt = 'E' ):
		self._message = message
		self._key = key
		self._crypt = crypt
		self._subKey = [[0] * 48] * 16
	# Pad mode is PKSC#5.
	def __getPadingData( self, data ):
		l = len( data ) % 8
		if l == 0:
			return bytes( [8] * 8 )
		else:
			return bytes( [8 - l] * ( 8 - l ) )
	# Get the source message.
	def getMessage( self ):
		return self._message
	# Get the source Key.
	def getKey( self ):
		return self._key
	# Get the crypt mode, it can be 'en' of encrypt or 'de' of decrypt.
	def getCrypt( self ):
		return self._crypt
	# Change a text message into binary list.
	def __stringToBinlist( self, data ):
		l = len( data ) * 8
		result = [0] * l
		position = 0
		for ch in data:
			i = 7
			while i >= 0:
				if ch & ( 1 << i ) != 0:
					result[position] = 1
				else:
					result[position] = 0

				position += 1
				i -= 1
		return result
	# Change a binary list into text.
	def __binListToString( self, data ):
		result = []
		position = 0
		c = 0
		while position < len( data ):
			c += data[position] << ( 7 - ( position % 8 ) )
			if ( position % 8 ) == 7:
				result.append( c )
				c = 0
			position += 1

		return bytes( result )
	# Permutate operation. Data can be permutated by the permutateTable.
	def __permutate( self, data, permutateTable ):
		return list( map( lambda x: data[x], permutateTable ) )
	# From the source key, choose the 16 subkeys.
	def __productSubKey( self, key ):
		key = self.__permutate( key, self.__PC1 )
		subKeyLeft = key[:28]
		subKeyRight = key[28:]
		i = 0
		while i < 16:
			j = 0
			while j < self.__left_rotations[i] :
				subKeyLeft.append( subKeyLeft[0] )
				del subKeyLeft[0]
				subKeyRight.append( subKeyRight[0] )
				del subKeyRight[0]
				j += 1
			self._subKey[i] = self.__permutate( subKeyLeft + subKeyRight, self.__PC2 )
			i += 1
	# Expand 32-bit data to 48-bit.
	def __expandData( self, data ):
		R = self.__permutate( data, self.__E )
		return R
	# f function
	def __f( self, data ):
		result = [0] * 32
		j = 0
		position = 0
		while j < 8:
			# for an 48-bit data, divided it into 8 groups, each group has 6 bits.
			# The input of sbox[j] is group[j]
			# group1:d0,...,d5
			# ...
			# group8:d42,...,d47
			# The row of sbox[j] is decided by group[j * 6] and group[j * 6 + 5]
			# The column of sbox[j] is decided by from group[j * 6 + 1] to group[j * 6 + 4]
			m = ( data[j * 6] << 1 ) + data[j * 6 + 5]
			n = ( data[j * 6 + 1] << 3 ) + ( data[j * 6 + 2] << 2 ) + ( data[j * 6 + 3] << 1 ) + data[j * 6 + 4]
			# Get the value of sbox[j]
			v = self.__sbox[j][( m << 4 ) + n]
			# The value must be change to binary list.
			result[position] = ( v & 8 ) >> 3
			result[position + 1] = ( v & 4 ) >> 2
			result[position + 2] = ( v & 2 ) >> 1
			result[position + 3] = ( v & 1 )
			position += 4
			j += 1
		result = self.__permutate( result, self.__P )
		return result
	# 16 round crypt.
	def __crypt( self, data ):
		data = self.__permutate( data, self.__IP )
		i = 0
		L = data[:32]
		R = data[32:]
		while i < 16:
			# What I have to achieve is that
			# L[i + 1] = R[i]
			# R[i + 1] = L[i] xor (f(R[i], subKey[i]))
			# Backup of L
			LBackup = L
			# L[i + 1] = R[i]
			L = R
			# expanded R to 48 bits
			R = self.__expandData( R )
			# R[i] xor subKey[i]
			R = list( map( lambda x, y: x ^ y, R, self._subKey[i] ) )
			# f(R), the result of f is 32 bits.
			R = self.__f( R )
			# R[i + 1] = R[i] xor L[i]
			R = list( map( lambda x, y: x ^ y, LBackup, R ) )
			i += 1
		data = self.__permutate( R + L, self.__FP )
		return data
	# If you give a Des class, You set the crypt model('en' or 'de'). You can use crypt method to encrypt or decrypt by crypt = 'en' or crypt = 'de'. Because the symmetry of DES algorthm, I can do this easily.
	def crypt( self ):
		result = []
		# If the lenth of data is not the times of 8
		# padding it.
		data = self._message
		# If encrypt a message, padding the message at first.
		if self._crypt == 'E':
			data += self.__getPadingData( self._message )
		# data is the binary list of source message.
		data = self.__stringToBinlist( data )
		# lenth of key must be 8 bits.
		if len( self._key ) != 8:
			print( 'Error: the lenth of key must be 8 bits.' )
			return
		key = self.__stringToBinlist( self._key )
		self.__productSubKey( key )
		# If decrypt a message, reverse the order of subKey.
		if self._crypt == 'D':
			self._subKey.reverse()
		i = 0
		while i < len( data ):
			encryptData = data[i: ( i + 64 )]
			s = self.__binListToString( self.__crypt( encryptData ) )
			result.append( s )
			i += 64
		result = b''.join( result )
		# If decrypt a message, delete the padding data at the end of result.
		if self._crypt == 'D':
			padLen = result[-1]
			result = result[:-padLen]
		return result
