'''
Common functions
Created on 10/set/2013
Licensed under GPL License, Version 3.0 (http://www.gnu.org/licenses/gpl.html)

@version: 0.1
@author: 0x7c0
'''

def u_FileExists( root ):
	'''
	check exist file
	@param string root	root of file
	'''

	from os.path import exists, isfile
	return exists( root ) and isfile( root )
def u_FilePurge( who ):
	'''
	purge file link
	@param string who	root of file
	'''

	from os import unlink
	from os.path import exists
	if ( exists( who ) ):
		unlink( who )
	return
def u_UtCrypto( psw ):
	'''
	encode string with hash
	@param string psw	password
	'''

	import hashlib    # oggetto per creare sha512
	Hash = hashlib.sha512( str.encode( psw ) )
	# hexdigest restituisce la stringa hash
	# str.encode converte in byte per passare base64
	Hash.update( Hash.digest() )
	s1 = Hash.hexdigest()
	# 2 step, for decrease size to 64
	Hash = hashlib.sha256( str.encode( s1 ) )
	Hash.update( Hash.digest() )
	return Hash.hexdigest()
def u_DirAbs( root ):
	'''
	check root and return abs path
	@param string root	root of file
	'''

	from os.path import isabs, join
	from os import getcwd
	if( isabs( root ) ):
		return join( root )
	else:
		return join( getcwd(), root )
def u_UserCheck( regex, question ):
	'''
	read stdin and return if match regex
	@param string regex		regex for match
	@param string question	print output string
	'''

	from re import match
	while True:
		from getpass import getpass
		temp = getpass( question )
		if( match( regex, temp ) ):
			return u_UtCrypto( temp )
		else:
			print( 'Provide a correct alfanum password.' )
def u_UserInput( question ):
	'''
	question about action
	@param string question	print output string
	'''

	while True:
		action = input( question )
		if( action.upper() == 'Y' ):
			return True
		elif( action.upper() == 'N' ):
			return False
def u_UtCrono( start, Print = True ):    # Crono old
	'''
	return completion time
	if not 'print' return time without formatting
	@param int start	initial time
	@param bool Print	boolean for formatting
	'''

	from time import time, gmtime, strftime
	# prende in tempo da Unix Time
	if( Print ):
		end = time() - start
		if ( end < 60 ):    # sec
			return strftime( '%S sec', gmtime( end ) )
		elif ( end < 3600 ):    # min
			return strftime( '%M:%S min', gmtime( end ) )
		else:    # hr
			return strftime( '%H:%M:%S hr', gmtime( end ) )
	else:
		return int( strftime( '%S', gmtime( start ) ) )
