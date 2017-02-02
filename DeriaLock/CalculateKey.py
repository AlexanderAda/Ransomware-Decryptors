
from array import *
import hashlib

if __name__ == '__main__':
	# from DeriaLock sample with MD5: 0a7b70efba0aa93d4bc0857b87ac2fcb
	password_string = "b3f6c3r6vctb9c3n789um83zn8c3tb7c3brc3b5c77327tbrv6b123rv6c3rb6c7tc3n7tb6tb6c3t6b35nt723472357t1423tb231br6c3v4"
	hash = hashlib.sha512(array("B", password_string)) # convert string to byte array and calculate sha512
	print "Key: %s" % hash.hexdigest()[0:64] # print first 32 bytes of the hash
	print "IV: %s" % hash.hexdigest()[64:96] # print next 16 bytes of the hash

	# Use OpenSSL to decrypt your files. For example:
	# openssl aes-256-cbc -d -in nio.png.deria -K 9c9e1ba2ee5b86494b7e1ebba6420ee6ab64ce6d678604eb5b5049b210693743 -iv 9fa4ed4d89b04ee7f3b74c9b46588e18 -out nio.png
