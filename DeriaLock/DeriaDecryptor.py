
# DeriaLock Decryptor
# NioGuard Security Lab, 2017
# Author: Alexander Adamov
# Email: ada@nioguard.com

import os
import hashlib
from array import *
from Crypto.Cipher import AES

DECRYPT_LOCATIONS = [
                        "%s" % os.environ['USERPROFILE'],
                        "d:/"
                    ]

EXT = ".deria"
PASSWORD = "b3f6c3r6vctb9c3n789um83zn8c3tb7c3brc3b5c77327tbrv6b123rv6c3rb6c7tc3n7tb6tb6c3t6b35nt723472357t1423tb231br6c3v4"
#KEY = "9c9e1ba2ee5b86494b7e1ebba6420ee6ab64ce6d678604eb5b5049b210693743"
#IV = "9fa4ed4d89b04ee7f3b74c9b46588e18"

def calculate_key_iv(password):
    hash = hashlib.sha512(array("B", PASSWORD)) # convert string to byte array and calculate sha512
    #print "Key: %s" % hash.hexdigest()[0:64] # print first 32 bytes of the hash
    #print "IV: %s" % hash.hexdigest()[64:96] # print next 16 bytes of the hash
    return hash.digest()[0:32], hash.digest()[32:48]


def decrypt_file(in_file, out_file):
    block_size = AES.block_size # 16
    key, iv = calculate_key_iv(PASSWORD)
    aes_cipher = AES.new(key, AES.MODE_CBC, iv)
    next_block = ''
    endoffile = False
    while not endoffile:
        block, next_block = next_block, aes_cipher.decrypt(in_file.read(1024 * block_size))
        if len(next_block) == 0:
            padding_length = ord(block[-1])
            # wrong key or iv may lead to incorrect padding length  
            if padding_length < 1 or padding_length > block_size:
                raise ValueError("Wrong padding length (%d). The DeriaLock password does not fit the file or the file has been corrupted." % padding_length)
            # all padding bytes must be the same
            if block[-padding_length:] != (padding_length * chr(padding_length)):
                raise ValueError("Decryption failed!")
            block = block[:-padding_length]
            endoffile = True
        out_file.write(block)

    in_file.close()
    out_file.close()
    print "Success!"


if __name__ == '__main__':

    print "DeriaLock decryptor by NioGuard Security Lab, 2017"

    for current_dir in DECRYPT_LOCATIONS:
        print "Scanning %s\ ..." % current_dir
        for root, dirs, files in os.walk(current_dir):
            for file in files:
                if file.endswith(EXT):
                    fullpath = os.path.join(root, file)
                    with open(fullpath, "rb") as file_in, open(fullpath[:-len(EXT)], 'wb') as file_out:
                        print "Decrypting %s" % fullpath
                        decrypt_file(file_in, file_out)

    print "Decryption has been completed. Bye!"

