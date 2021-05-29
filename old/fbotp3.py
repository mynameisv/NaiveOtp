#!/usr/bin/python
#DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
#                    Version 2, December 2004 
#Copyright (C) 2004 Sam Hocevar <sam@hocevar.net> 
#Everyone is permitted to copy and distribute verbatim or modified 
#copies of this license document, and changing it is allowed as long 
#as the name is changed. 
#           DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
# TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 
#
#1. You just DO WHAT THE FUCK YOU WANT TO.
#
#         ///\\\  ( Have Fun )
#        / ^  ^ \ /
#      __\  __  /__
#     / _ `----' _ \
#     \__\   _   |__\
#      (..) _| _ (..)
#       |____(___|     Mynameisv
#_ __ _ (____)____) _ _________________________________ _'
#
##
###
###########################################################
# Python Imports
#############################
from naiveotp3 import ObjNaiveOtp
import base64
import sys
import time
#
##
###
###########################################################
# Functions
#############################
def printHelp():
	print('')
	print('Facebook OTP Generator v0.1')
	print('')
	print('Dirty command line with the secret in clear as a parameter O_o')
	print('  # python fbotp.py <base32 encoded secret key>')
	print('')
	print('Example:')
	print('  # python fbotp.py ABCDEFGHIJKLMNOP')
	print('')
	sys.exit()
#end - printHelp
#
##
###
###########################################################
# Main
#############################
def main():
	if len(sys.argv)!=2:
		printHelp()
	else:
		sKeyBase32 = sys.argv[1].strip()
		
		#Check that the key is Base32 encoded
		try:
			sKeyBin = base64.b32decode(sKeyBase32)
		except:
			print(" [!] Argument is not Base32")
			printHelp()
		# Generate the OTP
		oOtp = ObjNaiveOtp()
		sKeyHex = oOtp.convertFacebookKeyToHex(sKeyBase32)
		oOtp.setKey(sKeyHex)
		oOtp.setAlgo('sha1')
		oOtp.setOtpLen(6)
		oOtp.setOtpValidity(30)
		oOtp.doTimeCurrent()
		oOtp.doTimeRangeFloor()
		print(str(oOtp.genOtp()))
		print('Sleep 10')
		time.sleep(10)
#end - main

if __name__ == '__main__':
	main()
else:
	main()