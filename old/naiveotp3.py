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
###########################################################
# NaiveOTP
#############################
# This lib is an extract of a closed-private dev i've made
# for a internal OTP solution.
# The purpose is simple : an easy to use library :-D
#
# Algorithms
##############
# This library supports :
#  * SHA1-160 bits, aka sha1
#  * SHA2-256 bits, aka sha256
#  * SHA2-384 bits, aka sha384
#  * SHA2-512 bits, aka sha512
#
# Shift and Drift
##############
# Shift time, is a shifted time on the client side.
# Drift time, is a shifted time on the server side.
# It's common to have time shifts between server and client on OTP,
# HardToken and SoftToken solution. This two options allow to
# correct the shifts on both sides. It's not really usefull if
# the library is used as a standalone one ;-).
#
# Previous and Next
##############
# Previous OTP are the n-1, n-2... OTP
# Next OTP are the n+1, n+2... OTP
# As "Shift and Drift", this feature is mostly used on full OTP
# solution with client and server. It allows, if needed, to support
# previous and/or next OTP.
#  
# Time Scheme
##############
# This is a draw of time line
#
#      current time: iTimeCurrent
#            A 
#            |      /-> end of time range
#            |     /
# .....X.....x.....X...... -=> time line
#      |\________/
#      |    \-> range of OTP's validity: iOtpValidity
#      |
#      \-> start of the time range: iTimeRangeFloor
#
#
#
# [ History ]
# * 2016-10
#  o fork for public publication
#
# * 2013...2016
#  + private changes
#
# * 2013-02-14
#  o creation
#
#
# [ Help ]
# Does it works:
#from naiveotp import ObjNaiveOtp
#oOtp = ObjNaiveOtp()
#oOtp.doesItWorks()
#
# Simple usage with a Facebook key:
#from naiveotp import ObjNaiveOtp
#sKeyB32 = 'ABCD EFGH IJKL MNOP'
#oOtp = ObjNaiveOtp()
#sKeyHex = oOtp.convertFacebookKeyToHex(sKeyB32)
#oOtp.setKey(sKeyHex)
#oOtp.setAlgo('sha1')
#oOtp.setOtpLen(6)
#oOtp.setOtpValidity(30)
#oOtp.doTimeCurrent()
#oOtp.doTimeRangeFloor()
#print str(oOtp.genOtp())
#
# Usage to get multiple OTP, 2 previous and 4 nexts:
#from naiveotp import ObjNaiveOtp
#sKeyB32 = 'ABCD EFGH IJKL MNOP'
#oOtp = ObjNaiveOtp()
#sKeyHex = oOtp.convertFacebookKeyToHex(sKeyB32)
#oOtp.setKey(sKeyHex)
#oOtp.setAlgo('sha1')
#oOtp.setOtpLen(6)
#oOtp.setOtpValidity(30)
#oOtp.doTimeCurrent()
#oOtp.doTimeRangeFloor()
#for dOtp in oOtp.genOtpPrevNext(2,4):
#	print dOtp['otp']
#
# Usage with a Drift:
#from naiveotp import ObjNaiveOtp
#sKeyB32 = 'ABCD EFGH IJKL MNOP'
#oOtp = ObjNaiveOtp()
#sKeyHex = oOtp.convertFacebookKeyToHex(sKeyB32)
#oOtp.setKey(sKeyHex)
#oOtp.setAlgo('sha1')
#oOtp.setOtpLen(6)
#oOtp.setOtpValidity(30)
#oOtp.setDrift(123) #Yes, it's a big shift ;-)
#oOtp.doDrift()
#oOtp.doTimeCurrent()
#oOtp.doTimeRangeFloor()
#print str(oOtp.genOtp())
#
#############################
#
##
###
###########################################################
# Python Imports
#############################
import base64
import binascii
import codecs
import hashlib
import hmac
import math
import time
#
##
###
###########################################################
# Object
#############################
class ObjNaiveOtp:
	#############################
	# Local Variables
	#############################
	# Key (or seed) in hex form as a String
	sKey = ''
	# Algo for hmac, as a String
	sAlgo = None
	# Otp length in bytes, as an integer
	iOtpLen = 6
	# Otp validity in seconds, as an integer
	iOtpValidity = 0
	# Current time (timestamp) in seconds, as an integer
	iTimeCurrent = 0
	# Time Drift in seconds, as an integer
	iDrift = 0
	# Time drifted (timestamp) from calculation (iTimeCurrent - iDrift) in seconds, as in integer
	iTimeDrifted = 0
	# Time range floor (timestamp) in seconds, as an integer
	iTimeRangeFloor = 0
	
	#############################
	# [ What ]
	# Set Key or seed for OTP calculation
	# [ Returns ]
	# True if key is ok
	# False if error
	#############################
	def setKey(self,
		sKey # private key or seek in hex form, as a String
	):
		# Check for old python version ;-) (instead of 'def funcname(s:str):'
		if type(sKey) is str:
			self.sKey = sKey.strip()
			return True
		elif type(sKey) == bytes:
			self.sKey = ''.join(map(chr,sKey))
		else:
			return False
	# end - setKey
	#############################
	# [ What ]
	# Convert a Facebook's Base32 key (seed) to Base64
	# [ Returns ]
	# Base64 encode key, as a String
	# False if error
	#############################
	def convertFacebookKeyToHex(self,
		sKeyBase32, # Facebook key in base32, as a String
	):
		# Check for old python version ;-) (instead of 'def funcname(s:str):'
		if type(sKeyBase32) is str:
			sKeyBase32 = sKeyBase32.replace(' ','').strip()
			sKeyBin = base64.b32decode(sKeyBase32)
			sKeyHex = binascii.hexlify(sKeyBin)
			#sKeyBase64 = base64.b64encode(sKeyBin)
			return sKeyHex
		else:
			return False
	# end - convertFacebookKeyToHex
	#############################
	# [ What ]
	# Set algorithm for OTP calculation
	# [ Returns ]
	# True if key is ok
	# False if error
	#############################
	def setAlgo(self,
		sAlgo # algorithm, as a String
	):
		# Check for old python version ;-) (instead of 'def funcname(s:str):'
		if type(sAlgo) is str:
			sAlgo = sAlgo.strip().lower()
			if sAlgo=='sha1' or sAlgo=='sha256' or sAlgo=='sha384' or sAlgo=='sha512':
				self.sAlgo = sAlgo
				return True
		# Dirty return is back \o/ (less lines than two else)
		return False
	# end - setAlgo
	#############################
	# [ What ]
	# Set OTP length for OTP calculation
	# [ Returns ]
	# True if key is ok
	# False if error
	#############################
	def setOtpLen(self,
		iOtpLen # otp length, as an Integer
	):
		# Check for old python version ;-) (instead of 'def funcname(s:str):'
		if type(iOtpLen) is int:
			self.iOtpLen = iOtpLen
			return True
		else:
			return False
	# end - setOtpLen
	#############################
	# [ What ]
	# Set period of validity in seconds for OTP calculation
	# [ Returns ]
	# True if key is ok
	# False if error
	#############################
	def setOtpValidity(self,
		iOtpValidity # otp period of validity in seconds, as an Integer
	):
		# Check for old python version ;-) (instead of 'def funcname(s:str):'
		if type(iOtpValidity) is int:
			self.iOtpValidity = iOtpValidity
			return True
		else:
			return False
	# end - setOtpValidity
	#############################
	# [ What ]
	# Set the current time (timestamp) in seconds
	# [ Returns ]
	# True if key is ok
	# False if error
	#############################
	def setTimeCurrent(self,
		iTimeCurrent # current time (timestamp) in seconds, as an Integer
	):
		# Check for old python version ;-) (instead of 'def funcname(s:str):'
		if type(iTimeCurrent) is int:
			self.iTimeCurrent = iTimeCurrent
			return True
		else:
			return False
	# end - setTimeCurrent
	#############################
	# [ What ]
	# Get/set the current time (timestamp) from local computer clock, in seconds
	# Erase the Drifted time with current time value
	# [ Returns ]
	# True if key is ok
	# False if error
	#############################
	# get the current time
	def doTimeCurrent(self):
		self.iTimeCurrent = int(time.time())
		self.iTimeDrifted = self.iTimeCurrent
	# end - doTimeCurrent
	#############################
	# [ What ]
	# Set a shift (drift) on server side, in seconds 
	# [ Returns ]
	# True if key is ok
	# False if error
	#############################
	def setDrift(self,
		iDrift # current time (timestamp) in seconds, as an Integer
	):
		# Check for old python version ;-) (instead of 'def funcname(s:str):'
		if type(iDrift) is int:
			self.iDrift = iDrift
			return True
		else:
			return False
	# end - setDrift
	#############################
	# [ What ]
	# Do (calculate) the shift (drift) on server side
	# [ Returns ]
	# True if key is ok
	# False if error
	#############################
	def doDrift(self):
		self.iTimeDrifted = self.iTimeCurrent - self.iDrift
		return True
	# end - doDrift
	#############################
	# [ What ]
	# Calculate the Time Range Floor
	# [ Returns ]
	# True if key is ok
	# False if error
	#############################
	def doTimeRangeFloor(self):
		if self.sAlgo == 'sha1':
			self.iTimeRangeFloor = int(self.iTimeDrifted/self.iOtpValidity)
		else:
			self.iTimeRangeFloor = int(self.iTimeDrifted/self.iOtpValidity)*self.iOtpValidity
	# end - doTimeRangeFloor
	#############################
	# [ What ]
	# Test is this lib is really working :-)
	#############################
	def doesItWorks(self):
		self.setKey('01234567890ABCDEF0123456789ABCDE')
		self.setAlgo('sha1')
		self.setOtpLen(6)
		self.setOtpValidity(30)
		self.setTimeCurrent(1234567890)
		self.doTimeRangeFloor()
		if self.genOtp() == '810312':
			print(' [*] Greatings, it works \o/')
		else:
			print(' [!] There is a problem with the OTP calculation, sorry...')
	# end - doesItWorks
	#############################
	# [ What ]
	# Convert an integer to hex value as a String
	# For example : 1360923000000 => "13CDD54FCC0"
	# [ Returns ]
	# Hex value, as a String
	#############################
	def i2h(self,i):
		sRet=''
		while i>0:
			sHex = '%X' % (i%16)
			sRet = sHex+sRet
			i=math.floor(i/16)
		return sRet
	# end - i2h
	#############################
	# [ What ]
	# Truncate an OTP with a len given in parameters
	# [ Returns ]
	# Truncated value of an OTP, as a String
	#############################
	def truncValue(self,
		sOtp,	# OTP value, as a String of bytes
		iLen # length of the result, as an Integer
	):
		lBytes = map(ord, sOtp)
		lBytes = list(sOtp)
		iOffset = lBytes[-1] & 0xf
		iRes = (lBytes[iOffset] & 0x7f) << 24 | (lBytes[iOffset+1] & 0xff) << 16 | (lBytes[iOffset+2] & 0xff) << 8 | (lBytes[iOffset+3] & 0xff)
		sRes = str(iRes)
		return sRes[len(sRes)-iLen:]
	# end - truncValue
	#############################
	# [ What ]
	# Shortens a Key (seed) in hex form, depending the used algorithm
	# [ Returns ]
	# Hex value, as a String
	#############################
	def shortSeed(self,
		sKey, # Key (seed) in hex as a String
		sAlgo # Algorithm, as a String
	):
		if sAlgo=='sha1':
			# 160 bits
			return sKey[:40]
		elif sAlgo=='sha256':
			# 256 bits
			return sKey[:64]
		elif sAlgo=='sha384':
			# 96 bits
			return sKey[:96]
		elif sAlgo=='sha512':
			# 512 bits
			return sKey[:128]
		else:
			return sKey
	# end - shortSeed
	#############################
	# [ What ]
	# Calculate the OTP
	# [ Returns ]
	# An OTP as a String
	#############################
	# - bOldFashion : False -> use time value as integer (as described in RFC)
	#                 True  -> multiply time value by 1000, resulting of a long value
	#                          for compatibility with first release with student's bug/error
	def genOtp(self):
		# Get Seed and short it, depending on the algo
		sKeyLocal = self.shortSeed(self.sKey,self.sAlgo)
		# Seed (hex string) to binary data
		binSeed = binascii.unhexlify(sKeyLocal)
		
		# Initialise iRange with iTimeRangeFloor
		iRange = self.iTimeRangeFloor
		
		# range floor (int) to hex string
		sHexRange = self.i2h(iRange)
		
		# Must be a 16bytes long hex string = 64bits int value = 8 bytes : 0x00 (len=2) => 1 byte, 0x0000 (len=4) => 2 bytes...
		while len(sHexRange)<16:
			sHexRange = '0'+sHexRange
		
		# range floor (hex string) to binary data
		binRange = binascii.unhexlify(sHexRange)
		

		# do the HMAC / OTP calculation
		# if/else because: Never use unchecked external string ;-)
		if self.sAlgo == 'sha1':
			sHash = hmac.new(binSeed, binRange, hashlib.sha1).digest()
		elif self.sAlgo == 'sha256':
			sHash = hmac.new(binSeed, binRange, hashlib.sha256).digest()
		elif self.sAlgo == 'sha512':
			sHash = hmac.new(binSeed, binRange, hashlib.sha512).digest()
		else:
			# Default
			sHash = hmac.new(binSeed, binRange, hashlib.sha256).digest()
		
		sOtp = self.truncValue(sHash,self.iOtpLen)
		return sOtp
	# end - genOtp
	#############################
	# [ What ]
	# Calculate the OTPs, a list of OTP from n-previous to n-next
	# [ Returns ]
	# An OTP as a String
	#############################
	def genOtpPrevNext(self,
		iPrev, # Previous OTP are the n-1, n-2... as an Integer
		iNext # Next OTP are the n+1, n+2... as an Integer
	):
		lTimes = []

		# Previous ?
		for i in range(iPrev,0,-1):
			lTimes.append(self.iTimeDrifted - i*self.iOtpValidity)

		# Current
		lTimes.append(self.iTimeDrifted)

		# Next ?
		for i in range(0,iNext):
			lTimes.append(self.iTimeDrifted + (i+1)*self.iOtpValidity)
		
		# Calculate OTPs and build the list
		lOtps = []
		for iTimePN in lTimes:
			self.iTimeDrifted = iTimePN
			self.doTimeRangeFloor()
			lOtps.append( {'otp':self.genOtp(),
										'rangefloor':int(self.iTimeDrifted/self.iOtpValidity)*self.iOtpValidity,
										'value':self.iTimeRangeFloor,
										'timestamp':iTimePN} )
		return lOtps
	# end - genOtpPrevNext
# end - ObjNaiveOtp