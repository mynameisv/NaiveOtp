#!/usr/bin/env -S python3 -OO
# coding: utf8
"""
	Class to generate OTP from :
	- HOTP / HMAC-Based OTP Algorithm (RFC 4226)
    - TOTP / Time-based One-time Password Algorithm (RFC 6238)
	By default use : SHA1 + 6-number OTP lenght + 30s. OTP validity

"""
#
##
###
###########################################################
# Python Imports
#############################
# Embedded imports
import base64
import binascii
import hashlib
import hmac
import io
import secrets
import time
from typing import Any, Dict, List, Tuple, Union
# External imports
try:
	import qrcode # qrcode
	from PIL import Image # Pillow
except:
	pass
#
##
###
###########################################################
# Python Exports
#############################
# Allowed class/function to be imported
__all__ = ['naiveotp']
#
##
###
###########################################################
# Class
#############################
class naiveotp():
	"""
	Class to generate OTP (HOTP+TOTP)
	"""
	def __init__(self, hash_name:str='sha1', otp_len:int=6, otp_validity:int=30, seed:str=''):
		"""
		Initiate the class to generate OTP (HOTP+TOTP)

		:param hash_name: name of the hmac algo. Defaults to ``sha1``
		:type hash_name: str
		:param otp_len: length of the OTP. Defaults to ``6``
		:type otp_len: int
		:param otp_validity: Validity duration of the OTP in seconds. Defaults to ``30``
		:type otp_validity: int
		:param seed: seed/secret, shared with the user to generate the OTP. Can be hexadecimal
			string prefixed or not with 0x, base 32 string with or without padding, both without
			separator or with space, dash or coma separator
		:type seed: str
		:raise: raise on value error
		"""

		# Dictionnary of allowed hashes.
		# Key are hash name and value are :
		# - 'hashlib' for hashlib builtin method
		# - 'seed_nbytes' for seed recomanded size in bytes
		self.__hashes_allowed = {
			'sha1': {'hashlib': hashlib.sha1, 'seed_nbytes': 40 },
			'sha224': {'hashlib': hashlib.sha224, 'seed_nbytes': 56 },
			'sha256': {'hashlib': hashlib.sha256, 'seed_nbytes': 64 },
			'sha384': {'hashlib': hashlib.sha384, 'seed_nbytes': 96 },
			'sha512': {'hashlib': hashlib.sha512, 'seed_nbytes': 128 },
		}

		# empty params
		self.__hash_name = ''
		self.__otp_len = 0
		self.__otp_validity = 0
		# seed as bytes
		self.__seed = ''

		# Set params
		self.set_hash(hash_name)
		self.set_otp_len(otp_len)
		self.set_otp_validity(otp_validity)
		self.set_seed(seed)
	#end __init__
	#
	#############################
	def set_hash(self, hash_name:str='sha1'):
		"""
		See __init__() for params
		"""
		if hash_name not in self.__hashes_allowed:
			raise ValueError(f'Hash name {hash_name} is not supported')
		
		self.__hash_name = hash_name
	#end set_hash
	#
	#############################
	def set_otp_len(self, otp_len:int=6):
		"""
		See __init__() for params
		"""
		if type(otp_len)!=int:
			raise ValueError(f'OTP length {otp_len} must be an integer')

		if otp_len<4 or otp_len>12:
			raise ValueError(f'OTP length {otp_len} is not supported')
		
		self.__otp_len = otp_len
	#end set_otp_len
	#
	#############################
	def set_otp_validity(self, otp_validity:int=30):
		"""
		See __init__() for params
		"""
		if type(otp_validity)!=int:
			raise ValueError(f'OTP validity {otp_validity} must be an integer')

		if otp_validity<10 or otp_validity>240:
			raise ValueError(f'OTP validity {otp_validity} is not supported')

		self.__otp_validity = otp_validity
	#end set_otp_validity
	#
	#############################
	def gen_seed(self, to_hex:bool=False, to_b32:bool=False) -> Union[str, bytes]:
		"""
		Generate a random seed with a length depending on the hmac algo
		By default, generate a 40-bytes long seed, for SHA1-160bits
		
		:param to_hex: return the seed in hex format
		:param to_hex: boolean
		:return: random seed with a default size of 40-bits as bytes, or hex str or b32 str
		"""
		if self.__hash_name not in self.__hashes_allowed:
			seed_nbytes = 40
		else:
			seed_nbytes = self.__hashes_allowed[self.__hash_name]['seed_nbytes']
		seed_as_bytes = secrets.token_bytes(nbytes=seed_nbytes)

		if to_hex==True:
			return binascii.hexlify(seed_as_bytes).decode()
		elif to_b32==True:
			return base64.b32encode(seed_as_bytes).decode()
		else:
			return seed_as_bytes
	#end set_otp_validity
	#
	#############################
	def set_seed(self, seed:Union[str,bytes]=None):
		"""
		See __init__() for params
		"""
		if type(seed)==bytes:
			# length must be even
			if len(seed)%2:
				raise ValueError(f'Seed lenght is odd and wrong')
			self.__seed = seed

		elif type(seed)==str:
			# To upper to simplify hex prefix detection or b32
			seed = seed.upper()

			# remove prefix '0x' if hexa
			if seed.startswith('0X'):
				seed = seed[2:]

			# clean base32 separators
			seed = seed.replace(' ','')
			seed = seed.replace('-','')
			seed = seed.replace(',','')

			# strip yeah !
			seed = seed.strip()

			# Try if seed is an hex encoded string
			try:
				self.__seed = binascii.unhexlify(seed)
			except:
				# Not hexa
				# Try base32 with auto-correct padding like for Amazon
				# https://github.com/keepassxreboot/keepassxc/pull/3622
				# Check with 5FT7WWLR3OWA26NWZ6DFCRLM3NGEWVUE7ZYWFMGCWBGJ7K3IEWDA
				decode_ok = False
				for i in range(0,7):
					try:
						# Try base32
						self.__seed = base64.b32decode(seed + i*'=')
					except:
						# Not working... try next padding
						continue
					else:
						decode_ok = True
						break
				if decode_ok==False:
					raise ValueError(f'Seed {seed[0:16]}... is not hex nor base32')
		else:
			# Seed empty ? Juste pass
			pass
	#end set_seed
	#
	#############################
	def get_seed_bytes(self):
		return self.__seed
	#end get_seed
	#
	#############################
	def get_seed_hex(self):
		return binascii.hexlify(self.__seed).decode()
	#end get_seed
	#
	#############################
	def get_seed_b32(self):
		return base64.b32encode(self.__seed).decode()
	#end get_seed
	#
	#############################
	def qrcode_from_seed(self, issuer:str='mynameisv_', user_login:str='none', qrc_filepath:str='qrcode.png', export_to_b64:bool=False):
		"""
		:param issuer: the issuer of the OTP solution, it's only info, but must be set
		:type issuer: str
		:param user_login: the issuer of the OTP solution, it's only info, but must be set
		:type user_login: str
		:param qrc_filepath: image filepath to store qrcode
		:type qrc_filepath: str
		:param export_to_b64: do export to base64 string instead of file ?
		:type export_to_b64: bool
		"""
		if self.__seed=='' or type(self.__seed)!=bytes:
			raise ValueError('Seed is not defined or not bytes')

		if 'qrcode' not in globals():
			raise ModuleNotFoundError('Module qrcode is missing, use: python3 -m pip install qrcode')
		if 'Image' not in globals():
			raise ModuleNotFoundError('Module PIL.Image is missing, use: python3 -m pip install Pillow')
		
		# Create the OTP Auth URL
		seed_as_b32 = base64.b32encode(self.__seed).decode()
		# Patch the b32 by removing padding (if not, the url wont work)
		seed_as_b32 = seed_as_b32.replace('=', '')
		oa_url = f'otpauth://totp/{issuer}%3A{user_login}?secret={seed_as_b32}&issuer=issuer'

		# https://note.nkmk.me/en/python-pillow-qrcode/
		qr = qrcode.QRCode(
			version=1, # 1 to 40
			error_correction=qrcode.constants.ERROR_CORRECT_Q, # L=7%, M=15%, Q=25%, H=30%
			box_size=4,
			border=2
		)
		qr.add_data(oa_url)
		qr.make()
		pilimg = qr.make_image(fill_color="#000000", back_color="#ffffff")

		if export_to_b64:
			img_bytes = io.BytesIO()
			pilimg.save(img_bytes, format='PNG')
			img_b64 = base64.b64encode(img_bytes.getvalue()).decode()
			#print(type(img_b64))
			#print(img_b64[:64])
			return f'data:image/png;base64,{img_b64}'
		else:
			pilimg.save(qrc_filepath, format='PNG')
			#print(f'Saved to {qrc_filepath}!')
			return qrc_filepath
	#end qrcode_from_seed
	#
	#############################
	def get_time_current(self, forced_time:int=0):
		"""
		Get the current time, so obvious !
		"""
		if forced_time!=0:
			return forced_time
		else:
			return round(time.time())
	#end get_time_current
	#
	#############################
	def truncate_otp(self, long_otp:bytes):
		"""
		Truncate the OTP
		"""
		#bytes_mapped = map(ord, long_otp)
		bytes_mapped = list(long_otp)
		offset = bytes_mapped[-1] & 0xf
		trunc_otp = (bytes_mapped[offset] & 0x7f) << 24 | (bytes_mapped[offset+1] & 0xff) << 16 | (bytes_mapped[offset+2] & 0xff) << 8 | (bytes_mapped[offset+3] & 0xff)
		otp_as_str = str(trunc_otp)
		start_offset = len(otp_as_str) - self.__otp_len
		return otp_as_str[start_offset:]
	# end truncate_otp
	#############################
	def otp(self, forced_time:int=0) -> str:
		return self.otps(forced_time=forced_time)[0]
	# end otp
	#############################
	def otps(self, forced_time:int=0, grace_number:int=0) -> list:
		"""
		:param forced_time: time to use to generate OTP insted of current time
		:type forced_time: int
		:param grace_number: due to time shifting on some devices, it may be usefull to get some
			OTPs before and after the current OTP. grace_number specify the number of OTPs to get
			that are before and after the current OTP. If grace_number=1, the following list will
			be return [otp-1, current otp, otp+1]
		:type grace_number: int
		:return: a list of one or more OTP, depending on grace_number
		"""

		# Get the current time to generate the current OTP and grace OTPs
		current_time = self.get_time_current(forced_time)

		# Build the OTP time list with possible grace time
		time_range_floors = []
		# Protect grace_number
		time_range_floors = []
		grace_number = abs(grace_number)
		# If grace_number==0, the loop will run once and build a list of one
		# element, from the current_time
		for i in range(-grace_number, grace_number+1):
			local_grace_time = current_time + i*self.__otp_validity
			# Calcutate the time range floor with a patch for non-sha1
			local_time_range_floor = local_grace_time//self.__otp_validity
			# - to confirm - if self.__hash_name != 'sha1':
			# - to confirm - 	local_time_range_floor = (local_grace_time//self.__otp_validity)*self.__otp_validity
			# add to our list
			time_range_floors.append(local_time_range_floor)
		
		otps = []
		for time_range_floor in time_range_floors:
			# Convert time_range_floor as int to bytes, but with a fixed length of 16-bytes
			# To get the exact length, it would be : (time_range_floor.bit_length() + 7) // 8
			bytes_len = 8
			#bytes_len = (time_range_floor.bit_length() + 7) // 8
			time_range_floor_by= time_range_floor.to_bytes(length=bytes_len, byteorder='big')

			# HMAC the seed+time
			long_hmac = hmac.new(
				key=self.__seed,
				msg=time_range_floor_by,
				digestmod=self.__hashes_allowed[self.__hash_name]['hashlib']
			).digest()
			# Truncate, cf. RFC
			trunc_hmac = self.truncate_otp(long_hmac)

			otps.append(trunc_hmac)

		return otps
	#end otps
	#
	#############################	
	def test(self):
		"""
		Test the class
		"""
		print(f'\n [*] Params in class creation')
		self.__init__(hash_name='sha1', otp_len=6, otp_validity=30, seed='BJEHF4TIPXQCTQ4S')
		print('   > OK')

		print(f'\n [*] Params random seed generation, as bytes')
		s = self.gen_seed()
		if type(s)==bytes and len(s)>0:
			m = '   > OK, '
		else:
			m = '   > Error, '
		m+= f'type:{type(s)}, seed:{s}'
		print(m)

		print(f'\n [*] Params random seed generation, as hex')
		s = self.gen_seed(to_hex=True)
		if type(s)==str and len(s)>0:
			m = '   > OK, '
		else:
			m = '   > Error, '
		m+= f'type:{type(s)}, seed:{s}'
		print(m)

		print(f'\n [*] Params random seed generation, as b32')
		s = self.gen_seed(to_b32=True)
		if type(s)==str and len(s)>0:
			m = '   > OK, '
		else:
			m = '   > Error, '
		m+= f'type:{type(s)}, seed:{s}'
		print(m)

		print(f'\n [*] Wrong seeds')
		try:
			s = 12345
			self.set_seed(s)
			print(f'   > Error, int does not raise, with seed:{s}, type:{type(s)}')
		except:
			pass
		try:
			s = 'BJEHF+4TIPXQCTQ+4S'
			self.set_seed(s)
			print(f'   > Error, non-b32 does not raise, with seed:{s}, type:{type(s)}')
		except:
			pass
		try:
			s = b'12345'
			self.set_seed(s)
			print(f'   > Error, odd does not raise, with seed:{s}, type:{type(s)}')
		except:
			pass
		print('   > OK')

		print(f'\n [*] Non-padded (fucking wrong) base32-seed, like the one from Amazon')
		self.set_seed('RLID574DSBFLYQT7QS6HHRQ5UMR3XRSPGMEAICJQSVOSMDSJLMOQ')
		print('   > OK')

		print(f'\n [*] Params after class creation')
		self.set_hash('sha1')
		self.set_otp_len(6)
		self.set_otp_validity(30)
		self.set_seed('BJEHF4TIPXQCTQ4S')
		print('   > OK')

		print(f'\n [*] OTP Generation')
		otps = self.otps(forced_time=123456789, grace_number=2)
		otps_awaited = ['424997', '339321', '937130', '545331', '209339']
		is_err = False
		for otp in enumerate(otps):
			if otp[1]!=otps_awaited[otp[0]]:
				print('   > Error, generated otp:{otp[1]} != awaited otp:{otps_awaited[otp[0]]}')
				is_err = True
		if is_err==False:
			print('   > OK')
	#end test
	#
	#############################	
#end naiveOtp
#
#############################


