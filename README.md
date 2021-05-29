License
-------

DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 

Version 2, December 2004 
                    
Copyright (C) 2004 Sam Hocevar <sam@hocevar.net> 

Everyone is permitted to copy and distribute verbatim or modified 

copies of this license document, and changing it is allowed as long 

as the name is changed. 

DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
           
TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 

1. You just DO WHAT THE FUCK YOU WANT TO.



NaiveOTP
--------
NaiveOTP is a simple OTP class to generate OTP for Python >=3.7 from :
* HOTP / HMAC-Based OTP Algorithm (RFC 4226)
* TOTP / Time-based One-time Password Algorithm (RFC 6238)

Functionalities :
* Support key/seed in different forms : base32 encoded with incorrect padding auto-patching, bytes, hex
* Can export key/seed as qrcode file or url base64
* Support a grace number of previous and futur OTP, if time if shifted/drifted

This library supports :
* SHA1-160 bits, aka sha1
* SHA2-256 bits, aka sha256
* SHA2-384 bits, aka sha384
* SHA2-512 bits, aka sha512

By default use : SHA1 + 6-number OTP lenght + 30s. OTP validity


Shift and Drift
----------------
 ! no more supported -> replaced by grace number
Shift time, is a shifted time on the client side. Drift time, is a shifted time on the server side. It's common to have time shifts between server and client on OTP, HardToken and SoftToken solution. This two options allow to correct the shifts on both sides. It's not really usefull if the library is used as a standalone one ;-).


Grace
----------------
Previous OTP are the n-1, n-2... OTP. Next OTP are the n+1, n+2... OTP. As "Shift and Drift", this feature is mostly used on full OTP solution with client and server. It allows, if needed, to support previous and/or next OTP.


Usage
----------------

test me
````
from naiveotp4 import naiveOtp
o=naiveOtp()
o.test()
````

generate 1 OTP
````
from naiveotp4 import naiveOtp
o = naiveOtp(hash_name='sha1', otp_len=6, otp_validity=30, seed='RLID574DSBFLYQT7QS6HHRQ5UMR3XRSPGMEAICJQSVOSMDSJLMOQ')
print(o.otp())
````

generate 1 OTP with multiple call for parameters
````
from naiveotp4 import naiveOtp
o = naiveOtp(hash_name='sha1')
o = naiveOtp(otp_len=6)
o = naiveOtp(otp_validity=30)
o.set_seed('RLID574DSBFLYQT7QS6HHRQ5UMR3XRSPGMEAICJQSVOSMDSJLMOQ')
print(o.gen_otp())
````

generate key/seed and export to qrcode image file
````
from naiveotp4 import naiveOtp
o = naiveOtp()
o.set_seed('RLID574DSBFLYQT7QS6HHRQ5UMR3XRSPGMEAICJQSVOSMDSJLMOQ')
o.qrcode_from_seed()
````

generate key/seed and export to qrcode base64 url encoded (recommanded for security)
````
from naiveotp4 import naiveOtp
o = naiveOtp()
sb = o.gen_seed()
o.set_seed(sb)
o.qrcode_from_seed(export_to_b64=True)
````



````
         ///\\\  ( Have Fun )
        / ^  ^ \ /
      __\  __  /__
     / _ `----' _ \
     \__\   _   |__\
      (..) _| _ (..)
       |____(___|     Mynameisv_ 2021
_ __ _ (____)____) _ _________________________________ _'
````