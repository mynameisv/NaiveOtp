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
This lib is an extract of a closed-private dev i've made for a internal OTP solution. The purpose here is simple: an easy to use library :-D


Algorithms
----------------
This library supports :
* SHA1-160 bits, aka sha1
* SHA2-256 bits, aka sha256
* SHA2-384 bits, aka sha384
* SHA2-512 bits, aka sha512


Shift and Drift
----------------
Shift time, is a shifted time on the client side. Drift time, is a shifted time on the server side. It's common to have time shifts between server and client on OTP, HardToken and SoftToken solution. This two options allow to correct the shifts on both sides. It's not really usefull if the library is used as a standalone one ;-).


Previous and Next
----------------
Previous OTP are the n-1, n-2... OTP. Next OTP are the n+1, n+2... OTP. As "Shift and Drift", this feature is mostly used on full OTP solution with client and server. It allows, if needed, to support previous and/or next OTP.


Usage
----------------
Does it works:
````
from naiveotp import ObjNaiveOtp
oOtp = ObjNaiveOtp()
oOtp.doesItWorks()
````

Simple usage with a Facebook key:
````
from naiveotp import ObjNaiveOtp
sKeyB32 = 'ABCD EFGH IJKL MNOP'
oOtp = ObjNaiveOtp()
sKeyHex = oOtp.convertFacebookKeyToHex(sKeyB32)
oOtp.setKey(sKeyHex)
oOtp.setAlgo('sha1')
oOtp.setOtpLen(6)
oOtp.setOtpValidity(30)
oOtp.doTimeCurrent()
oOtp.doTimeRangeFloor()
print str(oOtp.genOtp())
````

Usage to get multiple OTP, 2 previous and 4 nexts:
````
from naiveotp import ObjNaiveOtp
sKeyB32 = 'ABCD EFGH IJKL MNOP'
oOtp = ObjNaiveOtp()
sKeyHex = oOtp.convertFacebookKeyToHex(sKeyB32)
oOtp.setKey(sKeyHex)
oOtp.setAlgo('sha1')
oOtp.setOtpLen(6)
oOtp.setOtpValidity(30)
oOtp.doTimeCurrent()
oOtp.doTimeRangeFloor()
for dOtp in oOtp.genOtpPrevNext(2,4):
	print dOtp['otp']
````

Usage with a Drift:
````
from naiveotp import ObjNaiveOtp
sKeyB32 = 'ABCD EFGH IJKL MNOP'
oOtp = ObjNaiveOtp()
sKeyHex = oOtp.convertFacebookKeyToHex(sKeyB32)
oOtp.setKey(sKeyHex)
oOtp.setAlgo('sha1')
oOtp.setOtpLen(6)
oOtp.setOtpValidity(30)
oOtp.setDrift(123) #Yes, it's a big shift ;-)
oOtp.doDrift()
oOtp.doTimeCurrent()
oOtp.doTimeRangeFloor()
print str(oOtp.genOtp())
````


fbotp.py ?
----------------
A command line tool for Facebook OTP generation, based on lib NaiveOTP
Usage with a Drift:
````
python fbotp.py <base32 encoded secret key>
````


A word about Python ?
----------------
I like and hate Python. It very powerfull, easy to use but :
* That fracking indentation... Copy/paste a code from an email or a web page and it explode. C-style braces, I miss you :'(
* Space vs Tab, it's endless even after that https://medium.com/@hoffa/400-000-github-repositories-1-billion-files-14-terabytes-of-code-spaces-or-tabs-7cfe0b5dd7fd#.8ahftovun 
* Multithreading is not real multithreading on multi-core
* Variable scope in classes with multithreading is a mess (threadsafe)


Last word ?
----------------

````
         ///\\\  ( Have Fun )
        / ^  ^ \ /
      __\  __  /__
     / _ `----' _ \
     \__\   _   |__\
      (..) _| _ (..)
       |____(___|     Mynameisv_ 2016
_ __ _ (____)____) _ _________________________________ _'
````