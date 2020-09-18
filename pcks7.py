#!/usr/bin/python2
import os
import json
import sys
import time

from Crypto.Cipher import AES
context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)
host, port = "192.168.2.83", 28075
conn = remote(host, port)
content = conn.recv(1024)

cookiefile = open("cookie.txt", "r").read().strip()
flag = open("flag.txt", "r").read().strip()
key = open("key.txt", "r").read().strip()

welcome = """
Welcome to Secure Encryption Service version 1.19
"""
print welcome

def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def isvalidpad(s):
    return ord(s[-1]) * s[-1:] == s[-ord(s[-1]):]


def unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def encrypt(m):
    IV = "This is an IV456"
    cipher = AES.new(key.decode('hex'), AES.MODE_CBC, IV)
    return IV.encode("hex") + cipher.encrypt(pad(m)).encode("hex")


def decrypt(m):
    cipher = AES.new(key.decode('hex'), AES.MODE_CBC, m[0:32].decode("hex"))
    return cipher.decrypt(m[32:].decode("hex"))


plain_p0 = "7622757365726e616d65223a20226775"
plain_p1 = "657374222c202265787069716573223a"
plain_p2 = "2022323032302d31312d3037222c2022"
plain_p3 = "69735f61646d696e223a202022747275"
plain_p4 = "65227d0d0d0d0d0d0d0d0d0d0d0d0d0d"

IV_origin = "5468697320697320616e204956343536"
cookie_c0_origin = "dffe62b4c63dbb7a9d597ef15dd270df"
cookie_c1_origin = "e4ee7d0c35d41276e6c8c1cfe49c1bfd"
cookie_c2_origin = "4db86175e5f72ffe02a9e3a766e9abd4"
cookie_c4_origin = "75d59d5045214af8339a71c8d9af82a4"
cookie_c3_origin = "a5e6f54ea599ceb9f7decf0b7445f1a5"

def sxor(s1, s2):
    str1 = ''
    hex_ints1 = int(s1, 16)
    hex_ints2 = int(s2, 16)
    return hex(hex_ints1 ^ hex_ints2)[2:]

P2_need = "00000000020000010000000000000000"
P3_need = "00000000000000000000000244151e06"

cookie_c0 = encrypt(sxor(plain_p0, IV_origin))
cookie_c1 = encrypt(sxor(plain_p1, cookie_c0))
cookie_c2 = encrypt( sxor( sxor(plain_p2, P2_need) , cookie_c1) )
cookie_c3 = encrypt( sxor( sxor(plain_p3, P3_need) , cookie_c2) )
cookie_c4 = encrypt(sxor(plain_p4, cookie_c3))

cookienew = IV_origin + cookie_c0 + cookie_c1 + cookie_c2 + cookie_c3 + cookie_c4

plain1 ='{"username": "guest", "expires": "2000-01-07", "is_admin": "false"}'
print len(plain1)
print plain1 + (16 - len(plain1) % 16) * chr(16 - len(plain1) % 16)

# flush output immediately
# sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
print welcome
print "Here is a sample cookie: " + encrypt(cookiefile)

newtext = '{"username": "guest", "expires": "2010-11-07",  "is_admin": "true"}'
newcookie = encrypt(newtext)

# Get their cookie
print "What is your cookie?"
cookie2 = newcookie
# decrypt, but remove the trailing newline first
cookie2decoded = decrypt(cookie2[:-1])

if isvalidpad(cookie2decoded):
    d = json.loads(unpad(cookie2decoded))
    print "username: " + d["username"]
    print "Admin? " + d["is_admin"]
    exptime = time.strptime(d["expires"], "%Y-%m-%d")
    if exptime > time.localtime():
        print "Cookie is not expired"
    else:
        print "Cookie is expired"
    if d["is_admin"] == "true" and exptime > time.localtime():
        print "The flag is: " + flag
else:
    print "invalid padding"

# Get their cookie
# print "What is your cookie?"
# cookie2 = sys.stdin.readline()
# decrypt, but remove the trailing newline first
# cookie2decoded = decrypt(cookie2[:-1])

if isvalidpad(cookie2decoded):
    d = json.loads(unpad(cookie2decoded))
    print "username: " + d["username"]
    print "Admin? " + d["is_admin"]
    exptime = time.strptime(d["expires"], "%Y-%m-%d")
    if exptime > time.localtime():
        print "Cookie is not expired"
    else:
        print "Cookie is expired"
    if d["is_admin"] == "true" and exptime > time.localtime():
        print "The flag is: " + flag
else:
    print "invalid padding"
