# #!/usr/bin/python # This is client.py file
# # !/usr/bin/python # This is client.py file
import socket  # Import socket module
from itertools import permutations
import os

#
# s = socket.socket()  # Create a socket object
# host = "192.168.2.83"  # Remote machine name
# port = 28073  # Remote port
# s.connect((host, port))
# print (s.recv(1024))
# s.close()  # Close the socket when done

# !/usr/bin/env python
from pwn import *

context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)
host, port = "192.168.2.83", 28075
conn = remote(host, port)
content = conn.recv(1024)
print (content)  # Welcome to Secure Encryption Service version 1.19

sample_cookie_prompt = "Here is a sample cookie: "
sample_cookie = conn.recvline_contains(sample_cookie_prompt, keepends=False, timeout=3)
sample_cookie = sample_cookie[len(sample_cookie_prompt):]
print("\nconn's sample cookie:")
print(sample_cookie)

cookie_IV = "5468697320697320616e204956343536"
cookie_c0 = "dffe62b4c63dbb7a9d597ef15dd270df"
cookie_c1 = "e4ee7d0c35d41276e6c8c1cfe49c1bfd"
cookie_c2 = "4db86175e5f72ffe02a9e3a766e9abd4"
cookie_c4 = "75d59d5045214af8339a71c8d9af82a4"
cookie_c3_origin = "a5e6f54ea599ceb9f7decf0b7445f1a5"

def sxor(s1, s2):
    str1 = ''
    hex_ints1 = int(s1, 16)
    hex_ints2 = int(s2, 16)
    return hex(hex_ints1 ^ hex_ints2)[2:]

# modify here
char_deal = 2
correct_guess = "01"
c0 = sxor(cookie_c3_origin[32-(char_deal-1)*2:], correct_guess)

#

hex_len = pow(16,2)

chararray = []
for i in range(hex_len):
    chararray.append((hex(i)[2:]).zfill(2))





print chararray

pad = (char_deal % 16) * (hex(char_deal % 16))[2:].zfill(2)
print pad

cookie_c3_last = c0

get = " "

for i in range(hex_len):
    guess = chararray[i] + correct_guess
    guess_xor_pad = sxor(guess, pad).zfill(char_deal*2)
    last_nchar = cookie_c3_origin[32-(char_deal*2):]
    cookie_c3 = cookie_c3_origin[:32-(char_deal*2)] + sxor(last_nchar, guess_xor_pad).zfill(char_deal*2)
    print  "\noriginal C_[n-1][m]: ", last_nchar, "  guess: ", guess, "  Xored: ", guess_xor_pad
    print "Xored Cookie C_[n-1][%d]: ", sxor(cookie_c3_origin[32-(char_deal*2):], guess_xor_pad).zfill(char_deal*2)
    cookie = cookie_IV + cookie_c0 + cookie_c1 + cookie_c2 + cookie_c3 + cookie_c4
    print "send new cookie ", cookie
    conn = remote(host, port)
    conn.recvline_contains("What is your cookie?", keepends=False, timeout=5)
    conn.sendline(cookie)
    response = conn.recvall()
    # print "\ni=", i + 1
    get = " "
    if "invalid" not in response:
        print '\n', response
        get = cookie_c3
    if get != " ":
        print get
    else:
        print "not this one"
    conn.close()

if get == " ":
    print "not this combination"

print "get xored cookie_3", get