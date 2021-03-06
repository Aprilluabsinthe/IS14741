# #!/usr/bin/python # This is client.py file
# # !/usr/bin/python # This is client.py file
import socket  # Import socket module
from itertools import permutations
import os

# modify here
char_deal = 16
pn_value = "735f61646d696e223a202266616c73"
filename = "try_last2_16.txt"

# print "new need xored value",need_value
need_value = pn_value.zfill((char_deal-1) * 2)
pad = (char_deal)*(hex(char_deal))[2:].zfill(2)
print pad
#

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
with open(filename,'a+') as f:
    f.write(content) # Welcome to Secure Encryption Service version 1.19

sample_cookie_prompt = "Here is a sample cookie: "
sample_cookie = conn.recvline_contains(sample_cookie_prompt, keepends=False, timeout=3)
sample_cookie = sample_cookie[len(sample_cookie_prompt):]
print("\nconn's sample cookie:")
print(sample_cookie)
with open(filename,'a+') as f:
    f.write("\nconn's sample cookie:") #
    f.write(sample_cookie)  #
    f.write("\n")  #

cookie_IV = "5468697320697320616e204956343536"
cookie_c0 = "dffe62b4c63dbb7a9d597ef15dd270df"
cookie_c1 = "e4ee7d0c35d41276e6c8c1cfe49c1bfd"


cookie_c3 = "a5e6f54ea599ceb9f7decf0b7445f1a5"
cookie_c2_origin = "4db86175e5f72ffe02a9e3a766e9abd4"

def sxor(s1, s2):
    str1 = ''
    hex_ints1 = int(s1, 16)
    hex_ints2 = int(s2, 16)
    return hex(hex_ints1 ^ hex_ints2)[2:]

def sxor3(s1, s2, s3):
    hex_ints1 = int(s1, 16)
    hex_ints2 = int(s2, 16)
    hex_ints3 = int(s3, 16)
    return hex(hex_ints1 ^ hex_ints2 ^ hex_ints3)[2:]




hex_len = pow(16,2)

chararray = []
for i in range(hex_len):
    chararray.append((hex(i)[2:]).zfill(2))


print chararray


# cookie_c3_last = c0

get_guess = null

for i in range(hex_len):
    # guess = chararray[i]# for the right most byte, char_deal = 1
    guess = (chararray[i]+need_value).zfill(char_deal*2)
    guess_xor_pad = sxor(guess, pad).zfill(char_deal*2)
    last_nchar = cookie_c2_origin[32-(char_deal*2):]
    cookie_c2 = cookie_c2_origin[:32-(char_deal*2)] + sxor(last_nchar, guess_xor_pad).zfill(char_deal*2)
    print  "\noriginal C_[2][m]: ", last_nchar, "  guess: ", guess, "  Xored: ", guess_xor_pad
    print "Xored Cookie C_[2][%d]: ", sxor(cookie_c2_origin[32-(char_deal*2):], guess_xor_pad).zfill(char_deal*2)
    cookie = cookie_IV + cookie_c0 + cookie_c1 + cookie_c2 + cookie_c3
    print "send new cookie ", cookie
    with open(filename, 'a+') as f:
        f.write("\nsend new cookie: ")
        f.write(cookie)
        f.write("\noriginal C_[1][m]: ")
        f.write(last_nchar)
        f.write("  guess: ")
        f.write(guess)
        f.write("  Xored: ")
        f.write(guess_xor_pad)
        f.write("\nXored Cookie C_[1][%d]: ")
        f.write(sxor(cookie_c2_origin[32-(char_deal*2):], guess_xor_pad).zfill(char_deal*2))
    conn = remote(host, port)
    conn.recvline_contains("What is your cookie?", keepends=False, timeout=5)
    conn.sendline(cookie)
    response = conn.recvall()
    # print "\ni=", i + 1
    if "padding" not in response:
        get_guess = cookie_c2
        print '\n', response
        with open(filename, 'a+') as f:
            f.write("\n response: \n ")
            f.write(response)
    else:
        print "not this one"
        with open(filename, 'a+') as f:
            f.write("\n not this one \n")
            f.write(response)
    conn.close()

if get_guess == null:
    print "not this combination"
    with open(filename, 'a+') as f:
        f.write("\n not this combination")
else:
    print "get xored cookie_1", get_guess
    with open(filename, 'a+') as f:
        f.write("\n get xored cookie_c1")
        f.write(cookie_c2)
