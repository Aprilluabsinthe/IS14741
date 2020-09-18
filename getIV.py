# !/usr/bin/env python
from pwn import *

context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)
host, port = "192.168.2.83", 28075

# modify here
pn_value = ""
filename = "getIV.txt"
conn = remote(host, port)
content = conn.recv(1024)
with open(filename, 'a+') as f:
    f.write(content)  # Welcome to Secure Encryption Service version 1.19

sample_cookie_prompt = "Here is a sample cookie: "
sample_cookie = conn.recvline_contains(sample_cookie_prompt, keepends=False, timeout=3)
sample_cookie = sample_cookie[len(sample_cookie_prompt):]
print("\nconn's sample cookie:")
print(sample_cookie)

filename = "cal_IV.txt"
with open(filename, 'a+') as f:
    f.write("\nconn's sample cookie:")  #
    f.write(sample_cookie)  #
    f.write("\n")

    IV_origin = "5468697320697320616e204956343536"
    cookie_c0_origin = "dffe62b4c63dbb7a9d597ef15dd270df"
    cookie_c1_origin = "e4ee7d0c35d41276e6c8c1cfe49c1bfd"
    cookie_c2_origin = "4db86175e5f72ffe02a9e3a766e9abd4"
    cookie_c3_origin = "a5e6f54ea599ceb9f7decf0b7445f1a5"
    cookie_c4_origin = "75d59d5045214af8339a71c8d9af82a4"  # type: string

    plain_p0 = "7b22757365726e616d65223a20226775"
    plain_p1 = "657374222c202265787069726573223a"
    plain_p2 = "2022323030302d30312d3037222c2022"
    plain_p3 = "69735f61646d696e223a202266616c73"
    plain_p4 = "65227d0d0d0d0d0d0d0d0d0d0d0d0d0d"

    plain_p0_new = "7b22757365726e616d65223a20226775"
    plain_p1_new = "657374222c202265787069726573223a"
    plain_p2_new = "2022323032302d31312d3037222c2022"
    plain_p3_new = "69735f61646d696e223a202022747275"
    plain_p4_new = "65227d0d0d0d0d0d0d0d0d0d0d0d0d0d"

    plain_p2_after = "262432f11bb814d4a64b288afb3cb972"
    plain_p1_after = "786355ab644a6040c2578180961850ea"
    plain_p0_after = "6212de6fca6eae4a041870a7c1a96ab0"


def sxor(s1, s2):
    str1 = ''
    hex_ints1 = int(s1, 16)
    hex_ints2 = int(s2, 16)
    return hex(hex_ints1 ^ hex_ints2)[2:]


P3_need = sxor(plain_p3, plain_p3_new).zfill(32)  # P3_need = "00000000000000000000000244151e06"
print "P3 need:", P3_need
cookie_c2_neworigin = sxor(cookie_c2_origin, P3_need)
print "cookie_c2_neworigin : ", cookie_c2_neworigin

P2_need = sxor(plain_p2_after, plain_p2_new).zfill(32)
print "P2 need:", P2_need
cookie_c1_neworigin = sxor(cookie_c1_origin, P2_need)
print "cookie_c1_neworigin : ", cookie_c1_neworigin
#
P1_need = sxor(plain_p1_after, plain_p1_new).zfill(32)
print "P1 need:", P1_need
cookie_c0_neworigin = sxor(cookie_c0_origin, P1_need)
print "cookie_c0_neworigin : ", cookie_c0_neworigin
#
P0_need = sxor(plain_p0_after, plain_p0_new).zfill(32)
print "P0 need:", P0_need
IV_neworigin = sxor(IV_origin, P0_need)
print "IV_neworigin : ", IV_neworigin

cookie_new = IV_neworigin + cookie_c0_neworigin + cookie_c1_neworigin + cookie_c2_neworigin + cookie_c3_origin + cookie_c4_origin
print "cookie_new : ", cookie_new
conn = remote(host, port)
conn.recvline_contains("What is your cookie?", keepends=False, timeout=5)
conn.sendline(cookie_new)
response = conn.recvall()
print "response", response