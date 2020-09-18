
from pwn import *
import os
context.log_level = 'error'
# context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)
host, port = "192.168.2.83", 28075
conn = remote(host, port)
content = conn.recv(1024)
print (content)  # Welcome to Secure Encryption Service version 1.19
filename = "lastbite.txt"
sample_cookie_prompt = "Here is a sample cookie: "
sample_cookie = conn.recvline_contains(sample_cookie_prompt, keepends=False, timeout=3)
sample_cookie = sample_cookie[len(sample_cookie_prompt):]
print("\nconn's sample cookie:")
print(sample_cookie)
chararray = []
hex_len = 256
for i in range(hex_len):
    chararray.append((hex(i)[2:]).zfill(2))

cookieori = "5468697320697320616e204956343536dffe62b4c63dbb7a9d597ef15dd270dfe4ee7d0c35d41276e6c8c1cfe49c1bfd4db86175e5f72ffe02a9e3a766e9abd4a5e6f54ea599ceb9f7decf0b7445f1"
cookie4 = "75d59d5045214af8339a71c8d9af82a4"
for i in range(hex_len):
    cookie = cookieori + chararray[i] + cookie4
    print "send new cookie a5->", chararray[i]
    with open(filename, 'a+') as f:
        f.write("\nsend new cookie a5->")
        f.write(chararray[i])
    conn = remote(host, port)
    conn.recvline_contains("What is your cookie?", keepends=False, timeout=5)
    conn.sendline(cookie)
    response = conn.recvall()
    # print "\ni=", i + 1
    get = " "
    if "invalid" not in response:
        with open(filename, 'a+') as f:
            f.write("\nresponse")
            f.write(response)
        print '\n', response
        get = cookie
    if get != " ":
        print get
        with open(filename, 'a+') as f:
            f.write("\nget")
            f.write(get)
    else:
        with open(filename, 'a+') as f:
            f.write("\nnot this one")  #
    conn.close()
