# connect to the server 192.168.2.83:28074
from pwn import *
context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)
host, port = "192.168.2.83", 28074
conn = remote(host, port)

# print hint information
content = conn.recv(1024)
print content
content = conn.recv(1024)
print content
print type(content)

# split the content to get to the two cookies
s = content.split(":")
print s
cookie_admin_expired = (s[1].split("\n"))[0].strip()
cookie_notadmin_notexpired =  (s[2].split("\n"))[0].strip()
print "\ncookie_admin_expired" , cookie_admin_expired
print "\ncookie_notadmin_notexpired" , cookie_notadmin_notexpired

# generate the new cookie
cookie_new = cookie_admin_expired[0:47] + cookie_notadmin_notexpired[47:]
print "\ncookie_new",cookie_new

# send the new cookie to the server
print "\nsend new cookie"
conn.sendline(cookie_new)
print "\nresponse"
response = conn.recvall()
print response







# news = "94d5c4d7fd3c460fcc258d0ae88ae32c497e4d55a29f3a88e7ee437d3a1dd9e9"
# print len(news)
#
# def strxor(a, b):  # xor two strings (trims the longer input)
#     return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])
#
#
# def sxorshort(s1, s2):
#     str0 = ''
#     for i in range(len(s1) - len(s2)):
#         str0.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1[i:(i + len(s2))], s2))
#     return str0
#
#
# def sxor(s1, s2):
#     str1 = ''
#     for i in range(len(s1)):
#         str1.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))
#     print str1
#
#
# # print cookie_others[19]
# # print cookie_my[19
# s = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(cookie_my, cookie_others))
# print len(s)
#
# cypertext = "()()()()())"
# for i in range(len(s) - len(cypertext)):
#     guess = ''.join([chr(ord(a) ^ ord(b)) for a, b in zip(s[i:(i + len(cypertext))], cypertext)])
#     print i, guess
