from pwn import *
context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)
host, port = "192.168.2.83", 64832
conn = remote(host, port)
content = conn.recv(1024)
print content
content = conn.recv(1024)
print content
conn.interactive()
# sample_cookie_prompt = "Here is a sample cookie: "
# sample_cookie = conn.recvline_contains(sample_cookie_prompt, keepends=False, timeout=3)
# sample_cookie = sample_cookie[len(sample_cookie_prompt):]
# print("\nconn's sample cookie:")
# print(sample_cookie)
# conn.recvline_contains("What is your cookie?", keepends=False, timeout=5)
# conn.sendline(cookie_new)
# response = conn.recvall()
# text2 = "12345678901234567890123456789012"
# mytext = "thisisatheqwrtghdyfjskeowisucyde"
# print("My text is:", mytext)
# print("My text length is:", len(mytext))
#
# # encode2 = "5dce97b5349ae52c0bee0f4fc770788b672d616dd52336420500f0f2829c2958"
# encoded_mytext = "c03985b7e1afb979308d2cccf4f75d0344ca181f57af574db7155b7899358979"
# print ("My text encode to be:", encoded_mytext)
# print ("length of encoded mytext:", len(encoded_mytext))
#
# # tobe2 = "59cc93b2319feb2d00ed0d4fc4737b846326616ed52333470800fffb8d992f5e"
# tobe_decoded = "8161dbf7b8efe1346adb6e89b6b40c521380474615f60413f84a103ccc79da28"
# print("The text to be decoded :", tobe_decoded)
# print("The length of text to be decoded :", len(tobe_decoded))
#
# def strxor(s1, s2):  # xor two strings (trims the longer input)
#     # type: (string, string) -> stringans
#     return "".join([chr(ord(a) ^ ord(b)) for (a, b) in zip(s1, s2)])
#
# key = strxor(encoded_mytext.decode("hex"), mytext)
# print "cipher key length: ", len(key)
#
# tobe_de = strxor(tobe_decoded.decode("hex"), key)
# print "the plain text :", tobe_de
