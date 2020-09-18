# -*- coding:utf-8 -*-
# from Crypto.Cipher import AES
cookie_stolen = "5468697320697320616e204956343536dffe62b4c63dbb7a9d597ef15dd270dfe4ee7d0c35d41276e6c8c1cfe49c1bfd4db86175e5f72ffe02a9e3a766e9abd4a5e6f54ea599ceb9f7decf0b7445f1a575d59d5045214af8339a71c8d9af82a4"
print len(cookie_stolen)
print (cookie_stolen[:32].decode("hex"))
print cookie_stolen[:32]
print (cookie_stolen[32:].decode("hex"))
last_word = cookie_stolen[-32:]
last_word_de = last_word.decode("hex")
last_word2 = cookie_stolen[-64:-32]
last_word_de = last_word2.decode("hex")


print 'last',last_word,len(last_word),last_word.decode("hex")
print 'last 2',last_word2,len(last_word2),last_word2.decode("hex")
realpad = cookie_stolen[32:]
IV="This is an IV456"
key="secret message0202"
print realpad, len(realpad)# 16*10 real pads

planintext = '{"username":"Absinthe","is_admin":"true","expires"="2020-10-10"}'
planintext_stolen = '{"username":"guest","is_admin":"false","expires"="2020-09-10"}'
print planintext_stolen,len(planintext_stolen)
print planintext_stolen.encode("hex")

def decrypt(m):
  cipher = AES.new(key, AES.MODE_CBC, IV)
  return cipher.decrypt(m[32:].decode("hex"))

def isvalidpad(s):
  return ord(s[-1])*s[-1:]==s[-ord(s[-1]):]

def unpad(s):
  return s[:-ord(s[len(s)-1:])]

cookie2decoded = decrypt(cookie_stolen[:-1])

if isvalidpad(cookie2decoded):
  print unpad(cookie2decoded)
  print unpad(cookie2decoded)