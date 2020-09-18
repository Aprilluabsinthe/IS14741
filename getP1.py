# !/usr/bin/env python
from pwn import *

context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)
host, port = "192.168.2.83", 28075

# modify here
pn_value = ""

for j in range(1, 17, 1):
    char_deal = j
    filename = "cal_P1" + str(j) + ".txt"
    print "pn_value", pn_value
    need_value = pn_value.zfill((char_deal - 1) * 2)

    conn = remote(host, port)
    content = conn.recv(1024)
    with open(filename, 'a+') as f:
        f.write(content)  # Welcome to Secure Encryption Service version 1.19

    sample_cookie_prompt = "Here is a sample cookie: "
    sample_cookie = conn.recvline_contains(sample_cookie_prompt, keepends=False, timeout=3)
    sample_cookie = sample_cookie[len(sample_cookie_prompt):]
    print("\nconn's sample cookie:")
    print(sample_cookie)
    with open(filename, 'a+') as f:
        f.write("\nconn's sample cookie:")  #
        f.write(sample_cookie)  #
        f.write("\n")

    hex_len = pow(16, 2)

    chararray = []
    for i in range(hex_len):
        chararray.append((hex(i)[2:]).zfill(2))
    print chararray

    pad = (char_deal) * (hex(char_deal))[2:].zfill(2)
    print pad
    with open(filename, 'a+') as f:
        f.write("\npad ")
        f.write(pad)

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

    get_guess = null

    for i in range(hex_len):
        # guess = chararray[i]# for the right most byte, char_deal = 1
        guess = (chararray[i]+need_value).zfill(char_deal*2)
        guess_xor_pad = sxor(guess, pad).zfill(char_deal*2)
        last_nchar = cookie_c0_origin[32-(char_deal*2):]
        cookie_c0 = cookie_c0_origin[:32-(char_deal*2)] + sxor(last_nchar, guess_xor_pad).zfill(char_deal*2)
        print  "\noriginal C0[m]: ", last_nchar, "  guess: ", guess, "  Xored: ", guess_xor_pad
        print "Xored c0[%d]: ", sxor(cookie_c1_origin[32-(char_deal*2):], guess_xor_pad).zfill(char_deal*2)
        cookie = IV_origin + cookie_c0 + cookie_c1_neworigin
        print "send new cookie ", cookie
        with open(filename, 'a+') as f:
            f.write("\nsend new cookie: ")
            f.write(cookie)
            f.write("\noriginal c[0][m]: ")
            f.write(last_nchar)
            f.write("  guess: ")
            f.write(guess)
            f.write("  Xored: ")
            f.write(guess_xor_pad)
            f.write("\nXored c0[%d]: ")
            f.write(sxor(cookie_c0_origin[32-(char_deal*2):], guess_xor_pad).zfill(char_deal*2))
        conn = remote(host, port)
        conn.recvline_contains("What is your cookie?", keepends=False, timeout=5)
        conn.sendline(cookie)
        response = conn.recvall()
        # print "\ni=", i + 1
        if "padding" not in response:
            get_guess = guess
            pn_value = guess
            print '\n', response
            with open(filename, 'a+') as f:
                f.write("\n response: \n ")
                f.write(response)
            break
        else :
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
        print "get xored c1", get_guess
        with open(filename, 'a+') as f:
            f.write("\n get guess")
            f.write(get_guess)