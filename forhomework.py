# !/usr/bin/env python
from pwn import *

context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)
host, port = "192.168.2.83", 28075

IV_origin = "5468697320697320616e204956343536"
cookie_c0_origin = "dffe62b4c63dbb7a9d597ef15dd270df"
cookie_c1_origin = "e4ee7d0c35d41276e6c8c1cfe49c1bfd"
cookie_c2_origin = "4db86175e5f72ffe02a9e3a766e9abd4"
cookie_c3_origin = "a5e6f54ea599ceb9f7decf0b7445f1a5"
cookie_c4_origin = "75d59d5045214af8339a71c8d9af82a4"  # type: string

# function sxor, to do xor in two strings.
def sxor(s1, s2):
    hex_ints1 = int(s1, 16)
    hex_ints2 = int(s2, 16)
    return hex(hex_ints1 ^ hex_ints2)[2:]

# iterate the 16 bytes in a block
pn_value = ""
for j in range(1, 17, 1):
    char_deal = j

    # the right guesses from former loop.The backward bytes in P[n] will need this to be offset to 0x00
    print "pn_value", pn_value
    need_value = pn_value.zfill((char_deal - 1) * 2)

    # make connects, write down in file(recover_P[n]_rightmost bytes.txt)
    filename = "recover_P4_" + str(j) + ".txt"
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

    # necessary pre-calculations and functions. Print it our in every file
    # the total number of combination from 0x00-0xff
    hex_len = pow(16, 2)

    # get 0x00-0xff, 256 elements
    chararray = []
    for i in range(hex_len):
        chararray.append((hex(i)[2:]).zfill(2))
    print chararray

    # get the pad for the rightmost j bytes, for j is the byte in C[n-1] that we are trying to discover
    pad = (char_deal) * (hex(char_deal))[2:].zfill(2)
    print pad
    with open(filename, 'a+') as f:
        f.write("\npad ")
        f.write(pad)

    # iterate from 00 to ff
    get_guess = null
    for i in range(hex_len):
        guess = (chararray[i]+need_value).zfill(char_deal*2)# guess = [0x00~0xff]+[rightguess]
        guess_xor_pad = sxor(guess, pad).zfill(char_deal*2)# guess xor with paddings
        # modify C[n-1] by dong xor with guess_xor_pad
        last_nchar = cookie_c3_origin[32-(char_deal*2):]
        cookie_c3 = cookie_c3_origin[:32-(char_deal*2)] + sxor(last_nchar, guess_xor_pad).zfill(char_deal*2)

        # print and show
        print  "\noriginal C3[m]: ", last_nchar, "  guess: ", guess, "  Xored: ", guess_xor_pad
        print "Xored c3[%d]: ", sxor(cookie_c3_origin[32-(char_deal*2):], guess_xor_pad).zfill(char_deal*2)

        # the modified cookie
        cookie = IV_origin + cookie_c0_origin + cookie_c1_origin + cookie_c2_origin + cookie_c3 + cookie_c4_origin

        # write to files
        print "send new cookie ", cookie
        with open(filename, 'a+') as f:
            f.write("\nsend new cookie: ")
            f.write(cookie)
            f.write("\noriginal c[3][m]: ")
            f.write(last_nchar)
            f.write("  guess: ")
            f.write(guess)
            f.write("  Xored: ")
            f.write(guess_xor_pad)
            f.write("\nXored c3[%d]: ")
            f.write(sxor(cookie_c3_origin[32-(char_deal*2):], guess_xor_pad).zfill(char_deal*2))

        # make sure we have connections, send modified cookie when asked
        conn = remote(host, port)
        conn.recvline_contains("What is your cookie?", keepends=False, timeout=5)
        conn.sendline(cookie)

        # get response,

        # if the rsponse is dropped by d=json.loads(unpad(cookie2decoded)),
        # then we have found the right guess.
        # take down the guess and break out the loop for the next byte forehead.
        response = conn.recvall()
        if "JSON" in response:
            get_guess = guess
            pn_value = guess # pass the value to global value for next loop
            print '\n', response
            with open(filename, 'a+') as f:
                f.write("\n response: \n ")
                f.write(response)
            break
        # if the rsponse is "invalid padding", then try next chararray[i+1]
        else :
            print "not this one"
            with open(filename, 'a+') as f:
                f.write("\n not this one \n")
                f.write(response)
        conn.close()
    # if all the 256 values from 0x00-0xff can not trigger valid padding,
    # there mast be something wrong with our value
    if get_guess == null:
        print "not this combination"
        with open(filename, 'a+') as f:
            f.write("\n not this combination")
    else:
        print "get xored c3", get_guess
        with open(filename, 'a+') as f:
            f.write("\n get guess")
            f.write(get_guess)