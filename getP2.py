# build link
from pwn import *

context.log_level = 'error'
context.proxy = (socks.SOCKS5, 'localhost', 8123)
host, port = "192.168.2.83", 28075

# 0x00~0xff
hex_len = pow(16, 2)
chararray = []
for i in range(hex_len):
    chararray.append((hex(i)[2:]).zfill(2))
print chararray

# function string xor
def sxor(s1, s2):
    str1 = ''
    hex_ints1 = int(s1, 16)
    hex_ints2 = int(s2, 16)
    return hex(hex_ints1 ^ hex_ints2)[2:]

# The encrypt values
# the original old cookie
IV_origin = "5468697320697320616e204956343536"
cookie_c0_origin = "dffe62b4c63dbb7a9d597ef15dd270df"
cookie_c1_origin = "e4ee7d0c35d41276e6c8c1cfe49c1bfd"
cookie_c2_origin = "4db86175e5f72ffe02a9e3a766e9abd4"
cookie_c3_origin = "a5e6f54ea599ceb9f7decf0b7445f1a5"
cookie_c4_origin = "75d59d5045214af8339a71c8d9af82a4"  # type: string

# the Decrypted plaintext {not admin,expired}
# '{"username": "guest", "expires": "2000-01-07", "is_admin": "false"}'
plain_p0 = "7b22757365726e616d65223a20226775"
plain_p1 = "657374222c202265787069726573223a"
plain_p2 = "2022323030302d30312d3037222c2022"
plain_p3 = "69735f61646d696e223a202266616c73"
plain_p4 = "65227d0d0d0d0d0d0d0d0d0d0d0d0d0d"

# the ideal plaintext {admin,not expired}
# '{"username": "guest", "expires": "2020-11-07", "is_admin":  "true"}'
plain_p0_new = "7b22757365726e616d65223a20226775"
plain_p1_new = "657374222c202265787069726573223a"
plain_p2_new = "2022323032302d31312d3037222c2022"
plain_p3_new = "69735f61646d696e223a202022747275"
plain_p4_new = "65227d0d0d0d0d0d0d0d0d0d0d0d0d0d"

# the P' s
plain_p2_after = "262432f11bb814d4a64b288afb3cb972"# released after changing P3,C2, finish C1=>P2'
plain_p1_after = "6212de6fca6eae4a041870a7c1a96ab0"# released after changing P2,C1, finish C0=>P1'
plain_p0_after = "6212de6fca6eae4a041870a7c1a96ab0"# released after changing P1,C0, finish IV=>P0''


# the loop, almost the same as decryption
pn_value = ""
for j in range(1, 17, 1):
    char_deal = j
    filename = "cal_P2" + str(j) + ".txt"
    print "pn_value", pn_value
    need_value = pn_value.zfill((char_deal - 1) * 2)
    # to connect and write down
    conn = remote(host, port)
    content = conn.recv(1024)
    with open(filename, 'a+') as f:
        f.write(content)
    sample_cookie_prompt = "Here is a sample cookie: "
    sample_cookie = conn.recvline_contains(sample_cookie_prompt, keepends=False, timeout=3)
    sample_cookie = sample_cookie[len(sample_cookie_prompt):]
    print("\nconn's sample cookie:")
    print(sample_cookie)
    with open(filename, 'a+') as f:
        f.write("\nconn's sample cookie:")  #
        f.write(sample_cookie)  #
        f.write("\n")

    # calculate the paddings for j bytes
    pad = (char_deal) * (hex(char_deal))[2:].zfill(2)
    print pad
    with open(filename, 'a+') as f:
        f.write("\npad ")
        f.write(pad)

    # calculate the Pn_needs
    # The first, change P3, get C2
    P3_need = sxor(plain_p3, plain_p3_new).zfill(32)  # P3_need = "00000000000000000000000244151e06"
    print "P3 need:", P3_need
    cookie_c2_neworigin = sxor(cookie_c2_origin, P3_need)
    print "cookie_c2_neworigin : ", cookie_c2_neworigin

    # The second, change P2, get C1
    # comment out when P3,C2 are done
    P2_need = sxor(plain_p2_after, plain_p2_new).zfill(32)
    print "P2 need:", P2_need
    cookie_c1_neworigin = sxor(cookie_c1_origin, P2_need)
    print "cookie_c1_neworigin : ", cookie_c1_neworigin

    # The third, change P1, get C0
    # comment out when P3,C2 P2,C1 are done
    P1_need = sxor(plain_p1_after, plain_p1_new).zfill(32)
    print "P1 need:", P1_need
    cookie_c0_neworigin = sxor(cookie_c0_origin, P1_need)
    print "cookie_c0_neworigin : ", cookie_c0_neworigin

    # The third, change P0, get IV
    # comment out when P3,C2 P2,C1,P1,C0 are done
    P0_need = sxor(plain_p0_after, plain_p0_new).zfill(32)
    print "P0 need:", P0_need
    IV_neworigin = sxor(IV_origin, P0_need)
    print "IV_neworigin : ", IV_neworigin

    # The final step, calculate new cookie and send it to the server
    # comment out when all the calculations are finished.
    # cookie_new = IV_neworigin + cookie_c0_neworigin + cookie_c1_neworigin + cookie_c2_neworigin + cookie_c3_origin + cookie_c4_origin
    # print "cookie_new : ", cookie_new
    # conn = remote(host, port)
    # conn.recvline_contains("What is your cookie?", keepends=False, timeout=5)
    # conn.sendline(cookie_new)
    # response = conn.recvall()
    # print "response", response



    # The oscillation loop
    get_guess = null

    for i in range(hex_len):
        # guess = chararray[i]# for the right most byte, char_deal = 1
        guess = (chararray[i]+need_value).zfill(char_deal*2)
        guess_xor_pad = sxor(guess, pad).zfill(char_deal*2)
        last_nchar = IV_origin[32-(char_deal*2):]
        IV = IV_origin[:32-(char_deal*2)] + sxor(last_nchar, guess_xor_pad).zfill(char_deal*2)
        print  "\noriginal C1[m]: ", last_nchar, "  guess: ", guess, "  Xored: ", guess_xor_pad
        print "Xored c1[%d]: ", sxor(IV_origin[32-(char_deal*2):], guess_xor_pad).zfill(char_deal*2)
        cookie = IV + cookie_c0_neworigin

        # send and print
        print "send new cookie ", cookie
        with open(filename, 'a+') as f:
            f.write("\nsend new cookie: ")
            f.write(cookie)
            f.write("\noriginal c[1][m]: ")
            f.write(last_nchar)
            f.write("  guess: ")
            f.write(guess)
            f.write("  Xored: ")
            f.write(guess_xor_pad)
            f.write("\nXored c1[%d]: ")
            f.write(sxor(cookie_c1_origin[32-(char_deal*2):], guess_xor_pad).zfill(char_deal*2))
        conn = remote(host, port)
        conn.recvline_contains("What is your cookie?", keepends=False, timeout=5)
        conn.sendline(cookie)
        response = conn.recvall()

        # do the judgement
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

    # should not happen, indicates error situation
    if get_guess == null:
        print "not this combination"
        with open(filename, 'a+') as f:
            f.write("\n not this combination")
    else:
        print "get xored c1", get_guess
        with open(filename, 'a+') as f:
            f.write("\n get guess")
            f.write(get_guess)