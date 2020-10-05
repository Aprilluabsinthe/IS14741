# Certificate Chaining

## Introduction

In this problem, you will be implementing X509 certificate chain checking which
is performed by your browsers each time you visit any of the HTTPS website. While
X509 certificate are used in many places, we will restrict our implementation
to work for basic HTTPS-supporting webservers.

### Expectations

This assignment's main motive is to make you realise that TLS spec is easy to understand
but hard to implement correctly, even when using libraries.
* Watch first 30 minutes of [blackhat](https://www.youtube.com/watch?v=gmYcsdXT3W8) talk 
for a big hint and save yourself from a lot of headache
* Looking for documentation for each of the included packages is a fairgame
* Googling for "python3 certificate validation code" is **NOT**
  * Even if you get it, you will soon realize even those solutions are flawed

## Starter Code

Starter code is provided to you. You need to complete the `certChainCheck.py` file under 
`/solution` directory. More specifically, you need to complete the `x509_cert_chain_check`
function.

You are also provided with:
* `get_cert_chain` which contacts the domain and gets the certificates, in order to make your 
 lives easier.
* All libraries which are required to complete this problem have been provided. You are required 
 to use **ONLY** these libraries to solve this problem. This is also to save you from getting lost
 in figuring out which libraries to use.
* You may however use the regex library or any other python3 native libary in addition to the ones listed
 in the starter code. `fnmatch` should however be simpler and meet your needs.
* You are free to create helper functions in order to help organize your code.

### x509_cert_chain_check() Spec

The function accepts a domain, for example: **www.google.com**, **facebook.com**
are examples of domains. However, "https://www.google.com" is **NOT** an domain.
It then return True / False based on if the server had a valid certificate or not.

## Setup & Testing

This problem requires you to program your solution in `python3`. Our Testing infrastructure
only supports python3.

To get started,
* Install python3 on your system
* `python3 -m pip install -r requirements.txt`

### Testing your solutions

Your implementation will be tested against a predetermined set of test domains which have 
been included in your local testing suite.
```bash
python3 -m unittest tests/basic_tests.py
```
To test your program locally. 

**NOTE:**
* Please make sure not to hardcode any details to pass the test cases since TAs 
  will be manually reviewing your code.
* Any such attempts will result in your solution getting rendered invalid

## Submitting your solution

The solution will be submitted to gradescope based autograder.
* `certChainCheck.py` must be uploaded to the gradescope
* The name should be as is.
