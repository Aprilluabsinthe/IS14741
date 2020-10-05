#!/usr/bin/python3
import logging
import re

from OpenSSL import SSL, crypto
import socket
import certifi
import pem
import fnmatch
import urllib

# Cert Paths
from OpenSSL.crypto import X509StoreContext

TRUSTED_CERTS_PEM = certifi.where()


def get_cert_chain(target_domain):
    '''
    This function gets the certificate chain from the provided
    target domain. This will be a list of x509 certificate objects.
    '''
    # Set up a TLS Connection
    dst = (target_domain.encode('utf-8'), 443)
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    s = socket.create_connection(dst)
    s = SSL.Connection(ctx, s)
    s.set_connect_state()
    s.set_tlsext_host_name(dst[0])

    # Send HTTP Req (initiates TLS Connection)
    s.sendall('HEAD / HTTP/1.0\n\n'.encode('utf-8'))
    s.recv(16)

    # Get Cert Meta Data from TLS connection
    test_site_certs = s.get_peer_cert_chain()
    s.close()
    return test_site_certs


############### Add Any Helper Functions Below

def anchor_CAs():
    anchors = []
    file = open(TRUSTED_CERTS_PEM).read()
    blocks = file.split("\n\n")
    CA_certs = []
    for block in blocks:
        CA_cert = crypto.load_certificate(crypto.FILETYPE_PEM, block)
        CA_certs.append(CA_cert)
    return CA_certs


def get_user_name(cert):
    for component in cert.get_subject().get_components():
        if b'CN' in component[0]:
            return (component[1].decode('utf-8'))
# def get_user_name

def get_root_name(target_domain):
    chain = get_cert_chain(target_domain)
    root = chain[-1].get_issuer()
    for component in root.get_components():
        if b'CN' in component[0]:
            return (component[1].decode('utf-8'))


def root_in_trust(target_domain):
    root_name = get_root_name(target_domain)
    for an in anchor_CAs():
        name = get_user_name(an)
        if name == root_name:
            return True
    return False


def locate_root(target_domain):
    root_name = get_root_name(target_domain)
    for an in anchor_CAs():
        name = get_user_name(an)
        if name == root_name:
            return an
    return


def get_DNS(cert):
    DNSstring = []
    for i in range(cert.get_extension_count()):
        com = cert.get_extension(i)
        if 'DNS:' in str(com):
            DNSstring = str(com).strip().split(',')
    DNS = []
    for s in DNSstring:
        DNS.append(s.strip()[4:])
    return DNS


def inDNS(target_domain: str) -> bool:
    cert0 = get_cert_chain(target_domain)[0]
    DNS = get_DNS(cert0)
    for site in DNS:
        ismatched = (target_domain == site) or (
                fnmatch.fnmatch(target_domain, site) and (target_domain.count('.') == site.count('.')))
        if ismatched:  # target domain not in DNS
            return True
    return False

def match_target(target_domain):
    try:
        chain = get_cert_chain(target_domain)
        domain_useful = target_domain
    except:
        try:
            chain = get_cert_chain("www." + target_domain)
            domain_useful = "www."+target_domain
        except:
            try:
                chain = get_cert_chain(target_domain[4:])
                domain_useful = target_domain[4:]
            except:
                return
    return domain_useful
##############################################

def x509_cert_chain_check(target_test: str) -> bool:
    '''
    This function returns true if the target_domain provides a valid 
    x509cert and false in case it doesn't or if there's an error.
    '''
    # TODO: Complete Me!
    target_domain = match_target(target_test)
    chain = get_cert_chain(target_domain)
    depth = len(chain)
    print("pass: can be tracked, depth:{}".format(depth))

    # leaf not expired
    if chain[0].has_expired():
        print("not pass: has expired")
        return False
    print("pass: not expired")

    # root in trust
    if root_in_trust(target_domain) == True:
        root_cer = locate_root(target_domain)
        print("pass: root in trust")
    else:
        print("not pass: root not in Trust List")
        return False

    # verify the CAs of root in X509store
    store = crypto.X509Store()
    for an in anchor_CAs():
        store.add_cert(an)
    for an in anchor_CAs():
        store_ctx_CA = crypto.X509StoreContext(store, an)
        try:
            store_ctx_CA.verify_certificate()
        except:
            print("not pass: CAs unreliable")
            return False
    print("pass: CAs can be trusted and load successfully")

    # verify the validation of root in X509store
    store_ctx_root = crypto.X509StoreContext(store, root_cer)
    try:
        store_ctx_root.verify_certificate()
        print("pass: root certificate reliable")
    except:
        print("not pass: root certificate of chain unreliable")
        return False

    # verify from root to leaf
    for j in range(depth - 1, -1, -1):
        intermediate = chain[j]
        store_ctx = crypto.X509StoreContext(store, intermediate)
        try:
            store_ctx.verify_certificate()
            store.add_cert(intermediate)
            print("pass: intermediate {} verified and added".format(j))
        except:
            print("not pass: intermediate not to be trusted")
            return False

    # target name in DNS
    name_in = inDNS(target_domain)
    if not name_in:
        print("not pass: domain not in DNS")
        return False
    print("pass: name match DNS")
    print("Target Domain Verified")
    return True


if __name__ == "__main__":

    # Standalone running to help you test your program
    print("Certificate Validator...")
    target_domain = input("Enter TLS site to validate: ")
    print("Certificate for {} verifed: {}".format(target_domain, x509_cert_chain_check(target_domain)))
    print(anchor_CAs()[0])