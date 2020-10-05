import unittest
from solution.certChainCheck import x509_cert_chain_check

class TestBasicDomains(unittest.TestCase):

    # def test_baidu(self):
    #     self.assertEqual(x509_cert_chain_check("baidu.com"), True,
    #                      "baidu.com has valid cert.")
    #
    # def test_iqiyi(self):
    #     self.assertEqual(x509_cert_chain_check("www.iqiyi.com"), True,
    #                      "www.iqiyi.com has valid cert.")
    #
    # def test_bilibili(self):
    #     self.assertEqual(x509_cert_chain_check("www.bilibili.com"), True,
    #                      "www.bilibili.com has valid cert.")

    def test_google(self):
        self.assertEqual(x509_cert_chain_check("google.com"), True,
        "google.com has valid cert.")

    def test_facebook(self):
        self.assertEqual(x509_cert_chain_check("www.facebook.com"), True,
        "www.facebook.com has valid cert.")

    def test_youtube(self):
        self.assertEqual(x509_cert_chain_check("www.youtube.com"), True,
        "www.youtube.com has valid cert.")

    def test_expired(self):
        self.assertEqual(x509_cert_chain_check("expired.badssl.com"), False, 
        "expired.badssl.com has an invalid cert.")

    def test_wrong_host(self):
        self.assertEqual(x509_cert_chain_check("wrong.host.badssl.com"), False, 
        "wrong.host.badssl.com has an invalid cert.")

    def test_self_signed(self):
        self.assertEqual(x509_cert_chain_check("self-signed.badssl.com"), False, 
        "self-signed.badssl.com has an invalid cert.")

    def test_untrusted_root(self):
        self.assertEqual(x509_cert_chain_check("untrusted-root.badssl.com"), False, 
        "untrusted-root.badssl.com has an invalid cert.")

if __name__ == '__main__':
    unittest.main()
