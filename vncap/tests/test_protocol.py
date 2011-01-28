import unittest

from vncap.protocol import VNCServerAuthenticator

class DummyTransport(object):

    buf = ""

    def write(self, data):
        self.buf += data

class TestVNCServerAuthenticator(unittest.TestCase):

    def setUp(self):
        self.p = VNCServerAuthenticator("password")

    def test_trivial(self):
        pass

    def test_connectionMade(self):
        t = DummyTransport()
        self.p.makeConnection(t)
        self.assertEqual(t.buf, "RFB 003.008\n")
