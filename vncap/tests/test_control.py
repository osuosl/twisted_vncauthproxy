from twisted.internet import reactor
from twisted.trial import unittest

from vncap.control import ControlProtocol, ControlFactory

class DummyTransport(object):

    def __init__(self):
        self.buf = ""

    def write(self, data):
        self.buf += data

    def loseConnection(self):
        pass

class TestControlProtocol(unittest.TestCase):

    def setUp(self):
        self.cp = ControlProtocol()

    def test_trivial(self):
        pass

class TestControlProtocolUsage(unittest.TestCase):

    def setUp(self):
        self.cp = ControlProtocol()
        self.cp.transport = DummyTransport()

    def test_trivial(self):
        pass

    def test_bad_data(self):
        l = [
            "herp:derp",
            "herp:derp:lerp:merp",
            ":::::",
            "12:asdf:13",
        ]
        for line in l:
            self.cp.lineReceived(line)
            self.assertTrue(self.cp.transport.buf.startswith("FAILED"),
                "%s didn't cause an error" % line)
            self.cp.transport.buf = ""

    def test_privileged_port(self):
        self.cp.lineReceived("1:localhost:1:password")
        self.assertTrue(self.cp.transport.buf.startswith("FAILED"))

    def test_forwarding(self):
        self.cp.lineReceived("55555:localhost:55555:password")
        self.assertTrue(self.cp.transport.buf.startswith("OK"))

        # Clean up...
        reactor.removeAll()
