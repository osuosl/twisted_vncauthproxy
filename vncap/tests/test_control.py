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
            """{"hurp": "derp"}""",
        ]
        for line in l:
            self.cp.lineReceived(line)
            self.assertTrue(self.cp.transport.buf.startswith("FAILED"),
                "%s didn't cause an error" % line)
            self.cp.transport.buf = ""

    def test_privileged_port(self):
        self.cp.lineReceived("""{
            "sport": 1,
            "dport": 11048,
            "daddr": "localhost",
            "password": "fhqwhgads"
        }""")
        self.assertTrue(self.cp.transport.buf.startswith("FAILED"))

    def test_forwarding(self):
        self.cp.lineReceived("""{
            "sport": 55555,
            "dport": 11048,
            "daddr": "localhost",
            "password": "fhqwhgads"
        }""")
        self.assertTrue(self.cp.transport.buf.startswith("55555"))

        # Clean up one single delayed call.
        delayed = reactor.getDelayedCalls()
        self.assertEqual(len(delayed), 1)
        delayed[0].cancel()
        reactor.removeAll()
