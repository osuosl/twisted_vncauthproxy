from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.trial import unittest

from vncap.control import ControlProtocol, ControlFactory

class DummyTransport(object):

    def __init__(self):
        self.buf = ""

    def write(self, data):
        self.buf += data

    def loseConnection(self):
        pass

class DummyControlFactory(object):

    def allocate_port(self, port=None):
        return 55555

    def free_port(self, port):
        pass

class TestControlFactory(unittest.TestCase):

    def setUp(self):
        self.cf = ControlFactory()

    def test_trivial(self):
        pass

    def test_allocate_port(self):
        port = self.cf.allocate_port()
        self.assertTrue(1024 < port < 65536)

    def test_allocate_port_default(self):
        port = self.cf.allocate_port(4242)
        self.assertEqual(port, 4242)

    def test_allocate_port_default_privileged(self):
        port = self.cf.allocate_port(42)
        self.assertNotEqual(port, 42)

    def test_free_port(self):
        port = 42
        self.cf.free_port(42)
        self.assertTrue(42 in self.cf.pool)

    def test_allocate_and_free_port(self):
        port = self.cf.allocate_port()
        self.assertTrue(port not in self.cf.pool)
        self.cf.free_port(port)
        self.assertTrue(port in self.cf.pool)

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
        # Set up our test. We want to make sure that no actual ports are
        # opened, so let's patch out listenTCP().
        self.patch(reactor, "listenTCP",
            lambda port, factory, **kwargs: Deferred())
        self.cp.factory = DummyControlFactory()

        self.cp.lineReceived("""{
            "sport": 55555,
            "dport": 11048,
            "daddr": "localhost",
            "password": "fhqwhgads"
        }""")
        self.assertTrue(self.cp.transport.buf.startswith("55555"))

        # Clean up one single delayed call: The timeout.
        delayed = reactor.getDelayedCalls()
        self.assertEqual(len(delayed), 1)
        delayed[0].cancel()
