from json import loads

from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import ServerFactory
from twisted.internet.ssl import DefaultOpenSSLContextFactory
from twisted.protocols.basic import LineReceiver
from twisted.python import log

from txws import WebSocketFactory

from vncap.vnc.factory import VNCProxy

# Allowed proxy port ranges.
# By default, this is the VNC port range.
# To use a different port range, simply change the following two lines.
FIRST_PORT = 5800
LAST_PORT = 5900

class ControlProtocol(LineReceiver):

    def lineReceived(self, line):
        log.msg("Received line %s" % line)
        try:
            d = loads(line)
            # Required names.
            host = d["daddr"]
            dport = d["dport"]
            password = d["password"]
            # Optional names.
            sport = d.get("sport")
            ws = d.get("ws", False)
            tls = d.get("tls", False)
            client_opts = d.get("client", {})
            timeout_secs = d.get("timeout", 30)

            # Allocate the source port.
            sport = self.factory.allocate_port(sport)

            factory = VNCProxy(host, dport, password, client_opts)

            if ws:
                factory = WebSocketFactory(factory)
            if tls:
                context = DefaultOpenSSLContextFactory("keys/vncap.key",
                                                       "keys/vncap.crt")
                listening = reactor.listenSSL(sport, factory, context)
            else:
                listening = reactor.listenTCP(sport, factory)

            # Set up our timeout.
            def timeout():
                log.msg("Timed out connection on port %d" % sport)
                listening.stopListening()
                self.factory.free_port(sport)
            reactor.callLater(timeout_secs, timeout)

            log.msg("New forwarder (%d->%s:%d)" % (sport, host, dport))
            self.sendLine("%d" % sport)
        except (KeyError, ValueError):
            log.msg("Couldn't handle line %s" % line)
            self.sendLine("FAILED")
        except CannotListenError:
            # Couldn't bind the port. Don't free it, as it's probably not
            # available to us.
            log.msg("Couldn't bind port %d" % sport)
            self.sendLine("FAILED")

        self.transport.loseConnection()

class ControlFactory(ServerFactory):
    protocol = ControlProtocol

    def __init__(self):
        self.pool = set(range(FIRST_PORT, LAST_PORT))

    def allocate_port(self, port=None):
        """
        Allocate a port.

        If a specific port is requested, try to allocate that port. A random
        port will be selected if it is not available. A random port will also
        be selected if no specific port is requested.
        """

        if port not in self.pool:
            port = self.pool.pop()

        self.pool.discard(port)
        return port

    def free_port(self, port):
        """
        Free a port for further allocations.
        """

        self.pool.add(port)
