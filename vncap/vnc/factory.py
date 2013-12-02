from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.protocol import Factory
from twisted.python import log

from vncap.proxy import prepare_proxy
from vncap.vnc.protocol import VNCServerAuthenticator, VNCClientAuthenticator


class VNCClientAuthenticatorFactory(Factory):
    protocol = VNCClientAuthenticator

    def __init__(self, password):
        self.password = password

    def buildProtocol(self, addr):
        p = self.protocol(self.password)
        p.factory = self
        return p


class VNCProxy(Factory):
    """
    A simple VNC proxy.
    """

    protocol = VNCServerAuthenticator

    def __init__(self, host, port, password, client_opts):
        self.host = host
        self.port = port
        self.password = password
        self.client_opts = client_opts

    def buildProtocol(self, a):
        server = self.protocol(self.password, self.client_opts)

        endpoint = TCP4ClientEndpoint(reactor, self.host, self.port,
                                      timeout=30)
        d = endpoint.connect(VNCClientAuthenticatorFactory(self.password))
        d.addCallback(prepare_proxy, server)

        @d.addErrback
        def cancel_proxy(failure):
            log.err()
            log.msg("Couldn't connect to server, cancelling proxy")
            server.transport.loseConnection()

        return server
