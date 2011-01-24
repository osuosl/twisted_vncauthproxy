from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.protocol import Factory

from vncap.protocol import VNCServerAuthenticator, VNCClientAuthenticator

class VNCProxy(Factory):
    """
    A simple VNC proxy.
    """

    protocol = VNCServerAuthenticator

    def __init__(self, host, port, password):
        self.host = host
        self.port = port
        self.password = password

    def buildProtocol(self, a):
        endpoint = TCP4ClientEndpoint(reactor, self.host, self.port)
        d = endpoint.connect(VNCClientAuthenticator(self.password))

        d.addCallback(lambda client: (server, client))
        d.addCallback(self.client_connected)
        d.addErrback(lambda chaff: server.loseConnection())

        server = self.protocol(self.password)

        return server

    def client_connected(self, server_client):
        server, client = server_client

        server.setPeer(client)
        client.setPeer(server)
