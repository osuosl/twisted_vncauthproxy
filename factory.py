from twisted.internet import reactor
from twisted.internet.protocol import ClientCreator, Factory

from protocol import VNCServerAuthenticator, VNCClientAuthenticator

class VNCProxy(Factory):

    protocol = VNCServerAuthenticator

    def __init__(self, host, port, password):
        self.cc = ClientCreator(reactor, VNCClientAuthenticator, password)

        self.host = host
        self.port = port
        self.password = password

    def makeProtocol(self, a):
        server = VNCServerAuthenticator(self.password)
        d = self.cc.connectTCP(self.host, self.port)

        d.addCallback(lambda client: (server, client))
        d.addCallback(self.client_connected)
        d.addErrback(lambda chaff: server.loseConnection())

        return server

    def client_connected(self, server_client):
        server, client = server_client

        server.setPeer(client)
        client.setPeer(server)
