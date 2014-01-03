from twisted.conch.endpoints import SSHCommandClientEndpoint
from twisted.conch.ssh.keys import Key
from twisted.internet.defer import gatherResults
from twisted.internet.protocol import Factory, Protocol
from twisted.python import log
from vncap.ssh.protocol import SerialProxy, CommandTransport
from vncap.vnc.protocol import VNCServerAuthenticator
from vncap.vnc.factory import VNCClientAuthenticatorFactory

class NoiseProtocol(Protocol):
    def __init__(self, password, client_opts):
        log.msg("init noise")
        self.password = password
        self.client_opts = client_opts

    def connectionMade(self):
        self.finished = Deferred()
        self.strings = ["bif", "pow", "zot"]
        self.sendNoise()

    def sendNoise(self):
        if self.strings:
            self.transport.write(self.strings.pop(0) + "\n")
        else:
            self.transport.loseConnection()

    def dataReceived(self, data):
        print "Server says:", data
        self.sendNoise()

    def connectionLost(self, reason):
        self.finished.callback(None)

def start_proxying(results):
    log.msg("Starting proxy")

def prepare_proxy(client, server):
    log.msg("Preparing proxies for client %s and server %s" % (client, server)



class SSHProxy(Factory):

    def __init__(self, host, port, password, user, command, client_opts):
        log.msg('factory initialized')
        self.host = host
        self.port = port
        self.password = password
        self.user = user
        self.command = command
        self.client_opts = client_opts
        key = Key.fromFile('keys/id_rsa_client')
        if key is not None:
            log.msg('key is not none')
            self.keys = [key]
        else:
            log.msg('key is none')
            self.keys = None
        self.ui = None
        # This server connects to the jsTerm client.
        self.server = SerialProxy(self.password, self.client_opts)
        # This endpoint connects to the node and runs the socat command.
        self.endpoint = SSHCommandClientEndpoint.newConnection(
            reactor, self.command, self.user, self.host,
            port=self.port, keys=self.keys, ui=self.ui)
        d = endpoint.connect(server)
        d.addCallback(prepare_proxy, self.server)
        

    def buildProtocol(self, addr):
        return self.server
        log.msg('starting buildProtocol')
        server = self.protocol(self.password, self.client_opts)
        log.msg('finished self.protocol')

        endpoint = SSHCommandClientEndpoint.newConnection(
            reactor, command, self.user, self.host,
            port=self.port, keys=self.keys, ui=self.ui)
        d = endpoint.connect(server)
        d.addCallback(prepare_proxy, server)

        @d.addErrback
        def cancel_proxy(failure):
            log.err()
            log.msg("Couldn't connect to server, cancelling proxy")
            server.transport.loseConnection()

        return d
