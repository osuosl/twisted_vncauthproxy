import os

from twisted.conch.ssh.channel import SSHChannel
from twisted.conch.ssh.common import NS
from twisted.conch.ssh.connection import SSHConnection
from twisted.conch.ssh.keys import Key
from twisted.conch.ssh.session import packRequest_pty_req
from twisted.conch.ssh.transport import SSHClientTransport
from twisted.conch.ssh.userauth import SSHUserAuthClient
from twisted.internet import defer, protocol, reactor
from twisted.internet.stdio import StandardIO
from twisted.protocols.portforward import Proxy

USER = 'root'  # replace this with a valid username
HOST = 'localhost' # and a valid host

key_path = "keys/id_rsa_client"

class KeyOnlyAuth(SSHUserAuthClient):

    preferredOrder = ("publickey",)

    def getPublicKey(self):
        # this works with rsa too
        # just change the name here and in getPrivateKey
        if not os.path.exists(key_path) or self.lastPublicKey:
            # the file doesn't exist, or we've tried a public key
            return
        return Key.fromFile(key_path + ".pub")

    def getPrivateKey(self):
        return defer.succeed(Key.fromFile(key_path))

class SocatChannel(SSHChannel):

    name = 'session'
    peer = None

    def openFailed(self, reason):
        print 'echo failed', reason

    def channelOpen(self, ignoredData):
        req = packRequest_pty_req("xterm", (24, 80, 0, 0), "")
        self.conn.sendRequest(self, "pty-req", req)

        d = self.conn.sendRequest(self, 'exec', NS(" ".join(command)),
                                  wantReply=1)
        @d.addCallback
        def cb(chaff):
            class FakePeer(object):
                transport = self
            proxy = Proxy()
            proxy.setPeer(FakePeer())
            self.peer = proxy
            StandardIO(proxy)

    def dataReceived(self, data):
        if self.peer:
            self.peer.transport.write(data)

    def closed(self):
        print "Connection closed"
        self.loseConnection()
        reactor.stop()

class SocatConnection(SSHConnection):
    def serviceStarted(self):
        self.openChannel(SocatChannel(conn=self))

class CommandTransport(SSHClientTransport):
    """
    A protocol which will connect to a target SSH server and execute a given
    command only.
    """

    def __init__(self, command):
        self.command = command

    def verifyHostKey(self, hostKey, fingerprint):
        print 'host key fingerprint: %s' % fingerprint
        return defer.succeed(1)

    def connectionSecure(self):
        self.requestService(KeyOnlyAuth(USER, SocatConnection()))

command = ['/usr/bin/socat', 'STDIO,raw,echo=0,escape=0x1d',
           'UNIX-CONNECT:/var/run/ganeti/kvm-hypervisor/ctrl/instance1.example.org.serial']

protocol.ClientCreator(reactor, CommandTransport, command).connectTCP(HOST, 9000)
reactor.run()
