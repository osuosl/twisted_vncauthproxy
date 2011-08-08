import os
import sys

from twisted.python import log
log.startLogging(sys.stdout)

from twisted.conch.avatar import ConchUser
from twisted.conch.interfaces import IConchUser
from twisted.conch.ssh.channel import SSHChannel
from twisted.conch.ssh.common import NS
from twisted.conch.ssh.connection import SSHConnection
from twisted.conch.ssh.factory import SSHFactory
from twisted.conch.ssh.keys import Key
from twisted.conch.ssh.session import (SSHSessionProcessProtocol,
                                       wrapProtocol, packRequest_pty_req,
                                       parseRequest_pty_req)
from twisted.conch.ssh.transport import SSHClientTransport
from twisted.conch.ssh.userauth import SSHUserAuthClient
from twisted.conch.telnet import ITelnetProtocol
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.cred.portal import IRealm, Portal
from twisted.internet import reactor
from twisted.internet.defer import succeed
from twisted.internet.protocol import ClientCreator
from twisted.protocols.portforward import Proxy
from zope.interface import implements

checker = InMemoryUsernamePasswordDatabaseDontUse()
checker.addUser("simpson", "hurp")

def attach_protocol_to_channel(protocol, channel):
    # These are from
    # http://as.ynchrono.us/2011/08/twisted-conch-in-60-seconds-protocols.html
    transport = SSHSessionProcessProtocol(channel)
    protocol.makeConnection(transport)
    transport.makeConnection(wrapProtocol(protocol))
    channel.client = transport

    # And this one's from me :3
    channel.dataReceived = protocol.dataReceived

class ChannelBase(SSHChannel):

    name = "session"

    def __init__(self, *args, **kwargs):
        SSHChannel.__init__(self, *args, **kwargs)

        self.proxy = Proxy()
        attach_protocol_to_channel(self.proxy, self)

class Session(ChannelBase):

    def request_pty_req(self, data):
        self.term, self.size, modes = parseRequest_pty_req(data)
        return True

    def request_shell(self, data):
        d = cc.connectTCP("localhost", 9000)
        @d.addCallback
        def cb(protocol):
            protocol.client = self
        @d.addErrback
        def eb(failure):
            log.err(failure)
            self.closed()

        return True

    def closed(self):
        self.loseConnection()
        self.proxy.transport.loseConnection()

class SocatChannel(ChannelBase):

    def openFailed(self, reason):
        print 'echo failed', reason

    def channelOpen(self, ignoredData):
        req = packRequest_pty_req(self.conn.client.term,
                                  self.conn.client.size, "")
        self.conn.sendRequest(self, "pty-req", req)

        d = self.conn.sendRequest(self, 'exec', NS(" ".join(command)),
                                  wantReply=1)
        @d.addCallback
        def cb(chaff):
            other = self.conn.client.proxy
            self.proxy.setPeer(other)
            other.setPeer(self.proxy)

    def closed(self):
        self.loseConnection()
        self.proxy.transport.loseConnection()
        self.conn.client.loseConnection()

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
        return succeed(Key.fromFile(key_path))

class SocatConnection(SSHConnection):

    def __init__(self, client):
        SSHConnection.__init__(self)
        self.client = client

    def serviceStarted(self):
        self.channel = SocatChannel(conn=self)
        self.openChannel(self.channel)

class CommandTransport(SSHClientTransport):
    """
    A protocol which will connect to a target SSH server and execute a given
    command only.
    """

    def __init__(self, command):
        self.command = command

    def verifyHostKey(self, hostKey, fingerprint):
        print 'host key fingerprint: %s' % fingerprint
        return succeed(1)

    def connectionSecure(self):
        self.conn = SocatConnection(self.client)
        self.requestService(KeyOnlyAuth(USER, self.conn))

from twisted.internet.protocol import Factory
from twisted.conch.telnet import (TelnetTransport,
                                  AuthenticatingTelnetProtocol,
                                  TelnetProtocol)

class TelnetProxy(TelnetProtocol):

    term = "xterm"
    size = (24, 80, 0, 0)

    def __init__(self):
        self.proxy = Proxy()

    def connectionMade(self):
        self.proxy.transport = self.transport

        d = cc.connectTCP("localhost", 9000)
        @d.addCallback
        def cb(protocol):
            protocol.client = self
        @d.addErrback
        def eb(failure):
            log.err(failure)
            self.transport.loseConnection()

    def dataReceived(self, data):
        self.proxy.dataReceived(data)

    def loseConnection(self):
        self.transport.loseConnection()

class TelnetFactory(Factory):

    protocol = lambda none: TelnetTransport(AuthenticatingTelnetProtocol, portal)

class Realm(object):
    implements(IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        if IConchUser in interfaces:
            user = ConchUser()
            user.channelLookup["session"] = Session
            return IConchUser, user, lambda: None

        if ITelnetProtocol in interfaces:
            return ITelnetProtocol, TelnetProxy(), lambda: None

        return None

portal = Portal(Realm())
portal.registerChecker(checker)

command = ['/usr/bin/socat', 'STDIO,raw,echo=0,escape=0x1d',
           'UNIX-CONNECT:/var/run/ganeti/kvm-hypervisor/ctrl/instance1.example.org.serial']

cc = ClientCreator(reactor, CommandTransport, command)

private = Key.fromFile("keys/id_rsa_vncap")
public = Key.fromFile("keys/id_rsa_vncap.pub")

factory = SSHFactory()

factory.privateKeys = {"ssh-rsa": private}
factory.publicKeys = {"ssh-rsa": public}

factory.portal = portal

reactor.listenTCP(2022, factory)
reactor.listenTCP(2023, TelnetFactory())
reactor.run()
