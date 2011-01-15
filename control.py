from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import LineReceiver
from twisted.python import log

from factory import VNCProxy

class ControlProtocol(LineReceiver):

    def lineReceived(self, line):
        try:
            sport, host, dport, password = line.split(":", 3)
            sport = int(sport)
            dport = int(dport)
            factory = VNCProxy(host, dport, password)
            reactor.listenTCP(sport, factory)
            log.msg("New forwarder (%d->%s:%d)" % (sport, host, dport))
            self.sendLine("OK")
        except ValueError:
            log.err("Couldn't handle line %r" % line)
            self.sendLine("FAILED")
        except CannotListenError:
            log.err("Couldn't bind port %d" % sport)
            self.sendLine("FAILED")

        self.transport.loseConnection()

class ControlFactory(ServerFactory):
    protocol = ControlProtocol
