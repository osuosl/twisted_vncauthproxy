from json import loads

from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import LineReceiver
from twisted.python import log

from vncap.factory import VNCProxy
from vncap.site import VNCSite

class ControlProtocol(LineReceiver):

    def lineReceived(self, line):
        log.msg("Received line %s" % line)
        try:
            d = loads(line)
            sport = d["sport"]
            host = d["daddr"]
            dport = d["dport"]
            password = d["password"]
            if not sport:
                sport = self.factory.assign_port()

            #factory = VNCProxy(host, dport, password)
            factory = VNCSite(host, dport, password)
            listening = reactor.listenTCP(sport, factory)

            # Set up our timeout.
            def timeout():
                log.msg("Timed out connection on port %d" % sport)
                listening.stopListening()
            reactor.callLater(30, timeout)

            log.msg("New forwarder (%d->%s:%d)" % (sport, host, dport))
            self.sendLine("%d" % sport)
        except (KeyError, ValueError):
            log.err("Couldn't handle line %s" % line)
            self.sendLine("FAILED")
        except CannotListenError:
            log.err("Couldn't bind port %d" % sport)
            self.sendLine("FAILED")

        self.transport.loseConnection()

class ControlFactory(ServerFactory):
    protocol = ControlProtocol

    def __init__(self):
        self.pool = set()
        self.pool_counter = 12000

    def assign_port(self):
        # XXX hax
        self.pool_counter += 1
        return self.pool_counter
