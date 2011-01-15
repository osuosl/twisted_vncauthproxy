from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import LineReceiver

class ControlProtocol(LineReceiver):

    def lineReceived(self, line):
        try:
            source, host, dest, password = line.split(":", 3)
            self.sendLine("OK")
        except ValueError:
            self.sendLine("FAILED")

        self.transport.loseConnection()

class ControlFactory(ServerFactory):
    protocol = ControlProtocol
