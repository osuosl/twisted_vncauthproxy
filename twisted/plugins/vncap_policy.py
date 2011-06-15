from twisted.application.internet import TCPServer
from twisted.application.service import IServiceMaker
from twisted.internet.protocol import Factory, Protocol
from twisted.plugin import IPlugin
from twisted.python.usage import Options
from zope.interface import implements

policy = """
<cross-domain-policy>
    <allow-access-from domain="*" to-ports="*" />
</cross-domain-policy>
"""

class PolicyProtocol(Protocol):

    def connectionMade(self):
        self.transport.write(policy)
        self.transport.loseConnection()

class PolicyFactory(Factory):
    protocol = PolicyProtocol

class PolicyOptions(Options):
    pass

class PolicyServiceMaker(object):

    implements(IPlugin, IServiceMaker)

    tapname = "flashpolicy"
    description = "Permissive Flash policy server"
    options = PolicyOptions

    def makeService(self, options):
        """
        Set up a policy server.
        """

        return TCPServer(843, PolicyFactory())

servicemaker = PolicyServiceMaker()
