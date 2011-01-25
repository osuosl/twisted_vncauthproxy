from twisted.application.internet import TCPServer
from twisted.application.service import Application
from twisted.internet.protocol import Factory, Protocol

policy = """
<cross-domain-policy>
    <allow-access-from domain="*" to-ports="*" />
</cross-domain-policy>
"""

class PolicyProtocol(Protocol):

    def __init__(self):
        print "Hi mom!"

    def connectionMade(self):
        self.transport.write(policy)
        self.loseConnection()

class PolicyFactory(Factory):
    protocol = PolicyProtocol

application = Application("policy")
TCPServer(843, PolicyFactory()).setServiceParent(application)
