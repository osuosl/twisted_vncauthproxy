from twisted.application.internet import TCPServer, UNIXServer
from twisted.application.service import Application

from vncap.control import ControlFactory

application = Application("vncauthproxy")
cf = ControlFactory()
server = TCPServer(8888, cf)
server.setServiceParent(application)
server = UNIXServer("/tmp/vncproxy.sock", cf)
server.setServiceParent(application)
