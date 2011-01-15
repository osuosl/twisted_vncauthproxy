from twisted.application.internet import UNIXServer
from twisted.application.service import Application

from control import ControlFactory

application = Application("vncauthproxy")
server = UNIXServer("/tmp/vncproxy.sock", ControlFactory())
server.setServiceParent(application)
