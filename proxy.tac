from twisted.application.strports import service
from twisted.application.service import Application

from vncap.control import ControlFactory

application = Application("vncauthproxy")
cf = ControlFactory()
# Bind to port 8888 on the local loopback.
server = service("tcp:8888:interface=localhost", cf)
server.setServiceParent(application)
# These lines enable a local UNIX socket.
# This configuration isn't supported by ganeti-webmgr.
# server = service("unix:/tmp/vncproxy.sock", cf)
# server.setServiceParent(application)
