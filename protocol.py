from os import urandom

from twisted.internet.protocol import Protocol
from twisted.python import log

from d3des import generate_response
from rfb import check_password

(
    STATE_VERSION,
    STATE_SECURITY_TYPES,
    STATE_AUTHENTICATION,
    STATE_RESULT,
    STATE_CONNECTED
) = range(5)

class VNCAuthenticator(Protocol):
    """
    Base class for VNC protocols.

    This protocol isn't interesting on its own; subclass it to make a server
    or client.
    """

    VERSION = "RFB 003.008\n"

    def __init__(self):
        self.buf = ""

        self.state = STATE_VERSION

    def connectionLost(self):
        log.err("Connection lost...")
        if self.buf:
            log.err("Remaining buffer: %r" % self.buf)

class VNCServerAuthenticator(Protocol):
    """
    Trivial server protocol which can authenticate VNC clients.

    This protocol is lacking lots of things, like support for older VNC
    protocols.
    """

    def pick_security_types(self):
        """
        Choose the security type that the client wants.
        """

        if not self.buf:
            return

        security_type = ord(self.buf[0])

        if security_type == 2:
            self.vnc_authentication_challenge()
            self.handshaker = self.vnc_authentication_result
        elif security_type == 1:
            self.no_authentication_challenge()
            self.handshaker = self.no_authentication_result
        else:
            log.err("Couldn't agree on an authentication scheme!")
            self.transport.loseConnection()

        self.state = STATE_RESULT

    def no_authentication_challenge(self):
        pass

    def no_authentication_result(self):
        # Whew! That was easy!
        return True

    def vnc_authentication_challenge(self):
        self.challenge = urandom(16)
        self.transport.write(self.challenge)

    def vnc_authentication_result(self):
        if len(self.buf) < 16:
            return

        response, self.buf = self.buf[:16], self.buf[16:]

        return check_password(self.challenge, response, self.password)

    def dataReceived(self, data):
        self.buf += data

        if self.state == STATE_VERSION:
            # Waiting for a 12-byte magic number.
            if len(self.buf) < 12:
                return
            version, self.buf = self.buf[:12], self.buf[12:]
            if version == self.VERSION:
                # We support two security types: none, and VNC.
                self.transport.write("\x02\x01\x02")
                self.state = STATE_SECURITY_TYPES
            else:
                log.err("Failed version check: %s" % version)
                self.transport.loseConnection()

        elif self.state == STATE_SECURITY_TYPES:
            self.pick_security_type()

        elif self.state == STATE_RESULT:
            if self.handshaker():
                log.msg("Successfully authenticated!")
                self.transport.write("\x00")
                self.state = STATE_CONNECTED
            else:
                log.err("Couldn't authenticate...")
                self.transport.loseConnection()

    def connectionMade(self):
        self.transport.write(self.VERSION)

class VNCClientAuthenticator(Protocol):
    """
    Trivial client protocol which can authenticate itself to a VNC server.

    This protocol is lacking lots of things, like support for older VNC
    protocols.
    """

    def pick_security_type(self):
        """
        Ascertain whether the server supports any security types we might
        want.
        """

        if not self.buf:
            return

        count = ord(self.buf[0])
        if count == 0:
            log.err("Server wouldn't give us any security types!")
            self.transport.loseConnection()

        if len(self.buf) < count + 1:
            return

        # Pull types out of the buffer, and advance the buffer. (Plus one for
        # the count byte.)
        types, self.buf = self.buf[1:count + 1], self.buf[count + 1:]

        security_types = set(ord(i) for i in types)
        if 2 in security_types:
            log.msg("Choosing VNC authentication...")
            self.transport.write("\x02")
            self.handshaker = self.vnc_authentication
        elif 1 in security_types:
            log.msg("Choosing no authentication...")
            self.transport.write("\x01")
            self.handshaker = self.no_authentication
        else:
            log.err("Couldn't agree on an authentication scheme!")
            self.transport.loseConnection()

        self.state = STATE_AUTHENTICATION

    def no_authentication(self):
        # Whew! That was easy!
        self.state = STATE_RESULT

    def vnc_authentication(self):
        # Take in 16 bytes, encrypt with 3DES using the password as the key,
        # and send the response.
        if len(self.buf) < 16:
            return

        challenge, self.buf = self.buf[:16], self.buf[16:]

        response = generate_response(self.password, challenge)
        self.transport.write(response)

        self.state = STATE_RESULT

    def dataReceived(self, data):
        self.buf += data

        if self.state == STATE_VERSION:
            # Waiting for a 12-byte magic number.
            if len(self.buf) < 12:
                return
            version, self.buf = self.buf[:12], self.buf[12:]
            if version == self.VERSION:
                self.transport.send(self.version)
                self.state = STATE_SECURITY_TYPES
            else:
                log.err("Failed version check: %s" % version)
                self.transport.loseConnection()

        elif self.state == STATE_SECURITY_TYPES:
            self.pick_security_type()

        elif self.state == STATE_AUTHENTICATION:
            self.handshaker()

        elif self.state == STATE_RESULT:
            if not self.buf:
                return

            fail = ord(self.buf.pop(0))
            if not fail:
                log.msg("Successfully connected!")
                self.state = STATE_CONNECTED
            else:
                log.err("Failed authentication.")
                self.transport.loseConnection()
