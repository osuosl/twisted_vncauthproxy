from twisted.internet.defer import gatherResults
from twisted.python import log


def start_proxying(results):
    """
    Callback to start proxies.
    """

    log.msg("Starting proxy")
    client, server = results

    # Rewrite the dataReceived and connectionLost hooks to correctly handle
    # their peers.
    def cb(peer):
        if peer.transport:
            peer.transport.loseConnection()

    server.dataReceived = client.transport.write
    server.connectionLost = lambda reason=None: cb(client)
    client.dataReceived = server.transport.write
    client.connectionLost = lambda reason=None: cb(server)

    # Replay last bits of stuff in the pipe, if there's anything left.
    data = server._sful_data[1].read()
    if data:
        client.transport.write(data)
    data = client._sful_data[1].read()
    if data:
        server.transport.write(data)

    server.transport.resumeProducing()
    client.transport.resumeProducing()
    log.msg("Proxying started!")


def prepare_proxy(client, server):
    """
    Set up the deferred proxy callback.
    """

    log.msg("Preparing proxies for client %s and server %s"
        % (client, server))
    d = gatherResults([client.authentication_d, server.authentication_d])
    d.addCallback(start_proxying)

    @d.addErrback
    def cancel_proxy(failure):
        log.msg("Things went wrong, cancelling proxy")
        client.transport.loseConnection()
        server.transport.loseConnection()
