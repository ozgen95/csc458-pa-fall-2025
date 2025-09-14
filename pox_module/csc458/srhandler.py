from typing import Any, Dict, List, Optional, Tuple

from ltprotocol.ltprotocol import LTTwistedProtocol, LTMessage

from pox.core import core
from pox.lib.revent import Event, EventMixin

import threading
import os

from twisted.internet import reactor
from csc458.vns_protocol import (
    create_vns_server,
    VNSOpen,
    VNSClose,
    VNSPacket,
    VNSOpenTemplate,
    VNSAuthRequest,
    VNSAuthReply,
    VNSAuthStatus,
    VNSInterface,
    VNSHardwareInfo,
)

log = core.getLogger()


class SRServerListener(EventMixin):
    """TCP Server to handle connections to Software Router."""

    interfaces: List[VNSInterface]

    def __init__(self, address: Tuple[str, int] = ("127.0.0.1", 8888)) -> None:
        """
        Initialize the SR server listener.

        Args:
            address: Tuple of (host, port) to listen on
        """
        port = address[1]
        self.listenTo(core.csc458_ofhandler)
        self.srclients = []
        self.listen_port = port
        self.intfname_to_port: Dict[str, int] = {}
        self.port_to_intfname: Dict[int, str] = {}

        # Create VNS server
        self.server = create_vns_server(
            port,
            self._handle_recv_msg,
            self._handle_new_client,
            self._handle_client_disconnected,
        )
        log.info("created server")

    def broadcast(self, message: LTMessage) -> None:
        """
        Broadcast a message to all connected clients.

        Args:
            message: The message to broadcast
        """
        log.debug("Broadcasting message: %s", message)
        for client in self.srclients:
            client.send(message)

    def _handle_SRPacketIn(self, event: Any) -> None:
        """
        Handle SRPacketIn events from the openflow handler.

        Args:
            event: The SRPacketIn event
        """
        try:
            intfname = self.port_to_intfname[event.port]
        except KeyError:
            log.debug("Couldn't find interface for port number %s", event.port)
            return

        log.debug(
            "Forwarding packet from port %d to interface %s", event.port, intfname
        )
        self.broadcast(VNSPacket(intfname, event.pkt))

    def _handle_RouterInfo(self, event: Any) -> None:
        """
        Handle RouterInfo events to populate interface information.

        Args:
            event: The RouterInfo event containing interface details
        """
        log.info("Received RouterInfo event, populating interfaces...")

        interfaces = []
        for intf in event.info.keys():
            ip, mac, rate, port = event.info[intf]
            log.info(
                "Adding interface: %s (IP: %s, MAC: %s, Port: %s)", intf, ip, mac, port
            )

            interfaces.append(VNSInterface(intf, mac, ip, "255.255.255.255"))
            # Mapping between of-port and intf-name
            self.intfname_to_port[intf] = port
            self.port_to_intfname[port] = intf

        # Store the list of interfaces
        self.interfaces = interfaces
        log.info("Interfaces populated successfully")

    def _handle_recv_msg(
        self, conn: LTTwistedProtocol, vns_msg: Optional[LTMessage]
    ) -> None:
        """
        Handle incoming messages from the SR client.

        Args:
            conn: The connection that received the message
            vns_msg: The message received
        """
        if vns_msg is None:
            log.warning("Received invalid message, closing connection")
            self._handle_close_msg(conn)
            return

        log.debug("Received VNS message: %s", vns_msg)

        # Process message based on type
        if vns_msg.get_type() == VNSAuthReply.get_type():
            log.debug("Handling auth reply")
            self._handle_auth_reply(conn)
        elif vns_msg.get_type() == VNSOpen.get_type():
            log.debug("Handling open message")
            self._handle_open_msg(conn, vns_msg)
        elif vns_msg.get_type() == VNSClose.get_type():
            log.debug("Handling close message")
            self._handle_close_msg(conn)
        elif vns_msg.get_type() == VNSPacket.get_type():
            log.debug("Handling packet message")
            self._handle_packet_msg(conn, vns_msg)
        elif vns_msg.get_type() == VNSOpenTemplate.get_type():
            log.debug("Handling open template message")
            self._handle_open_template_msg(conn, vns_msg)
        else:
            log.warning("Unexpected VNS message received: %s", vns_msg)

    def _handle_auth_reply(self, conn: LTTwistedProtocol) -> None:
        """
        Handle authentication replies - always authenticate successfully.

        Args:
            conn: The connection that sent the auth reply
        """
        msg = f"Authenticated {conn} as user"
        conn.send(VNSAuthStatus(True, msg))
        log.debug("Authentication successful for %s", conn)

    def _handle_new_client(self, conn: LTTwistedProtocol) -> None:
        """
        Handle new client connections.

        Args:
            conn: The new connection
        """
        client_addr = conn.transport.getPeer().host
        log.info("Accepted client connection from %s", client_addr)
        self.srclients.append(conn)

        # Send auth request to drive the sr-client state machine
        salt = os.urandom(20)
        conn.send(VNSAuthRequest(salt))

    def _handle_client_disconnected(self, conn: LTTwistedProtocol) -> None:
        """
        Handle client disconnection.

        Args:
            conn: The connection that was disconnected
        """
        log.info("Client disconnected")
        conn.transport.loseConnection()
        if conn in self.srclients:
            self.srclients.remove(conn)

    def _handle_open_msg(self, conn: LTTwistedProtocol, vns_msg: VNSOpen) -> None:
        """
        Handle open messages from clients.

        Args:
            conn: The connection that sent the message
            vns_msg: The open message
        """
        log.debug("open-msg: %s, %s" % (vns_msg.topology_id, vns_msg.virtual_host_id))
        try:
            conn.send(VNSHardwareInfo(self.interfaces))
        except:
            log.debug("interfaces not populated yet")

    def _handle_close_msg(self, conn: LTTwistedProtocol) -> None:
        """
        Handle close messages from clients.

        Args:
            conn: The connection to close
        """
        conn.send("Goodbyte!")  # spelling mistake intended...
        conn.transport.loseConnection()
        if conn in self.srclients:
            self.srclients.remove(conn)

    def _handle_packet_msg(self, conn: LTTwistedProtocol, vns_msg: VNSPacket) -> None:
        """
        Handle packet messages from clients.

        Args:
            conn: The connection that sent the message
            vns_msg: The packet message
        """
        out_intf = vns_msg.interface_name
        pkt = vns_msg.ethernet_frame

        try:
            out_port = self.intfname_to_port[out_intf]
            log.debug(
                "Packet out on interface %s (port %d): %d bytes",
                out_intf,
                out_port,
                len(pkt),
            )
            core.csc458_srhandler.raiseEvent(SRPacketOut(pkt, out_port))
        except KeyError:
            log.warning("packet-out through unknown interface %s", out_intf)

    def _handle_open_template_msg(
        self, conn: LTTwistedProtocol, vns_msg: VNSOpenTemplate
    ) -> None:
        """
        Handle open template messages from clients.

        Args:
            conn: The connection that sent the message
            vns_msg: The open template message
        """
        # This is a placeholder for template handling if needed in the future
        log.debug("Open template message handling not implemented")
        pass


class SRPacketOut(Event):
    """Event raised when sending a packet back from the Software Router."""

    def __init__(self, packet: bytes, port: int) -> None:
        """
        Initialize a packet-out event.

        Args:
            packet: The packet data to send
            port: The port to send it on
        """
        Event.__init__(self)
        self.pkt = packet
        self.port = port


class csc458_srhandler(EventMixin):
    """Main handler for Software Router functionality."""

    _eventMixin_events = set([SRPacketOut])

    def __init__(self) -> None:
        """Initialize the SR handler."""
        EventMixin.__init__(self)
        self.listenTo(core)
        # self.listenTo(core.csc458_ofhandler)

        # Start the server
        self.server = SRServerListener()
        log.info("SRServerListener listening on port %s", self.server.listen_port)

        # Start reactor in a separate thread
        self.server_thread = threading.Thread(
            target=lambda: reactor.run(installSignalHandlers=False)
        )
        self.server_thread.daemon = True
        self.server_thread.start()

    def _handle_GoingDownEvent(self, event) -> None:
        """
        Handle shutdown events.

        Args:
            event: The shutdown event
        """
        log.info("Shutting down SR Server")
        del self.server


def launch(transparent: bool = False) -> None:
    """
    Start the SR handler application.

    Args:
        transparent: Whether to operate in transparent mode
    """
    core.registerNew(csc458_srhandler)
    log.info("SR Handler started")
