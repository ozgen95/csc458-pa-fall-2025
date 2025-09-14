# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
This is an L2 learning switch written directly against the OpenFlow library.
It is derived from one written live for an SDN crash course.
"""

from typing import Dict, Tuple, List

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import Event, EventMixin
from pox.lib.util import str_to_bool

import os
import sys

# Configure logging
log = core.getLogger()

# Constants
IPCONFIG_FILE = "./IP_CONFIG"
IP_SETTING: Dict[str, str] = {}
RTABLE: List[Tuple[str, str, str, str]] = []
ROUTER_IP: Dict[str, str] = {}


class RouterInfo(Event):
    """Event raised when information about an OpenFlow router is ready."""

    def __init__(
        self,
        info: Dict[str, Tuple[str, str, str, int]],
        rtable: List[Tuple[str, str, str, str]],
    ):
        """
        Initialize RouterInfo event.

        Args:
            info: Dictionary mapping interface names to (IP, MAC, rate, port_no) tuples
            rtable: Routing table as list of (destination, gateway, mask, interface) tuples
        """
        Event.__init__(self)
        self.info = info
        self.rtable = rtable


class SRPacketIn(Event):
    """Event raised when a packet_in is received from OpenFlow."""

    def __init__(self, packet: bytes, port: int):
        """
        Initialize SRPacketIn event.

        Args:
            packet: Raw packet data
            port: Port number where the packet was received
        """
        Event.__init__(self)
        self.pkt = packet
        self.port = port


class OFHandler(EventMixin):
    """
    OpenFlow handler implementing L2 learning switch capabilities.

    This handler processes OpenFlow messages and forwards packets to the
    SR handler for further processing.
    """

    def __init__(self, connection, transparent: bool):
        """
        Initialize the OpenFlow handler.

        Args:
            connection: The OpenFlow connection to the switch
            transparent: Whether to operate in transparent mode
        """
        # Store switch connection
        self.connection = connection
        self.transparent = transparent
        self.sw_info: Dict[str, Tuple[str, str, str, int]] = {}

        # Configure the connection to send full packets
        self.connection.send(of.ofp_set_config(miss_send_len=65535))

        # Process switch ports to extract interface information
        self._process_switch_ports()

        # Set up the routing table
        self.rtable = RTABLE

        # Listen for OpenFlow messages
        self.listenTo(connection)
        self.listenTo(core.csc458_srhandler)

        # Raise event for other components
        core.csc458_ofhandler.raiseEvent(RouterInfo(self.sw_info, self.rtable))

    def _process_switch_ports(self) -> None:
        """Process switch ports to identify and configure interfaces."""
        for port in self.connection.features.ports:
            intf_name_parts = port.name.split("-")
            if len(intf_name_parts) < 2:
                continue

            intf_name = intf_name_parts[1]

            # If this interface is defined in our config, store its info
            if intf_name in ROUTER_IP:
                self.sw_info[intf_name] = (
                    ROUTER_IP[intf_name],  # IP address
                    port.hw_addr.toStr(),  # MAC address
                    "10Gbps",  # Link speed (hardcoded)
                    port.port_no,  # Port number
                )

    def _handle_PacketIn(self, event) -> None:
        """
        Handle packet-in messages from the switch.

        This method simply forwards packets to the SR handler component.

        Args:
            event: The packet-in event
        """
        # Parse the packet
        packet = event.parse()
        raw_packet = packet.raw

        # Forward packet to SR handler
        core.csc458_ofhandler.raiseEvent(SRPacketIn(raw_packet, event.port))

        # Send packet-out to indicate we've processed it (drops the packet)
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    def _handle_SRPacketOut(self, event) -> None:
        """
        Handle packet-out requests from the SR handler.

        Args:
            event: The packet-out event containing the packet and output port
        """
        # Create packet-out message
        msg = of.ofp_packet_out()
        new_packet = event.pkt

        # Set output action
        msg.actions.append(of.ofp_action_output(port=event.port))

        # Use raw packet data (not from buffer)
        msg.in_port = of.OFPP_NONE
        msg.data = new_packet

        # Send the message
        self.connection.send(msg)


class csc458_ofhandler(EventMixin):
    """
    Main OpenFlow handler that creates OFHandler instances for each switch connection.
    """

    # Define events this component can raise
    _eventMixin_events = {SRPacketIn, RouterInfo}

    def __init__(self, transparent: bool):
        """
        Initialize the OpenFlow handler component.

        Args:
            transparent: Whether to operate in transparent mode
        """
        EventMixin.__init__(self)
        self.listenTo(core.openflow)
        self.transparent = transparent

    def _handle_ConnectionUp(self, event) -> None:
        """
        Handle new switch connections.

        Creates an OFHandler for each new switch that connects.

        Args:
            event: The connection-up event
        """
        log.debug("New connection: %s", event.connection)
        OFHandler(event.connection, self.transparent)


def get_ip_setting() -> int:
    """
    Load IP settings from the IP_CONFIG file.

    Returns:
        0 on success, -1 if file not found
    """
    if not os.path.isfile(IPCONFIG_FILE):
        return -1

    try:
        with open(IPCONFIG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    break

                name, ip = line.split()
                if ip == "<ELASTIC_IP>":
                    log.error(
                        "IP configuration is not set. Please put your Elastic IP addresses into %s",
                        IPCONFIG_FILE,
                    )
                    sys.exit(2)

                IP_SETTING[name] = ip

        # Set up routing table entries
        RTABLE.append(
            (IP_SETTING["client"], IP_SETTING["client"], "255.255.255.255", "eth3")
        )
        RTABLE.append(
            (IP_SETTING["server1"], IP_SETTING["server1"], "255.255.255.255", "eth1")
        )
        RTABLE.append(
            (IP_SETTING["server2"], IP_SETTING["server2"], "255.255.255.255", "eth2")
        )

        # Configure router interface IPs
        ROUTER_IP["eth1"] = IP_SETTING["sw0-eth1"]
        ROUTER_IP["eth2"] = IP_SETTING["sw0-eth2"]
        ROUTER_IP["eth3"] = IP_SETTING["sw0-eth3"]

        return 0
    except Exception as e:
        log.error("Error loading IP configuration: %s", e)
        return -1


def launch(transparent: bool = False) -> None:
    """
    Launch the OpenFlow handler component.

    Args:
        transparent: Whether to operate in transparent mode
    """
    # Register the main component
    core.registerNew(csc458_ofhandler, str_to_bool(transparent))

    # Load IP settings
    result = get_ip_setting()
    if result == -1:
        log.error(
            "Couldn't load config file for IP addresses. Check whether %s exists",
            IPCONFIG_FILE,
        )
        sys.exit(2)
    else:
        log.info("Successfully loaded IP settings for hosts: %s", IP_SETTING)
