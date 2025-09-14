import re
import struct
from enum import IntEnum
from socket import inet_aton, inet_ntoa
from typing import Any, Callable, List, Optional, Tuple

from ltprotocol.ltprotocol import (
    LTMessage,
    LTProtocol,
    LTTwistedProtocol,
    LTTwistedServer,
)


class VNSConstants:
    """Constants used throughout the VNS protocol."""
    
    DEFAULT_PORT = 3250
    ID_SIZE = 32
    MAC_ADDRESS_SIZE = 6
    IP_ADDRESS_SIZE = 4
    BANNER_MESSAGE_MAX_SIZE = 255


class VNSMessageType(IntEnum):
    """VNS message type identifiers."""
    
    OPEN = 1
    CLOSE = 2
    PACKET = 4
    BANNER = 8
    HARDWARE_INFO = 16
    RTABLE = 32
    OPEN_TEMPLATE = 64
    AUTH_REQUEST = 128
    AUTH_REPLY = 256
    AUTH_STATUS = 512


class VNSHardwareType(IntEnum):
    """Hardware interface type constants."""
    
    INTERFACE = 1
    SPEED = 2
    SUBNET = 4
    ETHER = 32
    ETH_IP = 64
    MASK = 128


class VNSProtocolException(Exception):
    """Exception raised for errors in the VNS protocol."""
    
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message
    
    def __str__(self) -> str:
        return self.message


class NetworkAddressValidator:
    """Utility class for network address validation and conversion."""
    
    _NULL_CHAR_PATTERN = re.compile(r"\x00*")
    
    @staticmethod
    def pack_mac_address(mac_address: str) -> bytes:
        """Convert a MAC address string to bytes."""
        octets = mac_address.split(":")
        return bytes(int(octet, 16) for octet in octets)
    
    @staticmethod
    def pack_ip_address(ip_address: str) -> bytes:
        """Convert an IP address string to bytes."""
        octets = ip_address.split(".")
        return bytes(int(octet) for octet in octets)
    
    @staticmethod
    def strip_null_characters_from_bytes(data: bytes) -> str:
        """Remove null characters from bytes and convert to string."""
        decoded = data.decode("utf-8", errors="ignore")
        return NetworkAddressValidator._NULL_CHAR_PATTERN.sub("", decoded)


class VNSOpen(LTMessage):
    """VNS message to open a connection to a virtual topology."""
    
    _FORMAT = f"> HH {VNSConstants.ID_SIZE}s {VNSConstants.ID_SIZE}s {VNSConstants.ID_SIZE}s"
    _SIZE = struct.calcsize(_FORMAT)
    
    def __init__(self, topology_id: int, virtual_host_id: str, user_id: str, password: str) -> None:
        super().__init__()
        self.topology_id = topology_id
        self.virtual_host_id = virtual_host_id
        self.user_id = user_id
        self.password = password
    
    @staticmethod
    def get_type() -> int:
        return VNSMessageType.OPEN
    
    def length(self) -> int:
        return self._SIZE
    
    def pack(self) -> bytes:
        return struct.pack(
            self._FORMAT,
            self.topology_id,
            0,  # padding
            self.virtual_host_id.encode("utf-8"),
            self.user_id.encode("utf-8"),
            self.password.encode("utf-8"),
        )
    
    @staticmethod
    def unpack(body: bytes) -> "VNSOpen":
        unpacked = struct.unpack(VNSOpen._FORMAT, body)
        # unpacked[1] is padding, ignored
        virtual_host_id = NetworkAddressValidator.strip_null_characters_from_bytes(unpacked[2])
        user_id = NetworkAddressValidator.strip_null_characters_from_bytes(unpacked[3])
        password = NetworkAddressValidator.strip_null_characters_from_bytes(unpacked[4])
        return VNSOpen(unpacked[0], virtual_host_id, user_id, password)
    
    def __str__(self) -> str:
        return f"OPEN: topo_id={self.topology_id} host={self.virtual_host_id} user={self.user_id}"


class VNSClose(LTMessage):
    """VNS message to close a connection."""
    
    _FORMAT = "> 256s"
    _SIZE = struct.calcsize(_FORMAT)
    
    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message
    
    @staticmethod
    def get_type() -> int:
        return VNSMessageType.CLOSE
    
    def length(self) -> int:
        return self._SIZE
    
    def pack(self) -> bytes:
        return struct.pack(self._FORMAT, self.message.encode("utf-8"))
    
    @staticmethod
    def unpack(body: bytes) -> "VNSClose":
        unpacked = struct.unpack(VNSClose._FORMAT, body)
        message = NetworkAddressValidator.strip_null_characters_from_bytes(unpacked[0])
        return VNSClose(message)
    
    @staticmethod
    def get_banners_and_close(message: str) -> List["VNSBanner | VNSClose"]:
        """Split message into VNSBanner messages with a VNSClose at the end."""
        messages = []
        chunk_size = VNSConstants.BANNER_MESSAGE_MAX_SIZE
        num_chunks = len(message) // chunk_size + 1
        
        for i in range(num_chunks):
            start_idx = i * chunk_size
            end_idx = (i + 1) * chunk_size
            chunk = message[start_idx:end_idx]
            
            if i + 1 < num_chunks:
                messages.append(VNSBanner(chunk))
            else:
                messages.append(VNSClose(chunk))
        
        return messages
    
    def __str__(self) -> str:
        return f"CLOSE: {self.message}"


class VNSPacket(LTMessage):
    """VNS message containing an Ethernet frame to be sent or received."""
    
    _HEADER_FORMAT = "> 16s"
    _HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)
    
    def __init__(self, interface_name: str, ethernet_frame: bytes) -> None:
        super().__init__()
        self.interface_name = interface_name
        self.ethernet_frame = ethernet_frame
    
    @staticmethod
    def get_type() -> int:
        return VNSMessageType.PACKET
    
    def length(self) -> int:
        return self._HEADER_SIZE + len(self.ethernet_frame)
    
    def pack(self) -> bytes:
        header = struct.pack(self._HEADER_FORMAT, self.interface_name.encode("utf-8"))
        return header + self.ethernet_frame
    
    @staticmethod
    def unpack(body: bytes) -> "VNSPacket":
        header_data = struct.unpack(VNSPacket._HEADER_FORMAT, body[:VNSPacket._HEADER_SIZE])
        interface_name = NetworkAddressValidator.strip_null_characters_from_bytes(header_data[0])
        ethernet_frame = body[VNSPacket._HEADER_SIZE:]
        return VNSPacket(interface_name, ethernet_frame)
    
    def __str__(self) -> str:
        return f"PACKET: {len(self.ethernet_frame)}B on {self.interface_name}"


class VNSInterface:
    """Represents a virtual network interface in the VNS system."""
    
    _FORMAT = "> I32s II28s I32s I4s28s II28s I4s28s"
    _SIZE = struct.calcsize(_FORMAT)
    
    def __init__(self, name: str, mac_address: str, ip_address: str, subnet_mask: str) -> None:
        self.name_bytes = name.encode("utf-8")
        self.mac_address_bytes = NetworkAddressValidator.pack_mac_address(mac_address)
        self.ip_address_bytes = NetworkAddressValidator.pack_ip_address(ip_address)
        self.subnet_mask_bytes = NetworkAddressValidator.pack_ip_address(subnet_mask)
        
        # Store original strings for display
        self.name = name
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.subnet_mask = subnet_mask
        
        # Basic validation for protocol requirements
        if len(self.mac_address_bytes) != VNSConstants.MAC_ADDRESS_SIZE:
            raise VNSProtocolException("MAC address must be 6B")
        if len(self.ip_address_bytes) != VNSConstants.IP_ADDRESS_SIZE:
            raise VNSProtocolException("IP address must be 4B")
        if len(self.subnet_mask_bytes) != VNSConstants.IP_ADDRESS_SIZE:
            raise VNSProtocolException("Subnet mask must be 4B")
    
    def pack(self) -> bytes:
        """Pack interface data into binary format for transmission."""
        return struct.pack(
            self._FORMAT,
            VNSHardwareType.INTERFACE,
            self.name_bytes,
            VNSHardwareType.SPEED,
            0,
            b"",
            VNSHardwareType.ETHER,
            self.mac_address_bytes,
            VNSHardwareType.ETH_IP,
            self.ip_address_bytes,
            b"",
            VNSHardwareType.SUBNET,
            0,
            b"",
            VNSHardwareType.MASK,
            self.subnet_mask_bytes,
            b"",
        )
    
    def __str__(self) -> str:
        return f"{self.name}: mac={self.mac_address} ip={self.ip_address} mask={self.subnet_mask}"


class VNSBanner(LTMessage):
    """VNS message to display banner text to the client."""
    
    _FORMAT = "> 256s"
    _SIZE = struct.calcsize(_FORMAT)
    
    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message
    
    @staticmethod
    def get_type() -> int:
        return VNSMessageType.BANNER
    
    def length(self) -> int:
        return self._SIZE
    
    def pack(self) -> bytes:
        return struct.pack(self._FORMAT, self.message.encode("utf-8"))
    
    @staticmethod
    def unpack(body: bytes) -> "VNSBanner":
        unpacked = struct.unpack(VNSBanner._FORMAT, body)
        message = NetworkAddressValidator.strip_null_characters_from_bytes(unpacked[0])
        return VNSBanner(message)
    
    @staticmethod
    def get_banners(message: str) -> List["VNSBanner"]:
        """Split message into the minimum number of VNSBanner messages."""
        banners = []
        chunk_size = VNSConstants.BANNER_MESSAGE_MAX_SIZE
        num_chunks = len(message) // chunk_size + 1
        
        for i in range(num_chunks):
            start_idx = i * chunk_size
            end_idx = (i + 1) * chunk_size
            chunk = message[start_idx:end_idx]
            banners.append(VNSBanner(chunk))
        
        return banners
    
    def __str__(self) -> str:
        return f"BANNER: {self.message}"


class VNSHardwareInfo(LTMessage):
    """VNS message containing hardware interface information."""
    
    def __init__(self, interfaces: List[VNSInterface]) -> None:
        super().__init__()
        self.interfaces = interfaces
    
    @staticmethod
    def get_type() -> int:
        return VNSMessageType.HARDWARE_INFO
    
    def length(self) -> int:
        return len(self.interfaces) * VNSInterface._SIZE
    
    def pack(self) -> bytes:
        return b"".join(interface.pack() for interface in self.interfaces)
    
    def __str__(self) -> str:
        interface_strings = [str(interface) for interface in self.interfaces]
        return "Hardware Info: " + " || ".join(interface_strings)


class VNSRtable(LTMessage):
    """VNS message containing routing table information."""
    
    _HEADER_FORMAT = f"> {VNSConstants.ID_SIZE}s"
    _HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)
    
    def __init__(self, virtual_host_id: str, routing_table: bytes) -> None:
        super().__init__()
        self.virtual_host_id = virtual_host_id
        self.routing_table = routing_table
    
    @staticmethod
    def get_type() -> int:
        return VNSMessageType.RTABLE
    
    def length(self) -> int:
        return self._HEADER_SIZE + len(self.routing_table)
    
    def pack(self) -> bytes:
        header = struct.pack(self._HEADER_FORMAT, self.virtual_host_id.encode("utf-8"))
        return header + self.routing_table
    
    @staticmethod
    def unpack(body: bytes) -> "VNSRtable":
        virtual_host_id = NetworkAddressValidator.strip_null_characters_from_bytes(
            body[:VNSConstants.ID_SIZE]
        )
        routing_table = body[VNSConstants.ID_SIZE:]
        return VNSRtable(virtual_host_id, routing_table)
    
    def __str__(self) -> str:
        routing_table_str = self.routing_table.decode("utf-8", errors="ignore")
        return f"RTABLE: node={self.virtual_host_id}:\n{routing_table_str}"


class VNSOpenTemplate(LTMessage):
    """VNS message to open a connection using a template."""
    
    _HEADER_FORMAT = f"> 30s {VNSConstants.ID_SIZE}s"
    _HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)
    _DEFAULT_SOURCE_FILTERS = [("0.0.0.0", 0)]
    
    def __init__(
        self,
        template_name: str,
        virtual_host_id: str,
        source_filters: Optional[List[Tuple[str, int]]] = None,
    ) -> None:
        super().__init__()
        self.template_name = template_name
        self.virtual_host_id = virtual_host_id
        self.source_filters = source_filters or self._DEFAULT_SOURCE_FILTERS
    
    @staticmethod
    def get_type() -> int:
        return VNSMessageType.OPEN_TEMPLATE
    
    def length(self) -> int:
        return self._HEADER_SIZE + 5 * len(self.source_filters)
    
    def get_source_filters(self) -> List[Tuple[str, int]]:
        """Get source filters."""
        return self.source_filters.copy()
    
    def pack(self) -> bytes:
        header = struct.pack(
            self._HEADER_FORMAT,
            self.template_name.encode("utf-8"),
            self.virtual_host_id.encode("utf-8"),
        )
        
        filter_data = b"".join(
            inet_aton(ip) + struct.pack(">B", mask)
            for ip, mask in self.source_filters
        )
        
        return header + filter_data
    
    @staticmethod
    def unpack(body: bytes) -> "VNSOpenTemplate":
        header_data = struct.unpack(
            VNSOpenTemplate._HEADER_FORMAT, body[:VNSOpenTemplate._HEADER_SIZE]
        )
        template_name = NetworkAddressValidator.strip_null_characters_from_bytes(header_data[0])
        virtual_host_id = NetworkAddressValidator.strip_null_characters_from_bytes(header_data[1])
        
        source_filters = []
        filter_bytes = body[VNSOpenTemplate._HEADER_SIZE:]
        
        for i in range(len(filter_bytes) // 5):
            start_idx = i * 5
            ip_bytes = filter_bytes[start_idx:start_idx + 4]
            mask_bytes = filter_bytes[start_idx + 4:start_idx + 5]
            
            ip = inet_ntoa(ip_bytes)
            mask = struct.unpack(">B", mask_bytes)[0]
            
            if not (0 <= mask <= 32):
                raise VNSProtocolException(f"Mask must be between 0 and 32, got {mask}")
            
            source_filters.append((ip, mask))
        
        return VNSOpenTemplate(template_name, virtual_host_id, source_filters)
    
    def __str__(self) -> str:
        filter_strings = [f"{ip}/{mask}" for ip, mask in self.source_filters]
        filters_str = ",".join(filter_strings)
        return (
            f"OPEN_TEMPLATE: {self.template_name} for node={self.virtual_host_id} "
            f"with filters={filters_str}"
        )


class VNSAuthRequest(LTMessage):
    """VNS message to request authentication."""
    
    def __init__(self, salt: bytes) -> None:
        super().__init__()
        self.salt = salt
    
    @staticmethod
    def get_type() -> int:
        return VNSMessageType.AUTH_REQUEST
    
    def length(self) -> int:
        return len(self.salt)
    
    def pack(self) -> bytes:
        return self.salt
    
    @staticmethod
    def unpack(body: bytes) -> "VNSAuthRequest":
        return VNSAuthRequest(body)
    
    def __str__(self) -> str:
        return f"AUTH_REQUEST: salt length={len(self.salt)}B"


class VNSAuthReply(LTMessage):
    """VNS message containing authentication reply."""
    
    def __init__(self, username: bytes, salted_password_hash: bytes) -> None:
        super().__init__()
        self.username = username
        self.salted_password_hash = salted_password_hash
    
    @staticmethod
    def get_type() -> int:
        return VNSMessageType.AUTH_REPLY
    
    def length(self) -> int:
        return len(self.username) + len(self.salted_password_hash) + 4  # +4 for username length
    
    def pack(self) -> bytes:
        return (
            struct.pack(">I", len(self.username))
            + self.username
            + self.salted_password_hash
        )
    
    @staticmethod
    def unpack(body: bytes) -> "VNSAuthReply":
        username_length = struct.unpack(">I", body[:4])[0]
        username = body[4:4 + username_length]
        salted_password_hash = body[4 + username_length:]
        return VNSAuthReply(username, salted_password_hash)
    
    def __str__(self) -> str:
        username_str = self.username.decode("utf-8", errors="ignore")
        return f"AUTH_REPLY: username={username_str}"


class VNSAuthStatus(LTMessage):
    """VNS message containing authentication status."""
    
    def __init__(self, authentication_successful: bool, message: str) -> None:
        super().__init__()
        self.authentication_successful = authentication_successful
        self.message = message.encode("utf-8", errors="ignore")
    
    @staticmethod
    def get_type() -> int:
        return VNSMessageType.AUTH_STATUS
    
    def length(self) -> int:
        return 1 + len(self.message)
    
    def pack(self) -> bytes:
        return struct.pack(">B", self.authentication_successful) + self.message
    
    @staticmethod
    def unpack(body: bytes) -> "VNSAuthStatus":
        authentication_successful = bool(struct.unpack(">B", body[:1])[0])
        message = body[1:]
        return VNSAuthStatus(authentication_successful, message)
    
    def __str__(self) -> str:
        message_str = self.message.decode("utf-8", errors="ignore")
        return f"AUTH_STATUS: auth_ok={self.authentication_successful} msg={message_str}"


class VNSProtocolManager:
    """Manages VNS protocol configuration and message types."""
    
    def __init__(self) -> None:
        self._message_types = [
            VNSOpen,
            VNSClose,
            VNSPacket,
            VNSBanner,
            VNSHardwareInfo,
            VNSRtable,
            VNSOpenTemplate,
            VNSAuthRequest,
            VNSAuthReply,
            VNSAuthStatus,
        ]
        self._protocol = LTProtocol(self._message_types, "I", "I")
    
    @property
    def protocol(self) -> LTProtocol:
        """Get the configured LT protocol instance."""
        return self._protocol
    
    @property
    def message_types(self) -> List[type]:
        """Get the list of supported message types."""
        return self._message_types.copy()


# Global protocol instance for backward compatibility
_protocol_manager = VNSProtocolManager()
VNS_PROTOCOL = _protocol_manager.protocol
VNS_MESSAGES = _protocol_manager.message_types


def create_vns_server(
    port: int,
    receive_callback: Callable[[LTTwistedProtocol, Any], None],
    new_connection_callback: Callable[[LTTwistedProtocol], None],
    lost_connection_callback: Callable[[LTTwistedProtocol], None],
    verbose: bool = True,
) -> LTTwistedServer:
    """Create a VNS server that listens for clients on the specified port."""
    server = LTTwistedServer(
        VNS_PROTOCOL,
        receive_callback,
        new_connection_callback,
        lost_connection_callback,
        verbose,
    )
    server.listen(port)
    return server
