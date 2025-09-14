def pack_mac(macaddr: str) -> bytes:
    """
    Convert a MAC address string (format: xx:xx:xx:xx:xx:xx) to bytes.

    Args:
        macaddr: MAC address in string format

    Returns:
        Packed MAC address as bytes
    """
    octets = macaddr.split(":")
    result = bytes()
    for byte in octets:
        result += bytes([int(byte, 16)])
    return result


def pack_ip(ipaddr: str) -> bytes:
    """
    Convert an IP address string (format: x.x.x.x) to bytes.

    Args:
        ipaddr: IP address in string format

    Returns:
        Packed IP address as bytes
    """
    octets = ipaddr.split(".")
    result = bytes()
    for byte in octets:
        result += bytes([int(byte)])
    return result
