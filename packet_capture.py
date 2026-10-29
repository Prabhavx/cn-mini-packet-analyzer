"""Obtain raw bytes with standard-library sockets. Parsing lives elsewhere."""

from datetime import datetime
import ipaddress
import socket
import struct
import sys
import time


def list_interfaces():
    if sys.platform == "win32":
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_INET
        )})
        print("Local IPv4 candidates (use ipconfig to check the active adapter):")
        for address in addresses:
            print(" ", address)
    elif sys.platform.startswith("linux"):
        print("Interfaces:")
        for _, name in socket.if_nameindex():
            print(" ", name)
    else:
        print("Live capture supports Windows and Linux. Demo mode works anywhere.")


def ethernet_to_ipv4(frame):
    """Remove Ethernet and optional VLAN headers; ignore IPv6, ARP, etc."""
    if len(frame) < 14:
        return None
    offset = 14
    ether_type = struct.unpack("!H", frame[12:14])[0]
    while ether_type in (0x8100, 0x88A8):
        if len(frame) < offset + 4:
            return None
        ether_type = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        offset += 4
    return frame[offset:] if ether_type == 0x0800 else None


def capture_ipv4(interface, count, timeout):
    """Yield (timestamp, IPv4 bytes) until the count or time limit is reached."""
    sniffer = None
    receive_all = False
    try:
        if sys.platform == "win32":
            if not interface:
                raise ValueError("Windows needs --interface YOUR_LOCAL_IPV4. Use --list-interfaces.")
            try:
                address = ipaddress.IPv4Address(interface)
            except ipaddress.AddressValueError:
                raise ValueError("On Windows, --interface must be a local IPv4 address.") from None
            if address.is_unspecified or address.is_multicast or address.is_loopback:
                raise ValueError("Choose the IPv4 address of an active Ethernet or Wi-Fi adapter.")
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((str(address), 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # IP-level capture avoids enabling the NIC's promiscuous mode.
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_IPLEVEL)
            receive_all = True
        elif sys.platform.startswith("linux"):
            # ETH_P_ALL includes incoming AND outgoing frames. We keep IPv4 only.
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            if interface:
                sniffer.bind((interface, 0))
        else:
            raise ValueError("Live capture supports Windows and Linux; use --demo on this OS.")

        deadline = time.monotonic() + timeout
        captured = 0
        while count == 0 or captured < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sniffer.settimeout(min(0.5, remaining))
            try:
                frame, _ = sniffer.recvfrom(65535 + 256)
            except socket.timeout:
                continue
            timestamp = datetime.now().astimezone()
            raw = frame if sys.platform == "win32" else ethernet_to_ipv4(frame)
            if raw is None:
                continue
            captured += 1
            yield timestamp, raw
    except PermissionError:
        raise PermissionError(
            "Live capture requires Administrator on Windows or root/CAP_NET_RAW on Linux. "
            "Use --demo without elevated permissions."
        ) from None
    finally:
        if sniffer is not None:
            if receive_all:
                try:
                    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except OSError:
                    pass  # Still close the socket if the adapter has disappeared.
            sniffer.close()
