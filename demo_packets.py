"""Build a few synthetic datagrams for learning. Nothing is sent on the network."""

from datetime import datetime, timedelta
import socket
import struct


def internet_checksum(data):
    """One's-complement checksum, used only to make realistic demo headers."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_packet(protocol, source, destination, source_port, destination_port,
                payload=b"", flags=0x18, sequence=105482, acknowledgment=208713,
                ip_options=b"", tcp_options=b""):
    """Construct bytes with struct.pack; the analyzer independently unpacks them."""
    if len(ip_options) % 4 or len(tcp_options) % 4:
        raise ValueError("Options must contain a multiple of four bytes.")
    source_bytes = socket.inet_aton(source)
    destination_bytes = socket.inet_aton(destination)
    if protocol == 6:
        tcp_words = (20 + len(tcp_options)) // 4
        segment = struct.pack("!HHIIBBHHH", source_port, destination_port,
                              sequence, acknowledgment, tcp_words << 4, flags,
                              65535, 0, 0) + tcp_options + payload
        checksum_offset = 16
    elif protocol == 17:
        segment = struct.pack("!HHHH", source_port, destination_port,
                              8 + len(payload), 0) + payload
        checksum_offset = 6
    else:
        raise ValueError("Demo builder supports TCP (6) and UDP (17).")
    pseudo_header = struct.pack("!4s4sBBH", source_bytes, destination_bytes,
                                0, protocol, len(segment))
    checksum = internet_checksum(pseudo_header + segment)
    if protocol == 17 and checksum == 0:
        checksum = 0xFFFF
    segment = (segment[:checksum_offset] + struct.pack("!H", checksum)
               + segment[checksum_offset + 2:])

    ip_words = (20 + len(ip_options)) // 4
    header = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ip_words, 0,
                         ip_words * 4 + len(segment), 1234, 0x4000,
                         64, protocol, 0, source_bytes, destination_bytes) + ip_options
    header = header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:]
    return header + segment


def demo_packets():
    samples = [
        make_packet(6, "192.168.1.10", "192.168.1.20", 49152, 8080, b"HELLO SERVER"),
        make_packet(6, "192.168.1.20", "192.168.1.10", 8080, 49152, b"HELLO CLIENT"),
        make_packet(17, "192.168.1.10", "192.168.1.20", 53000, 9999, b"Hello over UDP!"),
        make_packet(17, "192.168.1.20", "192.168.1.10", 9999, 53000, b"UDP reply"),
        make_packet(6, "192.168.1.10", "192.168.1.20", 49152, 8080, flags=0x10),
        make_packet(6, "192.168.1.10", "192.168.1.20", 49153, 443, flags=0x02,
                    acknowledgment=0, ip_options=b"\x01\x01\x00\x00",
                    tcp_options=b"\x02\x04\x05\xb4"),
        make_packet(17, "192.168.1.10", "192.168.1.20", 53001, 9999, b"\x00\x01\x1b\xffABC"),
    ]
    start = datetime.now().astimezone()
    return [(start + timedelta(milliseconds=i * 100), raw) for i, raw in enumerate(samples)]
