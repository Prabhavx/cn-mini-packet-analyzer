"""Read IPv4, TCP and UDP headers directly from bytes (no decoding libraries)."""

from dataclasses import dataclass, field
from datetime import datetime
import socket
import struct


@dataclass
class Packet:
    """One captured IPv4 packet and the fields that we managed to decode."""

    number: int
    timestamp: datetime
    raw: bytes
    ip: dict = field(default_factory=dict)
    transport: dict = field(default_factory=dict)
    payload: bytes = b""
    notes: list = field(default_factory=list)

    @property
    def size(self):
        # Consistently count IPv4 bytes, excluding the Ethernet header.
        return len(self.raw)

    @property
    def protocol(self):
        number = self.ip.get("protocol")
        return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(
            number, "UNKNOWN" if number is None else f"IP/{number}"
        )


def parse_ipv4_header(raw):
    if len(raw) < 20:
        raise ValueError("IPv4 header needs at least 20 bytes.")

    # First byte: high 4 bits = version; low 4 bits = header size in words.
    version = raw[0] >> 4
    header_length = (raw[0] & 0x0F) * 4
    if version != 4:
        raise ValueError(f"Expected IPv4, received version {version}.")
    if header_length < 20 or header_length > len(raw):
        raise ValueError("Invalid or incomplete IPv4 header length.")

    # ! = network byte order; B = 1 byte; H = 2 bytes; 4s = 4 raw bytes.
    fields = struct.unpack("!BBHHHBBH4s4s", raw[:20])
    total_length = fields[2]
    if total_length < header_length:
        raise ValueError("IPv4 total length is smaller than its header.")
    flags_and_offset = fields[4]
    return {
        "version": version,
        "header_length": header_length,
        "total_length": total_length,
        "identification": fields[3],
        "dont_fragment": bool(flags_and_offset & 0x4000),
        "more_fragments": bool(flags_and_offset & 0x2000),
        "fragment_offset": (flags_and_offset & 0x1FFF) * 8,
        "ttl": fields[5],
        "protocol": fields[6],
        "checksum": fields[7],
        "source": socket.inet_ntoa(fields[8]),
        "destination": socket.inet_ntoa(fields[9]),
        "options": raw[20:header_length],
    }


def parse_tcp_header(segment):
    if len(segment) < 20:
        raise ValueError("TCP header needs at least 20 bytes.")

    # I = unsigned 4-byte integer (sequence and acknowledgment numbers).
    fields = struct.unpack("!HHIIBBHHH", segment[:20])
    header_length = (fields[4] >> 4) * 4
    if header_length < 20 or header_length > len(segment):
        raise ValueError("Invalid or incomplete TCP header length.")
    flag_names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
    flags = [name for bit, name in enumerate(flag_names) if fields[5] & (1 << bit)]
    return {
        "source_port": fields[0],
        "destination_port": fields[1],
        "sequence": fields[2],
        "acknowledgment": fields[3],
        "header_length": header_length,
        "flags": flags,
        "flags_value": fields[5],
        "window": fields[6],
        "checksum": fields[7],
        "urgent_pointer": fields[8],
        "options": segment[20:header_length],
        "payload_length": len(segment) - header_length,
    }


def parse_udp_header(segment):
    if len(segment) < 8:
        raise ValueError("UDP header needs 8 bytes.")
    source_port, destination_port, length, checksum = struct.unpack("!HHHH", segment[:8])
    if length < 8:
        raise ValueError("UDP length cannot be smaller than its 8-byte header.")
    return {
        "source_port": source_port,
        "destination_port": destination_port,
        "length": length,
        "checksum": checksum,
        "payload_length": min(length, len(segment)) - 8,
    }


def parse_packet(raw, number=1, timestamp=None):
    """Decode one IPv4 datagram; retain bad packets with an explanatory note."""
    packet = Packet(number, timestamp or datetime.now().astimezone(), raw)
    try:
        packet.ip = parse_ipv4_header(raw)
    except ValueError as error:
        packet.notes.append(str(error))
        return packet

    ip = packet.ip
    # Ignore Ethernet padding or extra bytes after the declared IPv4 datagram.
    packet.raw = raw[:ip["total_length"]]
    if len(raw) < ip["total_length"]:
        packet.notes.append("Truncated IPv4 packet: some bytes were not captured.")
    segment = packet.raw[ip["header_length"]:]

    # Later fragments start in the middle of a transport message, not its header.
    if ip["fragment_offset"]:
        packet.notes.append("Later IPv4 fragment: transport header is unavailable; no reassembly.")
        return packet
    if ip["more_fragments"]:
        packet.notes.append("First IPv4 fragment: displayed payload is only this fragment; no reassembly.")

    try:
        if ip["protocol"] == 6:
            packet.transport = parse_tcp_header(segment)
            packet.payload = segment[packet.transport["header_length"]:]
        elif ip["protocol"] == 17:
            packet.transport = parse_udp_header(segment)
            length = packet.transport["length"]
            packet.payload = segment[8:length]
            if length > len(segment):
                packet.notes.append("UDP length exceeds available bytes; payload is incomplete.")
            elif length < len(segment):
                packet.notes.append("Bytes after the declared UDP length are excluded from payload.")
        else:
            packet.notes.append("Only the IP header is decoded for this protocol.")
    except ValueError as error:
        packet.notes.append(str(error))
    return packet
