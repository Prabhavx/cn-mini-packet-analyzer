"""Readable summaries, details, payloads and display filters."""


SUMMARY_HEADER = (
    f"{'No.':>5}  {'Time':12}  {'Source IP':15}  {'Destination IP':15}  "
    f"{'Protocol':8}  {'Src port':>8}  {'Dst port':>8}  {'IP bytes':>8}"
)


def matches_filters(packet, filters):
    """All supplied conditions must match (logical AND)."""
    checks = [
        (filters.protocol, packet.protocol),
        (filters.src_ip, packet.ip.get("source")),
        (filters.dst_ip, packet.ip.get("destination")),
        (filters.src_port, packet.transport.get("source_port")),
        (filters.dst_port, packet.transport.get("destination_port")),
    ]
    return all(wanted is None or wanted == actual for wanted, actual in checks)


def summary_line(packet):
    stamp = packet.timestamp.strftime("%H:%M:%S.%f")[:-3]
    return (
        f"{packet.number:5}  {stamp:12}  {packet.ip.get('source', '-'):15}  "
        f"{packet.ip.get('destination', '-'):15}  {packet.protocol:8}  "
        f"{packet.transport.get('source_port', '-'):>8}  "
        f"{packet.transport.get('destination_port', '-'):>8}  {packet.size:8}"
        + ("  *" if packet.notes else "")
    )


def print_summary(packets, filters):
    print(SUMMARY_HEADER)
    shown = [packet for packet in packets if matches_filters(packet, filters)]
    for packet in shown:
        print(summary_line(packet))
    print(f"Shown: {len(shown)} / Stored: {len(packets)}. * = notes; inspect for details.")


def hex_dump(data):
    if not data:
        return "(empty)"
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_text = " ".join(f"{byte:02X}" for byte in chunk)
        # Never send packet control characters (e.g. terminal escapes) to stdout.
        ascii_text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:04X}  {hex_text:47}  |{ascii_text}|")
    return "\n".join(lines)


def print_details(packet):
    def field(label, value):
        print(f"{label + ':':24} {value}")

    def section(title):
        print(f"\n{title}\n{'-' * 48}")

    print(f"\nPacket #{packet.number}")
    field("Time", packet.timestamp.isoformat(sep=" ", timespec="milliseconds"))
    field("Packet length", f"{packet.size} IPv4 bytes (without Ethernet)")
    if packet.ip:
        ip = packet.ip
        section("IP Header")
        field("Version", ip["version"])
        field("Header length", f"{ip['header_length']} bytes")
        field("Total length", f"{ip['total_length']} bytes")
        field("TTL", ip["ttl"])
        field("Protocol", f"{packet.protocol} ({ip['protocol']})")
        field("Header checksum", f"0x{ip['checksum']:04X}")
        field("Source IP", ip["source"])
        field("Destination IP", ip["destination"])
        field("Identification", ip["identification"])
        field("Don't fragment / More", f"{ip['dont_fragment']} / {ip['more_fragments']}")
        field("Fragment offset", f"{ip['fragment_offset']} bytes")
        if ip["options"]:
            field("IP options (hex)", ip["options"].hex(" "))

    header = packet.transport
    if header:
        section(f"{packet.protocol} Header")
        field("Source port", header["source_port"])
        field("Destination port", header["destination_port"])
        if packet.protocol == "TCP":
            field("Sequence number", header["sequence"])
            field("Acknowledgment number", header["acknowledgment"])
            field("Header length", f"{header['header_length']} bytes")
            field("Flags", f"{', '.join(header['flags']) or '(none)'} (0x{header['flags_value']:02X})")
            field("Window size", header["window"])
            field("Urgent pointer", header["urgent_pointer"])
            if header["options"]:
                field("TCP options (hex)", header["options"].hex(" "))
        else:
            field("Length", f"{header['length']} bytes (header + payload)")
        field("Checksum", f"0x{header['checksum']:04X}")
        field("Payload length", f"{header['payload_length']} bytes available")
        section("Payload: hex bytes | printable ASCII (. = non-printable)")
        print(hex_dump(packet.payload))
    else:
        section("Undecoded bytes (not identified as application payload)")
        offset = packet.ip.get("header_length", 0)
        print(hex_dump(packet.raw[offset:]))

    if packet.notes:
        section("Notes")
        for note in packet.notes:
            print("-", note)
