# How the assignment works

## The whole program in one picture

```text
Real network -> socket -> raw IPv4 bytes --+
                                         |
Offline demo -> synthetic IPv4 bytes -----+
                                         v
                               Read the IPv4 header
                                         |
                      protocol 6 --------+-------- protocol 17
                          v                            v
                   Read TCP header              Read UDP header
                          |                            |
                          +-------------+--------------+
                                        v
                              Separate the payload
                                        v
                         Store numbered/timestamped packet
                                        v
                      Filter summary -> select number -> details
```

The capture code only obtains bytes. All decisions about the IP, TCP and UDP
fields are made by our own functions in `packet_parser.py`.

## 1. What are packet bytes?

Think of a packet as a sequence of numbers between 0 and 255. The protocol tells
us which positions have which meanings. Python represents this sequence as
`bytes`. For example, `raw[0]` is the first byte and `raw[12:16]` is bytes 12-15.
Slice end positions are excluded.

For an ordinary TCP packet:

```text
| IPv4 header (usually 20 bytes) | TCP header (usually 20 bytes) | payload |
```

For UDP:

```text
| IPv4 header (usually 20 bytes) | UDP header (always 8 bytes) | payload |
```

IP and TCP can have options, so we must calculate their header sizes. Assuming
both headers are always 20 bytes would misidentify options as application data.

## 2. Network byte order and struct.unpack

Network protocols place the most significant byte first: **big-endian**.
The two bytes `1F 90` mean `0x1F90 = 8080`.

```python
source_port, destination_port = struct.unpack("!HH", segment[:4])
```

- `!`: use network byte order and standard field sizes.
- `B`: one unsigned byte.
- `H`: two-byte unsigned integer.
- `I`: four-byte unsigned integer.
- `4s`: four bytes kept as bytes, useful for an IPv4 address.

`struct.unpack` is a general byte-conversion tool. It does not understand TCP or
IP. We choose every offset, field format, length check and interpretation.

## 3. IPv4 header

Offsets below are relative to the start of the IPv4 header and start at zero.

| Byte offset | Size | Meaning |
| --- | --- | --- |
| 0 | 1 | Version in upper 4 bits; IHL in lower 4 bits |
| 1 | 1 | DSCP/ECN, not needed for the requested display |
| 2 | 2 | Total length, including IP header |
| 4 | 2 | Identification |
| 6 | 2 | Flags and fragment offset |
| 8 | 1 | TTL |
| 9 | 1 | Protocol: TCP = 6, UDP = 17 |
| 10 | 2 | Header checksum |
| 12 | 4 | Source IPv4 address |
| 16 | 4 | Destination IPv4 address |
| 20 onward | variable | Options, if IHL is greater than 5 |

For first byte `0x45`, its bits are `0100 0101`:

```python
version = raw[0] >> 4           # 0100 -> 4
header_length = (raw[0] & 15) * 4  # 0101 -> 5 words -> 20 bytes
```

The shift keeps the upper four bits. The mask `15`, also written `0x0F`, keeps
the lower four. IHL counts **four-byte words**, hence multiplication by four.
An address stored as `C0 A8 01 0A` becomes `192.168.1.10` using `inet_ntoa`.

The transport segment starts at `raw[header_length]` and ends at IP Total Length.
Anything after Total Length is excluded, which avoids including Ethernet padding.
A Total Length of 0 can appear on outgoing packets when the network card does
segmentation; the parser then uses the captured length and adds a note.

## 4. TCP header

These offsets start at the **TCP header**, not at the IP header.

| Byte offset | Size | Meaning |
| --- | --- | --- |
| 0 | 2 | Source port |
| 2 | 2 | Destination port |
| 4 | 4 | Sequence number |
| 8 | 4 | Acknowledgment number |
| 12 | 1 | Upper four bits give TCP header length in four-byte words |
| 13 | 1 | Eight TCP control flags |
| 14 | 2 | Window size |
| 16 | 2 | Checksum |
| 18 | 2 | Urgent pointer |
| 20 onward | variable | Options, if TCP header length is greater than 20 |

```python
tcp_header_length = (segment[12] >> 4) * 4
payload = segment[tcp_header_length:]
payload_length = len(payload)
```

The flags byte uses one bit for each of FIN, SYN, RST, PSH, ACK, URG, ECE and CWR.
For example, `0x18 = 00011000` has the PSH and ACK bits set.

```python
ack_is_set = bool(segment[13] & 0x10)
```

The sequence number identifies a position in TCP's byte stream. The acknowledgment
number tells the peer which sequence position is expected next when ACK is set.
The displayed window is the raw 16-bit field; TCP window scaling is not applied.
This analyzer inspects individual packets, not reconstructed TCP conversations.

## 5. UDP header

| Byte offset | Size | Meaning |
| --- | --- | --- |
| 0 | 2 | Source port |
| 2 | 2 | Destination port |
| 4 | 2 | UDP length, including its 8-byte header |
| 6 | 2 | Checksum |

```python
source_port, destination_port, length, checksum = struct.unpack("!HHHH", segment[:8])
payload = segment[8:length]
```

For a complete UDP datagram, payload length is `length - 8`. If fewer bytes were
captured, the display reports the available payload length and an incomplete-data
note. The IP and UDP lengths are both respected.

## 6. Worked example: demo packet 1

The first packet contains `HELLO SERVER`, which is 12 ASCII bytes.

```text
IPv4 header = 20 bytes
TCP header  = 20 bytes
Payload     = 12 bytes
Total       = 52 IPv4 bytes
```

The IPv4 protocol field is 6, so we decode TCP. Its source port is 49152 and
destination port is 8080. The TCP header length is 20, so the payload begins at
overall byte offset `20 + 20 = 40`.

```text
Hex:    48 45 4C 4C 4F 20 53 45 52 56 45 52
ASCII:  H  E  L  L  O     S  E  R  V  E  R
```

Demo packet 5 has a total length of 40 bytes: `20 + 20 + 0`. The correct result
is an empty payload. No bytes are invented or read beyond the packet.

## 7. Filtering and selecting

Filters compare the parsed fields with the user's inputs. Every specified
condition must match. For example:

```text
filter --protocol UDP --src-ip 192.168.1.10 --dst-port 9999
```

Only packets meeting all three conditions appear. The packet list is kept intact,
so `reset` can show everything again and packet numbers do not change.
Typing `3` looks up packet number 3 and prints the stored headers and payload.


