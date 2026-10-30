# Assignment 3: Mini Packet Analyzer

A small command-line Python program that captures IPv4 packets and manually reads
their IPv4, TCP and UDP headers. It uses only the Python standard library.
No Scapy, PyShark, Wireshark, Npcap or pip packages are needed.

Start with the demo, then read `HOW_IT_WORKS.md`, then try live capture.

## 1. Run the demo first

Open PowerShell in this folder:

```powershell
cd path\to\cn-mini-packet-analyzer
.\run.bat --demo
```

The launcher uses the `py` launcher or `python` from PATH. On any system with
Python 3.9 or newer, the equivalent command is:

```text
python mini_packet_analyzer.py --demo
```

Demo mode creates seven synthetic packets in memory. It does **not** capture or
send traffic. These bytes go through exactly the same parser as live packets.

At the `analyzer>` prompt, try these commands one at a time:

```text
1
3
5
6
7
filter --protocol UDP
filter --src-ip 192.168.1.10 --dst-port 9999
reset
quit
```

- Packet 1: TCP with the text `HELLO SERVER`.
- Packet 3: UDP with the text `Hello over UDP!`.
- Packet 5: TCP acknowledgment with **zero payload bytes**.
- Packet 6: IP and TCP options, so both headers are 24 bytes long.
- Packet 7: binary bytes, displayed safely as hex and printable ASCII.

Every `filter` command replaces the previous filters. Multiple conditions are
combined with AND. Filtering hides rows but retains all stored packets and their
original numbers. Enter any stored packet number to inspect it. `list` repeats the
current summary; `help` explains all commands.

## 2. Capture real packets on Windows

1. Open **PowerShell as Administrator**. Raw sockets require this.
2. Change to this folder and list your local IPv4 address candidates:

```powershell
cd path\to\cn-mini-packet-analyzer
.\run.bat --list-interfaces
ipconfig
```

3. Find the IPv4 address of your active Wi-Fi or Ethernet adapter. Replace the
   example address below with yours:

```powershell
.\run.bat --interface 192.168.1.35 --count 50 --timeout 30
```

4. While capture is running, use your computer normally or generate IPv4 traffic
   in a second terminal, for example:

```powershell
curl.exe -4 https://example.com/
nslookup example.com
```

The first command normally produces TCP traffic. A DNS lookup can produce UDP
traffic if the configured DNS server uses IPv4. Capture starts printing summary
rows immediately. It stops after 50 IPv4 packets or 30 seconds, whichever occurs
first. You can also press **Ctrl+C** to stop and inspect what was collected.

Only capture on systems and networks you own or are authorized to analyze.
Choose an actual adapter address, not `0.0.0.0` or `127.0.0.1`. This Windows
capture method listens to one adapter; locally looped-back traffic may not be
visible there. VPNs and multiple adapters can require a different interface.

## 3. Useful command-line examples

The following use `python`; you can substitute `.\run.bat` for
`python mini_packet_analyzer.py` on Windows.

```text
python mini_packet_analyzer.py --demo --protocol TCP
python mini_packet_analyzer.py --demo --protocol UDP --dst-port 9999
python mini_packet_analyzer.py --demo --src-ip 192.168.1.10
python mini_packet_analyzer.py --demo --dst-ip 192.168.1.10 --src-port 8080
python mini_packet_analyzer.py --demo --packet 3 --no-interactive
python mini_packet_analyzer.py --demo --packet 5 --no-interactive
python mini_packet_analyzer.py --help
```

For a live capture with a display filter:

```powershell
.\run.bat --interface 192.168.1.35 --protocol TCP --dst-port 443 --timeout 30
```

`--count` counts all captured IPv4 packets, including hidden rows. `--count 0`
removes the packet-count limit, but the positive time limit still applies.
`--no-interactive` prints results and exits. `--packet N` prints one packet's
details after capture. Use both to save a report with normal shell redirection:

```powershell
.\run.bat --demo --packet 1 --no-interactive > demo_report.txt
```

Live packets are held in memory for this run; quitting discards them. This small
assignment does not implement a capture-file format.

## 4. Linux

Demo mode needs no special permissions. For live capture, use root privileges or
an appropriately configured `CAP_NET_RAW` environment:

```bash
python3 mini_packet_analyzer.py --list-interfaces
sudo python3 mini_packet_analyzer.py --interface eth0 --count 50 --timeout 30
```

Replace `eth0` with your interface name. Linux can also capture across interfaces
when `--interface` is omitted. Its raw socket supplies Ethernet frames; the code
removes Ethernet/VLAN headers before passing IPv4 bytes to the parser. This path
expects Ethernet-style link headers, not raw Wi-Fi monitor-mode headers.

## 5. Files and reading order

| File | Purpose |
| --- | --- |
| `HOW_IT_WORKS.md` | Beginner explanation, byte offsets and worked example |
| `mini_packet_analyzer.py` | Command-line options and the capture/filter/inspect flow |
| `packet_parser.py` | Manual IPv4, TCP and UDP parsing; the main assignment logic |
| `packet_capture.py` | Windows/Linux raw socket acquisition and cleanup |
| `packet_display.py` | Summary table, filters, details and hex/ASCII output |
| `demo_packets.py` | Synthetic packets for demonstrations without admin rights |
| `test_analyzer.py` | Automated tests using hand-written bytes and simulated sockets |
| `run.bat` | Windows convenience launcher |
| `SAMPLE_OUTPUT.txt` | Actual output from the offline demo |
| `TEST_RESULTS.txt` | Recorded test run and live-capture verification limits |

## 6. Run the tests

With a normal Python installation:

```powershell
python -m unittest -v test_analyzer.py
```

Tests cover known header values, each filter, combined filters, packet selection,
empty/binary payloads, header options, truncation, malformed input, fragmentation,
Ethernet/VLAN removal, loopback de-duplication, capture timeout, permission errors and socket cleanup.
Simulated socket tests do not establish that a particular real adapter works.

## 7. Scope and troubleshooting

- **Access denied:** use an Administrator terminal on Windows or root/CAP_NET_RAW
  on Linux. The demo does not require either.
- **No rows:** check the interface, make IPv4 traffic during capture, and remove
  filters. IPv6 and ARP are intentionally outside the assignment's IPv4 analysis.
- **Only some rows:** filters affect display; `reset` shows every stored packet.
- **Unreadable payload:** HTTPS and other encrypted/binary protocols naturally
  contain non-text bytes. This program does not decrypt application data.
- **Packet size:** the summary consistently reports captured IPv4 bytes, without
  Ethernet headers or padding. IP Total Length is also shown; a truncated packet
  can have fewer captured bytes than its declared total length. A Total Length
  of 0 (segmentation offload on outgoing packets) falls back to the captured size.
- **Fragments:** the first fragment is decoded if its transport header is complete;
  later fragments are labeled and shown as undecoded bytes. No reassembly is done.
- **Checksums:** fields are extracted and displayed, not validated during capture.
  NIC checksum offloading can affect the values seen in local outgoing captures.
- **Timestamps:** local timezone, recorded when Python receives each packet.
- **Capture coverage:** one Windows adapter per run; operating-system and driver
  behavior determine which packets reach the socket. Linux may show duplicates
  when capturing across multiple interfaces (no `--interface`).

## Assignment coverage

| Requirement | Implementation |
| --- | --- |
| Capture transmitted/received packets | Raw sockets in `capture_ipv4` |
| Number, timestamp and size | `Packet` and the summary table |
| Select an individual packet | Interactive number or `--packet` |
| Manual IPv4 header extraction | `parse_ipv4_header` |
| Manual TCP header extraction | `parse_tcp_header` |
| Manual UDP header extraction | `parse_udp_header` |
| Automatically identify TCP/UDP | IPv4 protocol byte: 6 / 17 |
| Protocol, source/destination IP/port filters | CLI and interactive `filter` |
| Detailed headers and payload | `print_details` with hex and ASCII |
| Correct empty payload behavior | `(empty)` and payload length 0 |

The implementation was tested offline on Windows and with real root captures on
Linux (`lo` and `eth0`). An elevated Windows capture still needs to be verified
with the steps above.

References for the capture API:

- [Python socket documentation and Windows sniffer example](https://docs.python.org/3/library/socket.html)
- [Microsoft SIO_RCVALL and adapter capture behavior](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-rcvall)
- [Microsoft raw socket privileges](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2)

## Running in WSL (Windows Subsystem for Linux)

WSL is Linux, so use `python3` instead of `run.bat`. Open the project folder
(for example a project on drive F:):

```bash
cd /mnt/f/cn-mini-packet-analyzer
python3 mini_packet_analyzer.py --demo
python3 -m unittest -v test_analyzer.py
```

Live capture needs `sudo`. Start it in one terminal:

```bash
sudo python3 mini_packet_analyzer.py --interface eth0 --timeout 60
```

While it is capturing, generate traffic in a second WSL terminal:

```bash
curl -4 https://example.com/
python3 -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'HELLO UDP', ('8.8.8.8', 9999))"
```

The first command produces TCP packets to port 443, the second a single UDP
packet. When capture finishes, use the `analyzer>` prompt as described above.

Notes:

- WSL captures only its own virtual network, not traffic from Windows apps such
  as the browser. To capture the whole PC, use the Windows steps in section 2.
- DNS lookups may not appear because WSL forwards them through Windows.
