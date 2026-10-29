"""Run with: python -m unittest -v test_analyzer.py (no admin required)."""

import argparse
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import io
import socket
import struct
import unittest
from unittest.mock import Mock, patch

from demo_packets import demo_packets, internet_checksum, make_packet
from mini_packet_analyzer import main
from packet_capture import capture_ipv4, ethernet_to_ipv4
from packet_display import hex_dump, matches_filters, print_details
from packet_parser import parse_packet


# Hand-written fixtures independently specify the byte layout and expected values.
# Their checksum fields are arbitrary known values; the parser extracts them.
TCP_BYTES = bytes.fromhex(
    "45 00 00 2d 12 34 40 00 40 06 be ef c0 a8 01 0a c0 a8 01 14 "
    "c0 00 1f 90 01 02 03 04 a1 b2 c3 d4 50 18 ff ff 2f 81 00 00 "
    "48 45 4c 4c 4f"
)
UDP_BYTES = bytes.fromhex(
    "45 00 00 1f 56 78 00 00 3f 11 12 34 0a 00 00 01 0a 00 00 02 "
    "00 35 14 e9 00 0b 56 78 61 62 63"
)


def changed(raw, offset, replacement):
    return raw[:offset] + replacement + raw[offset + len(replacement):]


def filters(**values):
    defaults = dict(protocol=None, src_ip=None, dst_ip=None, src_port=None, dst_port=None)
    defaults.update(values)
    return argparse.Namespace(**defaults)


class ParserTests(unittest.TestCase):
    def test_ipv4_fields_and_packet_metadata(self):
        stamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
        packet = parse_packet(TCP_BYTES, 17, stamp)
        self.assertEqual((packet.number, packet.timestamp, packet.size), (17, stamp, 45))
        self.assertEqual(packet.protocol, "TCP")
        self.assertEqual(packet.ip["version"], 4)
        self.assertEqual(packet.ip["header_length"], 20)
        self.assertEqual(packet.ip["total_length"], 45)
        self.assertEqual(packet.ip["ttl"], 64)
        self.assertEqual(packet.ip["protocol"], 6)
        self.assertEqual(packet.ip["checksum"], 0xBEEF)
        self.assertEqual(packet.ip["source"], "192.168.1.10")
        self.assertEqual(packet.ip["destination"], "192.168.1.20")
        self.assertFalse(packet.notes)

    def test_tcp_fields(self):
        packet = parse_packet(TCP_BYTES)
        header = packet.transport
        self.assertEqual((header["source_port"], header["destination_port"]), (49152, 8080))
        self.assertEqual(header["sequence"], 0x01020304)
        self.assertEqual(header["acknowledgment"], 0xA1B2C3D4)
        self.assertEqual(header["header_length"], 20)
        self.assertEqual(header["flags"], ["PSH", "ACK"])
        self.assertEqual(header["window"], 65535)
        self.assertEqual(header["checksum"], 0x2F81)
        self.assertEqual(header["payload_length"], 5)
        self.assertEqual(packet.payload, b"HELLO")

    def test_udp_fields(self):
        packet = parse_packet(UDP_BYTES)
        self.assertEqual(packet.protocol, "UDP")
        self.assertEqual(packet.ip["ttl"], 63)
        self.assertEqual(packet.transport, {
            "source_port": 53, "destination_port": 5353,
            "length": 11, "checksum": 0x5678, "payload_length": 3,
        })
        self.assertEqual(packet.payload, b"abc")

    def test_variable_ip_and_tcp_header_sizes(self):
        raw = make_packet(6, "10.0.0.1", "10.0.0.2", 1, 2, b"DATA",
                          ip_options=b"\x01\x01\x00\x00",
                          tcp_options=b"\x02\x04\x05\xb4")
        packet = parse_packet(raw)
        self.assertEqual(packet.ip["header_length"], 24)
        self.assertEqual(packet.transport["header_length"], 24)
        self.assertEqual(packet.payload, b"DATA")

    def test_empty_tcp_and_udp_payloads(self):
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                packet = parse_packet(make_packet(protocol, "10.0.0.1", "10.0.0.2", 1, 2))
                self.assertEqual(packet.payload, b"")
                self.assertEqual(packet.transport["payload_length"], 0)
                output = io.StringIO()
                with redirect_stdout(output):
                    print_details(packet)
                self.assertIn("(empty)", output.getvalue())

    def test_all_eight_tcp_flags(self):
        packet = parse_packet(changed(TCP_BYTES, 33, b"\xff"))
        self.assertEqual(packet.transport["flags"],
                         ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"])

    def test_invalid_ip_headers_are_reported(self):
        cases = [b"", TCP_BYTES[:19], changed(TCP_BYTES, 0, b"\x65"),
                 changed(TCP_BYTES, 0, b"\x44"), changed(TCP_BYTES, 0, b"\x4f"),
                 changed(TCP_BYTES, 2, b"\x00\x10")]
        for raw in cases:
            with self.subTest(raw=raw):
                packet = parse_packet(raw)
                self.assertFalse(packet.ip)
                self.assertTrue(packet.notes)

    def test_truncated_packet_keeps_only_available_payload(self):
        packet = parse_packet(TCP_BYTES[:-2])
        self.assertEqual(packet.size, 43)
        self.assertEqual(packet.ip["total_length"], 45)
        self.assertEqual(packet.payload, b"HEL")
        self.assertTrue(any("Truncated" in note for note in packet.notes))

    def test_short_or_invalid_tcp_header(self):
        for raw in (TCP_BYTES[:30], changed(TCP_BYTES, 32, b"\x40"),
                    changed(TCP_BYTES, 32, b"\xf0")):
            with self.subTest(raw=raw):
                packet = parse_packet(raw)
                self.assertTrue(packet.ip)
                self.assertFalse(packet.transport)
                self.assertTrue(packet.notes)

    def test_invalid_udp_lengths(self):
        for raw in (UDP_BYTES[:25], changed(UDP_BYTES, 24, b"\x00\x07")):
            packet = parse_packet(raw)
            self.assertFalse(packet.transport)
            self.assertTrue(packet.notes)
        packet = parse_packet(changed(UDP_BYTES, 24, b"\x00\x20"))
        self.assertEqual(packet.payload, b"abc")
        self.assertTrue(packet.notes)

    def test_trailing_bytes_are_not_application_payload(self):
        packet = parse_packet(TCP_BYTES + b"PADDING")
        self.assertEqual(packet.payload, b"HELLO")
        self.assertEqual(packet.size, 45)
        packet = parse_packet(changed(UDP_BYTES, 24, b"\x00\x09"))
        self.assertEqual(packet.payload, b"a")
        self.assertEqual(packet.transport["payload_length"], 1)
        self.assertTrue(packet.notes)

    def test_zero_total_length_from_segmentation_offload(self):
        packet = parse_packet(changed(TCP_BYTES, 2, b"\x00\x00"))
        self.assertEqual(packet.ip["total_length"], 0)
        self.assertEqual(packet.size, 45)
        self.assertEqual(packet.payload, b"HELLO")
        self.assertTrue(any("offload" in note for note in packet.notes))

    def test_later_fragment_is_not_decoded_as_tcp(self):
        packet = parse_packet(changed(TCP_BYTES, 6, b"\x00\x01"))
        self.assertEqual(packet.ip["fragment_offset"], 8)
        self.assertFalse(packet.transport)
        self.assertFalse(packet.payload)
        self.assertTrue(packet.notes)

    def test_first_fragment_can_have_transport_header(self):
        packet = parse_packet(changed(TCP_BYTES, 6, b"\x20\x00"))
        self.assertTrue(packet.ip["more_fragments"])
        self.assertEqual(packet.transport["source_port"], 49152)
        self.assertTrue(packet.notes)

    def test_other_protocol_has_ip_but_no_fake_transport_header(self):
        packet = parse_packet(changed(UDP_BYTES, 9, b"\x01"))
        self.assertEqual(packet.protocol, "ICMP")
        self.assertFalse(packet.transport)
        self.assertFalse(packet.payload)

    def test_demo_checksums_are_valid(self):
        for _, raw in demo_packets():
            length = (raw[0] & 15) * 4
            self.assertEqual(internet_checksum(raw[:length]), 0)
            segment = raw[length:]
            pseudo = raw[12:20] + struct.pack("!BBH", 0, raw[9], len(segment))
            self.assertEqual(internet_checksum(pseudo + segment), 0)


class DisplayAndCliTests(unittest.TestCase):
    def test_every_filter_and_combined_filters(self):
        packet = parse_packet(TCP_BYTES)
        values = dict(protocol="TCP", src_ip="192.168.1.10", dst_ip="192.168.1.20",
                      src_port=49152, dst_port=8080)
        for key, value in values.items():
            self.assertTrue(matches_filters(packet, filters(**{key: value})))
        self.assertTrue(matches_filters(packet, filters(**values)))
        mismatches = dict(protocol="UDP", src_ip="10.0.0.1", dst_ip="10.0.0.2",
                          src_port=1, dst_port=2)
        for key, value in mismatches.items():
            self.assertFalse(matches_filters(packet, filters(**{**values, key: value})))

    def test_port_zero_is_not_treated_as_missing(self):
        packet = parse_packet(changed(UDP_BYTES, 20, b"\x00\x00"))
        self.assertTrue(matches_filters(packet, filters(src_port=0)))
        self.assertFalse(matches_filters(packet, filters(src_port=53)))

    def test_binary_payload_cannot_inject_terminal_commands(self):
        output = hex_dump(b"\x1b[31m\x00\xffABC")
        self.assertIn("1B 5B 33 31 6D 00 FF 41 42 43", output)
        self.assertNotIn("\x1b", output)
        self.assertIn(".[31m..ABC", output)

    def test_demo_cli_filters_and_selection(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(["--demo", "--protocol", "udp", "--dst-port", "9999",
                           "--packet", "3", "--no-interactive"])
        self.assertEqual(result, 0)
        self.assertIn("Shown: 2 / Stored: 7", output.getvalue())
        self.assertIn("UDP Header", output.getvalue())
        self.assertIn("Hello over UDP!", output.getvalue())

    def test_interactive_selection_filter_reset_and_errors(self):
        commands = ["5", "filter --protocol UDP", "filter --dst-port wrong", "list",
                    "filter --src-ip bad", "reset", "999", "nonsense", "help", "quit"]
        output = io.StringIO()
        with patch("builtins.input", side_effect=commands), redirect_stdout(output), redirect_stderr(output):
            result = main(["--demo"])
        self.assertEqual(result, 0)
        for text in ("Packet #5", "(empty)", "Shown: 3 / Stored: 7",
                     "Filters unchanged", "Shown: 7 / Stored: 7", "does not exist", "Unknown command"):
            self.assertIn(text, output.getvalue())

    def test_invalid_cli_values_fail_cleanly(self):
        for arguments in (["--src-ip", "invalid"], ["--dst-port", "65536"],
                          ["--src-port", "-1"], ["--count", "-1"],
                          ["--timeout", "nan"], ["--timeout", "inf"],
                          ["--timeout", "0"], ["--packet", "0"]):
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    main(["--demo", *arguments])
                self.assertEqual(error.exception.code, 2)

    def test_missing_packet_returns_failure(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--demo", "--packet", "999", "--no-interactive"]), 1)

    def test_ctrl_c_retains_packets_and_closes_capture(self):
        closed = []

        def stream(*unused):
            try:
                yield datetime.now(timezone.utc), TCP_BYTES
                raise KeyboardInterrupt
            finally:
                closed.append(True)

        output = io.StringIO()
        with patch("mini_packet_analyzer.capture_ipv4", stream), redirect_stdout(output):
            result = main(["--packet", "1", "--no-interactive"])
        self.assertEqual(result, 0)
        self.assertEqual(closed, [True])
        self.assertIn("Packet #1", output.getvalue())


class CaptureTests(unittest.TestCase):
    def test_ethernet_vlan_and_unsupported_frames(self):
        macs = b"\x00" * 12
        self.assertEqual(ethernet_to_ipv4(macs + b"\x08\x00" + TCP_BYTES), TCP_BYTES)
        self.assertEqual(ethernet_to_ipv4(macs + b"\x81\x00\x00\x01\x08\x00" + UDP_BYTES), UDP_BYTES)
        self.assertEqual(ethernet_to_ipv4(macs + b"\x88\xa8\x00\x01\x81\x00\x00\x02\x08\x00" + TCP_BYTES), TCP_BYTES)
        self.assertIsNone(ethernet_to_ipv4(macs + b"\x86\xdd" + b"IPv6"))
        self.assertIsNone(ethernet_to_ipv4(macs + b"\x08\x06" + b"ARP"))
        self.assertIsNone(ethernet_to_ipv4(b"short"))
        self.assertIsNone(ethernet_to_ipv4(macs + b"\x81\x00\x00"))

    def test_linux_loopback_packet_is_kept_once(self):
        frame = b"\x00" * 12 + b"\x08\x00" + UDP_BYTES
        fake = Mock()
        fake.recvfrom.side_effect = [(frame, ("lo", 0x0800, 4, 772, b"")),
                                     (frame, ("lo", 0x0800, 0, 772, b""))]
        with patch("packet_capture.sys.platform", "linux"), \
                patch("packet_capture.socket.AF_PACKET", 17, create=True), \
                patch("packet_capture.socket.socket", return_value=fake):
            packets = list(capture_ipv4("lo", 1, 1))
        self.assertEqual(len(packets), 1)
        self.assertEqual(fake.recvfrom.call_count, 2)

    def test_windows_capture_and_cleanup(self):
        fake = Mock()
        fake.recvfrom.return_value = (TCP_BYTES, ("192.168.1.10", 0))
        with patch("packet_capture.sys.platform", "win32"), \
                patch("packet_capture.socket.socket", return_value=fake), \
                patch("packet_capture.socket.SIO_RCVALL", 1, create=True), \
                patch("packet_capture.socket.RCVALL_IPLEVEL", 3, create=True), \
                patch("packet_capture.socket.RCVALL_OFF", 0, create=True):
            packets = list(capture_ipv4("192.168.1.10", 1, 1))
        self.assertEqual(packets[0][1], TCP_BYTES)
        fake.bind.assert_called_once_with(("192.168.1.10", 0))
        self.assertEqual(fake.ioctl.call_args_list[0].args, (1, 3))
        self.assertEqual(fake.ioctl.call_args_list[-1].args, (1, 0))
        fake.close.assert_called_once()

    def test_linux_capture_skips_other_ether_types(self):
        fake = Mock()
        fake.recvfrom.side_effect = [
            (b"\x00" * 12 + b"\x08\x06" + b"ARP", ("eth0", 0x0806, 0, 1, b"")),
            (b"\x00" * 12 + b"\x08\x00" + UDP_BYTES, ("eth0", 0x0800, 0, 1, b"")),
        ]
        with patch("packet_capture.sys.platform", "linux"), \
                patch("packet_capture.socket.AF_PACKET", 17, create=True), \
                patch("packet_capture.socket.socket", return_value=fake):
            packets = list(capture_ipv4("eth0", 1, 1))
        self.assertEqual(packets[0][1], UDP_BYTES)
        fake.bind.assert_called_once_with(("eth0", 0))
        fake.close.assert_called_once()

    def test_capture_timeout_without_traffic(self):
        fake = Mock()
        fake.recvfrom.side_effect = socket.timeout
        with patch("packet_capture.sys.platform", "linux"), \
                patch("packet_capture.socket.AF_PACKET", 17, create=True), \
                patch("packet_capture.socket.socket", return_value=fake), \
                patch("packet_capture.time.monotonic", side_effect=[0, 0.1, 2]):
            self.assertEqual(list(capture_ipv4(None, 0, 1)), [])
        fake.close.assert_called_once()

    def test_capture_permission_error_is_actionable(self):
        with patch("packet_capture.sys.platform", "linux"), \
                patch("packet_capture.socket.AF_PACKET", 17, create=True), \
                patch("packet_capture.socket.socket", side_effect=PermissionError):
            with self.assertRaisesRegex(PermissionError, "Administrator"):
                list(capture_ipv4(None, 1, 1))

    def test_capture_setup_failure_still_closes_socket(self):
        fake = Mock()
        fake.bind.side_effect = OSError("adapter unavailable")
        with patch("packet_capture.sys.platform", "win32"), \
                patch("packet_capture.socket.socket", return_value=fake):
            with self.assertRaises(OSError):
                list(capture_ipv4("192.168.1.10", 1, 1))
        fake.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
