"""Assignment 3: capture -> manually decode -> filter -> inspect."""

import argparse
from contextlib import closing
import ipaddress
import math
import shlex
import sys

from demo_packets import demo_packets
from packet_capture import capture_ipv4, list_interfaces
from packet_display import SUMMARY_HEADER, matches_filters, print_details, print_summary, summary_line
from packet_parser import parse_packet


def ipv4_address(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        raise argparse.ArgumentTypeError("Enter a valid IPv4 address.") from None


def port_number(value):
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Port must be an integer from 0 to 65535.") from None
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError("Port must be from 0 to 65535.")
    return port


def add_filter_arguments(parser):
    parser.add_argument("--protocol", type=str.upper, choices=["TCP", "UDP"])
    parser.add_argument("--src-ip", type=ipv4_address, help="source IPv4 address")
    parser.add_argument("--dst-ip", type=ipv4_address, help="destination IPv4 address")
    parser.add_argument("--src-port", type=port_number, help="source port")
    parser.add_argument("--dst-port", type=port_number, help="destination port")


def inspect_packet(packets, number):
    for packet in packets:
        if packet.number == number:
            print_details(packet)
            return True
    print(f"Packet #{number} does not exist. Available packet numbers: 1 to {len(packets)}.")
    return False


def interactive_menu(packets, filters):
    filter_parser = argparse.ArgumentParser(prog="filter", description="Replace display filters.")
    add_filter_arguments(filter_parser)
    print("\nCommands: number | list | filter [options] | reset | help | quit")
    print("Example: filter --protocol UDP --dst-port 9999")
    while True:
        try:
            command = input("analyzer> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if command.lower() in ("quit", "q", "exit"):
            return
        if command.lower() == "list":
            print_summary(packets, filters)
        elif command.lower() == "reset":
            filters = filter_parser.parse_args([])
            print_summary(packets, filters)
        elif command.lower() == "help":
            print("Enter a packet number for details. 'list' repeats the summary.")
            print("'filter' replaces filters; conditions are combined with AND. 'reset' clears them.")
            print("Packet numbers stay unchanged. Any stored number can be inspected.")
            filter_parser.print_help()
        elif command.isdecimal():
            inspect_packet(packets, int(command))
        elif command == "filter" or command.startswith("filter "):
            try:
                new_filters = filter_parser.parse_args(shlex.split(command)[1:])
            except (SystemExit, ValueError):
                print("Filters unchanged. Use 'filter --help' for syntax.")
                continue
            filters = new_filters
            print_summary(packets, filters)
        elif command:
            print("Unknown command. Type 'help' for examples.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true", help="analyze synthetic packets; no capture or admin needed")
    parser.add_argument("--interface", help="Windows: local IPv4 address; Linux: interface name")
    parser.add_argument("--list-interfaces", action="store_true", help="list capture interface candidates and exit")
    parser.add_argument("--count", type=int, default=50, help="stop after this many IPv4 packets; 0 = no count limit (default: 50)")
    parser.add_argument("--timeout", type=float, default=30, help="live capture duration in seconds (default: 30)")
    parser.add_argument("--packet", type=int, help="inspect this packet after capture")
    parser.add_argument("--no-interactive", action="store_true", help="print results and exit without a prompt")
    add_filter_arguments(parser)
    args = parser.parse_args(argv)
    if args.count < 0:
        parser.error("--count must be 0 or greater.")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a finite positive number.")
    if args.packet is not None and args.packet < 1:
        parser.error("--packet must be 1 or greater.")

    packets = []
    try:
        if args.list_interfaces:
            list_interfaces()
            return 0
        if args.demo:
            print("DEMO: synthetic IPv4 bytes, not live network traffic.")
            samples = demo_packets()
            if args.count:
                samples = samples[:args.count]
            packets = [parse_packet(raw, i, timestamp)
                       for i, (timestamp, raw) in enumerate(samples, start=1)]
        else:
            print("Capture only traffic on systems/networks you own or are authorized to analyze.")
            print(f"Capturing IPv4 for up to {args.timeout:g}s or {args.count or 'unlimited'} packets.")
            print("Ctrl+C stops capture and keeps collected packets for inspection.")
            print(SUMMARY_HEADER, flush=True)
            try:
                with closing(capture_ipv4(args.interface, args.count, args.timeout)) as stream:
                    for timestamp, raw in stream:
                        packet = parse_packet(raw, len(packets) + 1, timestamp)
                        packets.append(packet)
                        if matches_filters(packet, args):
                            print(summary_line(packet), flush=True)
            except KeyboardInterrupt:
                print("\nCapture stopped.")
            print("\nCapture finished.")
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print_summary(packets, args)
    if not packets:
        print("No IPv4 packets were captured. Check the interface and generate IPv4 traffic during capture.")
        return 1 if args.packet is not None else 0
    if args.packet is not None and not inspect_packet(packets, args.packet):
        return 1
    if not args.no_interactive:
        interactive_menu(packets, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
