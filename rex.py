"""
Packet sniffer proxy server

As minecraft packets pass through the proxy, it can:

- Show the ID and name of packets
- Hexdump packet payloads
- Dump payloads to disk

You can choose to handle individual packets yourself (in the usual
quarry fashion) if you want to extract fields from packet payloads
"""

import csv
import logging
import os.path

from quarry.net.proxy import DownstreamFactory, Bridge
from quarry.mojang.profile import Profile


def hexdump(data):
    lines = ['']
    bytes_read = 0
    while len(data) > 0:
        data_line, data = data[:16], data[16:]

        l_hex = []
        l_str = []
        for c in data_line:
            l_hex.append("%02x" % ord(c))
            l_str.append(c if 32 <= ord(c) < 127 else ".")

        l_hex.extend(['  ']*(16-len(l_hex)))
        l_hex.insert(8, '')

        lines.append("%08x  %s  |%s|" % (
            bytes_read,
            " ".join(l_hex),
            "".join(l_str)))

        bytes_read += len(data_line)
    return "\n    ".join(lines + ["%08x" % bytes_read])


def get_packet_names():
    packet_names = {}

    with open(os.path.join("data", "packet_names.csv")) as csvfile:
        reader = csv.reader(csvfile)
        for record in reader:
            protocol_version = int(record[0])
            protocol_mode = record[1]
            packet_ident = int(record[2])
            packet_direction = record[3]
            packet_name = record[4]

            packet_names[(protocol_version, protocol_mode,
                          packet_ident, packet_direction)] = packet_name

    return packet_names


class PacketSnifferBridge(Bridge):
    packet_number = 0

    def packet_received(self, buff, protocol_mode, ident, direction):
        if ((self.downstream_factory.packet_direction is None
                or direction == self.downstream_factory.packet_direction)
            and (self.downstream_factory.packet_whitelist is None
                or (protocol_mode, ident, direction) in
                    self.downstream_factory.packet_whitelist)):

            packet_name = self.downstream_factory.packet_names.get(
                (self.downstream.protocol_version,
                 protocol_mode, ident, direction), "UNKNOWN")
            description = "%s %s 0x%02x %s" % (
                "-->" if direction == "upstream" else "<--",
                protocol_mode,
                ident,
                packet_name)

            print_payload, dump_payload = (
                self.downstream_factory.print_payload,
                self.downstream_factory.dump_payload)

            if print_payload or dump_payload:
                buff.save()
                payload = buff.read()
                if print_payload:
                    description += hexdump(payload)
                if dump_payload:
                    filename = "%06d_%s_%s_%02x_%s.bin" % (
                        self.packet_number,
                        "UP" if direction == "upstream" else "DN",
                        protocol_mode.upper(),
                        ident,
                        packet_name)
                    filepath = os.path.join(dump_payload, filename)
                    with open(filepath, "wb") as fd:
                        fd.write(payload)
                    self.packet_number += 1

                buff.restore()

            self.logger.info(description)

        Bridge.packet_received(self, buff, protocol_mode, ident, direction)


class PacketSnifferDownstreamFactory(DownstreamFactory):
    bridge_class = PacketSnifferBridge
    log_level = logging.WARN

    packet_names = {}
    packet_whitelist = None
    packet_direction = None
    print_payload = False
    dump_payload = False


def split_host_port(host_port):
    host, port = (host_port+":25565").split(":")[:2]
    return host, int(port)


def main(args):
    # Parse options
    import argparse
    parser = argparse.ArgumentParser()

    group = parser.add_argument_group("upstream options")
    group.add_argument("-c", "--connect", dest="connect",
                       metavar="HOST[:PORT]",
                       help="Sets the address the proxy should connect to. "
                            "If not given, the proxy connects to the address "
                            "requested by the user. You probably want to set "
                            "this.")
    group.add_argument("-a", "--account", dest="account",
                       metavar=("EMAIL", "PASSWORD"), nargs=2,
                       help="Sets the minecraft account with which to log "
                            "in. Without setting this, the proxy will not be "
                            "capable of logging in to online-mode servers.")
    group = parser.add_argument_group("downstream options")
    group.add_argument("-l", "--listen", dest="listen",
                       metavar="HOST[:PORT]",
                       help="Sets the address the proxy should listen on. "
                            "If not given, the proxy listens on port 25565 on "
                            "all interfaces.")
    group.add_argument("-o", "--online-mode", dest="online_mode",
                       action="store_true",
                       help="If given, users connecting to the proxy are "
                            "authenticated by the Mojang session servers, "
                            "i.e. the server bit of the proxy is running in "
                            "online-mode.")
    group.add_argument("-v", "--protocol-version", dest="protocol_version",
                       type=int,
                       help="Sets the protocol version that the proxy "
                            "accepts from connecting users. If not set, the "
                            "proxy will attempt to use whichever the user "
                            "requests.")
    group = parser.add_argument_group("sniffer options")
    inner_group = group.add_mutually_exclusive_group()
    inner_group.add_argument("-p", "--packet", dest="packets",
                             action="append",
                             metavar=("PROTOCOL_MODE", "IDENT", "DIRECTION"),
                             nargs=3,
                             help="Adds a packet to be sniffed. "
                                  "PROTOCOL_MODE should be one of: "
                                  "'init', 'handshake', 'status', 'login', "
                                  "'play'. "
                                  "IDENT should be one of: "
                                  "'up' (client --> server), "
                                  "'down' (server -> client).")
    inner_group.add_argument("-d", "--direction", dest="direction",
                             choices=("up", "down"),
                             help="Only sniff packets heading in a particular "
                                  "direction.")
    group.add_argument("-x", "--print-payload", dest="print_payload",
                       action="store_true",
                       help="Prints a hexdump with attempted ASCII "
                            "interpretation of the payload of sniffed "
                            "packets")
    group.add_argument("-y", "--dump-payload", dest="dump_payload",
                       metavar="DEST_PATH",
                       help="Dumps the payload of sniffed packets to the "
                            "specified directory")

    args = parser.parse_args(args)

    listen_host = ""
    listen_port = 25565

    factory = PacketSnifferDownstreamFactory()
    factory.online_mode = args.online_mode
    factory.packet_names = get_packet_names()
    factory.force_protocol_version = args.protocol_version

    if args.direction is not None:
        factory.packet_direction = args.direction + "stream"
    if args.packets is not None:
        packets = set()
        for protocol_mode, ident, direction in args.packets:
            ident = int(ident, 16)
            assert direction in ('up', 'down')
            direction += 'stream'
            packets.add((protocol_mode, ident, direction))
        factory.packet_whitelist = packets

    factory.print_payload = args.print_payload
    factory.dump_payload = args.dump_payload

    if args.listen:
        listen = split_host_port(args.listen)
        listen_host = listen[0]
        listen_port = int(listen[1])

    if args.connect:
        connect = split_host_port(args.connect)
        factory.connect_host = connect[0]
        factory.connect_port = int(connect[1])

    if args.account:
        def login_ok(data):
            factory.listen(listen_host, listen_port)

        def login_failed(err):
            print "login failed:", err.value
            factory.stop()

        username, password = args.account
        profile = Profile()

        factory.upstream_factory_class.profile = profile

        deferred = profile.login(username, password)
        deferred.addCallbacks(login_ok, login_failed)
    else:
        factory.listen(listen_host, listen_port)

    factory.run()


if __name__ == "__main__":
    import sys
    main(sys.argv[1:])