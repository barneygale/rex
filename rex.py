"""
Packet sniffer proxy server

As minecraft packets pass through the proxy, it can:

- Show the ID and name of packets
- Hexdump packet payloads
- Dump payloads to disk

You can choose to handle individual packets yourself (in the usual
quarry fashion) if you want to extract fields from packet payloads
"""

import logging
import os.path

from twisted.internet import reactor, defer

from quarry.net.proxy import DownstreamFactory, Bridge
from quarry.auth import ProfileCLI


class PacketSnifferBridge(Bridge):
    packet_number = 0

    def make_profile(self):
        return self.downstream_factory.profile

    def packet_received(self, buff, direction, name):
        if ((self.downstream_factory.packet_direction is None
                or direction == self.downstream_factory.packet_direction)
            and (self.downstream_factory.packet_whitelist is None
                or (direction, name) in
                    self.downstream_factory.packet_whitelist)):

            description = "%s %s" % (
                "-->" if direction == "upstream" else "<--",
                name)

            print_payload, dump_payload = (
                self.downstream_factory.print_payload,
                self.downstream_factory.dump_payload)

            if print_payload or dump_payload:
                buff.save()
                payload = buff.read()
                if print_payload:
                    description += self.dump_packet(payload)
                if dump_payload:
                    filename = "%06d_%s_%s.bin" % (
                        self.packet_number,
                        "up" if direction == "upstream" else "dn",
                        name)
                    filepath = os.path.join(dump_payload, filename)
                    with open(filepath, "wb") as fd:
                        fd.write(payload)
                    self.packet_number += 1

                buff.restore()

            self.logger.info(description)

        Bridge.packet_received(self, buff, direction, name)


class PacketSnifferDownstreamFactory(DownstreamFactory):
    bridge_class = PacketSnifferBridge
    log_level = logging.WARN

    packet_whitelist = None
    packet_direction = None
    print_payload = False
    dump_payload = False


def split_host_port(host_port):
    host, port = (host_port+":25565").split(":")[:2]
    return host, int(port)


def main(argv):
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
    ProfileCLI.make_parser(group)
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
                             metavar=("DIRECTION", "NAME"),
                             nargs=2,
                             help="Adds a packet to be sniffed. "
                                  "DIRECTION should be one of: "
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

    args = parser.parse_args(argv)
    run(args)
    reactor.run()


@defer.inlineCallbacks
def run(args):
    factory = PacketSnifferDownstreamFactory()
    factory.profile = yield ProfileCLI.make_profile(args)
    factory.online_mode = args.online_mode
    factory.force_protocol_version = args.protocol_version

    if args.direction is not None:
        factory.packet_direction = args.direction + "stream"
    if args.packets is not None:
        packets = set()
        for direction, name in args.packets:
            assert direction in ('up', 'down')
            direction += 'stream'
            packets.add((direction, name))
        factory.packet_whitelist = packets

    factory.print_payload = args.print_payload
    factory.dump_payload = args.dump_payload

    if args.listen:
        listen = split_host_port(args.listen)
        listen_host = listen[0]
        listen_port = int(listen[1])
    else:
        listen_host = ""
        listen_port = 25565

    if args.connect:
        connect = split_host_port(args.connect)
        factory.connect_host = connect[0]
        factory.connect_port = int(connect[1])

    # Connect!
    yield factory.listen(listen_host, listen_port)


if __name__ == "__main__":
    import sys
    main(sys.argv[1:])
