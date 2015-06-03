*****************************
Rex: Minecraft packet sniffer
*****************************

Rex is a Minecraft proxy server that can identify, print and dump packets
that pass through it. It might be a useful tool if you're interested in how
Minecraft works or are writing your own client/server.

--------
Features
--------

All of these can be turned on/off and filtered by packet type:

- Print the direction, id and name of packets that pass through the proxy
- Print hexdumps of packet payloads
- Save payloads to disk
- Authenticate connecting users
- Connect to online-mode servers (requires an account)

-----------
Limitations
-----------

These might be fixed at some point.

- **No support for sniffing packets in protocol modes other than "play"**. Both
  client-side and server-side login (whether online-mode or not) take place
  in isolation. Support for dumping handshake/status/login packets should be
  possible in offline-to-offline proxies, but isn't available yet.
- No "transport-level" information. Rex won't give you information about
  encryption, compression, etc.

------------
Requirements
------------

- quarry_

-------------
Sample output
-------------

.. code-block:: console

    # Print the ids and names of upstream (client->server) packets
    $ python rex.py -c 127.0.0.1:25566 -d up
    PacketSnifferBridge{barneygale} | INFO | --> play 0x15 Client Settings
    PacketSnifferBridge{barneygale} | INFO | --> play 0x17 Plugin Message
    PacketSnifferBridge{barneygale} | INFO | --> play 0x06 Player Position And Look
    PacketSnifferBridge{barneygale} | INFO | --> play 0x03 Player
    PacketSnifferBridge{barneygale} | INFO | --> play 0x00 Keep Alive
    #-snip-

.. code-block:: bash

    # Hexdump the "Player List Item" packet
    $ python rex.py -c 127.0.0.1:25566 -x -p play 38 down
    PacketSnifferBridge{barneygale} | INFO | <-- play 0x38 Player List Item
    00000000  00 01 fa de 3c 17 42 aa  3e c3 af 21 3b 62 b6 65  |....<.B.>..!;b.e|
    00000010  67 a1 0a 62 61 72 6e 65  79 67 61 6c 65 00 01 00  |g..barneygale...|
    00000020  00                                                |.|
    00000021
    #-snip-

.. _quarry: http://github.com/barneygale/quarry