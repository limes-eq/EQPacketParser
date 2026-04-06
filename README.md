# EQPacketParser
Python script for decoding wireshark dumps of Everquest traffic

First, create a packet capture in Wireshark, and then File > Export Packet Dissections > as JSON

Next, run this script providing the packet dump and the RoF2.xml opcodes as arguments:

`python eq_packet_parser capture.json --xml RoF2.xml`

By default it will output two files: parsed.txt and summary.txt

Summary.txt contains an overall summary of traffic seen, example:

```
==============================================================
 SECTION 1 — OVERALL OPCODE COUNTS
==============================================================
  Opcode                                      Count       %
  ---------------------------------------- --------  ------
  OP_ClientUpdate                               154   49.0%
  OP_WearChange                                 102   32.5%
  OP_Unknown(0x1100)                             18    5.7%
  OP_SpawnAppearance                             11    3.5%
  OP_Unknown(0x1500)                              9    2.9%
  ---------------------------------------- --------  ------
  TOTAL                                         314  100.0%

==================================================================================================================
 SECTION 2 — OPCODES PER SECOND  (floor of frame.time_relative)
==================================================================================================================
  Opcode                                      t=0s    t=1s    t=2s    t=3s    t=4s    t=5s    t=6s    t=7s    t=8s
  ----------------------------------------------------------------------------------------------------------------
  OP_ClientUpdate                                8      15      15      21      17      12       9      55       2
  OP_WearChange                                  0       0       0      48       0       0       0      54       0
  OP_Unknown(0x1100)                             0       0       0      18       0       0       0       0       0
  OP_SpawnAppearance                             0       0       2       0       0       0       0       9       0
  OP_Unknown(0x1500)                             2       2       3       2       0       0       0       0       0
  ----------------------------------------------------------------------------------------------------------------
  TOTAL                                         11      18      23      98      17      12       9     124       2

```

And parsed.txt contains the decoded opcodes for each packet.
