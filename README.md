hcxlabtool
==============

Skeleton to test WiFi adapters and to understand 802.11 protocol.

Issue reports and feature requests will be ignored!

It is not made for newbies.

Code will often change!


Brief description
--------------

This skeleton is designed to understand 802.11 protocol and to provide a laboratory environment to test WiFi adapters and code snippets for hcxdumptool/hcxtools.

There are only a few basic options and there is no status output.

All additional test functions must be compiled individually (gcc -D - see Makefile).


Requirements
--------------

latest Linux Kernel

driver must support full monitor mode and full packet injection

diver must not depend on NETLINK

up to 4 WiFi adapters

tshark or Wireshark to monitor interface

tcpdump to create BPF code

Raspberry Pi onboard WiFi chip msut be disabled by boot options: dtoverlay=pi3-disable-wifi


General workflow
--------------

connect 1, 2, 3 or 4 WiFi adpater

run hcxlabxxxx tool (at the moment only hcxlabdeauth)

$ sudo hcxlabdeauth --bpfc=own.bpfc

output (depending on the interfaces) will look like this

0 wlp39s0f3u1u1u2 scanlist:2 3 4 5 7 8 9 10 12 13

1 wlp39s0f3u1u4 channel:1

2 wlp39s0f3u1u1u4 channel:6

3 wlp39s0f3u1u3 channel:11

entering main loop...


hcxlabxxxx will create 4 files which contain the recorded traffic

20210219010816-wlp39s0f3u1u1u2.pcapng

20210219010816-wlp39s0f3u1u1u4.pcapng

20210219010816-wlp39s0f3u1u3.pcapng

20210219010816-wlp39s0f3u1u4.pcapng 


Traffic on a single interface can be monitored by tshark or Wireshark on the fly 


Lessons learned (to be continued)
--------------

A beautiful status output make the attack tool slow and sluggish

Too many featues make the attack tool slow and sluggish.

Response time behavior becomes very bad

A Raspberry Pi is not able to handle more tha one interface!
