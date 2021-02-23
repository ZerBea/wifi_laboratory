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

Raspberry Pi onboard WiFi chip must be disabled by boot options: dtoverlay=pi3-disable-wifi


General workflow
--------------

connect WiFi adpater

run hcxlabxxxx tool

hcxlabxxxx will create a pcapng file which contain the recorded traffic

Traffic can be monitored by tshark or Wireshark on the fly 


Lessons learned (to be continued)
--------------

A beautiful status output make the attack tool slow and sluggish.

Too many featues make the attack tool slow and sluggish.

Response time behavior becomes very bad on big ringbuffers.

Transmitting too many packets make a channel busy.

A Raspberry Pi is not able to handle more than one interface!
