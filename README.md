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

tshark or Wireshark to monitor interface

tcpdump to create BPF code

Raspberry Pi onboard WiFi chip must be disabled by boot options: dtoverlay=pi3-disable-wifi


General workflow
--------------

connect WiFi adpater

run hcxlabxxxx tool

hcxlabxxxx will create a pcapng file which contain the recorded traffic

traffic can be monitored by tshark or Wireshark on the fly 


Usual commandlines:
--------------

$ sudo ./hcxlabgetmall -gpio_button=4 --gpio_statusled=17 <br />  control behavior on a modified RPI 

$ sudo ./hcxlabgetmall --bpfc=own.bpfc <br /> we need to protect own devices

$ sudo ./hcxlabgetmall -c 1,6,11  <br /> scan this channels only

$ sudo ./hcxlabgetmall -c 1  <br /> use this channel only

$ sudo ./hcxlabgetmall  <br /> use all available channels

$ sudo ./hcxlabgetmall -i interface <br /> use this interface - otherwise the first detected interface is used  <br /> on a RPI the internal WiFi chip must be disabled by boot options

or a combination of this options.


Lessons learned (to be continued)
--------------

a beautiful status output make the attack tool slow and sluggish.

too many featues make the attack tool slow and sluggish.

response time behavior becomes very bad on big ringbuffers.

transmitting too many packets make a channel busy.

a Raspberry Pi is not able to handle more than one interface!

pselect doesn't like to be interrupted by another timer.

it is mandatory to ACK NULL and ACTION frames within a 4way handshake!

short preambles work with every wireless type other than older types with limited transmission rates in the 1 to 2 Mbps range.

unfortunately short preamble in radiotap header is ignored on tx
