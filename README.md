hcxlabtool
==============

Skeleton to test WiFi adapters, to understand 802.11 protocol and to discover potential weak points.

Feature requests will be ignored!

It is not made for newbies and comes without any warnings.

Code will often change!


Brief description
--------------

This skeleton is designed to understand 802.11 protocol and to provide a laboratory environment to test WiFi adapters and code snippets for hcxdumptool/hcxtools.

There are only a few basic options and there is no status output.

All additional test functions must be compiled individually (gcc -D - see Makefile).

hcxlabtool is designed to run headless on a modified (GPIO push button and LED) Raspberry Pi.


Requirements
--------------

* detailed knowledge of radio technology

* detailed knowledge of electromagnetic-wave engineering

* detailed knowledge of 802.11 protocol

* detailed knowledge of key derivation functions

* detailed knowledge of Linux

* latest Linux Kernel (recommended distribution: Arch Linux on notebooks and desktop systems, Arch Linux Arm on >= Armv7 systems and Raspberry Pi OS Lite on ARMv6 systems)  

* driver must support full monitor mode and full packet injection

* diver must not depend on NETLINK

* tshark or Wireshark to monitor interface

* tcpdump to create BPF code

Raspberry Pi onboard WiFi chip must be disabled by boot options: dtoverlay=pi3-disable-wifi


General workflow
--------------

connect WiFi adapter

run hcxlabxxxx tool

hcxlabxxxx will create a pcapng file which contain the recorded traffic

traffic can be monitored by tshark or Wireshark on the fly 


Usual commandlines:
--------------

$ sudo hcxlabgetmall -gpio_button=4 --gpio_statusled=17 <br />  control behavior on a modified RPI 

$ sudo hcxlabgetmall --bpfc=own.bpfc <br /> we need to protect own devices

$ sudo hcxlabgetmall -c 1,6,11  <br /> scan this channels only

$ sudo hcxlabgetmall -c 1  <br /> use this channel only

$ sudo hcxlabgetmall  <br /> use all available channels

$ sudo hcxlabgetmall -i interface <br /> use this interface - otherwise the first detected interface is used  <br /> on a RPI the internal WiFi chip must be disabled by boot options

or a combination of this options.


Lessons learned (to be continued)
--------------

a beautiful status output make the attack tool slow and sluggish.

too many features make the attack tool slow and sluggish.

response time behavior becomes very bad on big ringbuffers.

transmitting too many packets make a channel busy.

a Raspberry Pi is not able to handle more than one interface at the same time.

pselect doesn't like to be interrupted by another timer.

active monitor mode (enabled by radiotap header) is mandatatory on AUTHENTICATION, ASSOCIATION and EAPOL frames.

it is mandatory to ACK NULL and ACTION frames within a 4way handshake!

setting a short preamble in radiotap header is ignored on tx.

entire AUTHENTICATION process should be done running a data rate of 1.0 Mb/s
