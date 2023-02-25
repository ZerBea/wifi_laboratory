hcxlabtool
==============

This is a highly experimental penetration testing tool!

Full NL80211 / RTNETLINK support instead of WIRELESS EXTENSIONS.

It is not made for newbies and it comes without warnings and limited status display.

Feature requests will be ignored and code will often change! 


Brief description
--------------

It is made to detect vulnerabilities in your NETWORK mercilessly!

Is is also designed to run headless on a modified (GPIO push button and LED) Raspberry Pi.

Main purpose is to understand 802.11 protocol and to detect weak points.



Requirements
--------------

* detailed knowledge of radio technology

* detailed knowledge of electromagnetic-wave engineering

* detailed knowledge of 802.11 protocol

* detailed knowledge of key derivation functions

* detailed knowledge of Linux

* latest Linux Kernel (recommended distribution: Arch Linux on notebooks and desktop systems, Arch Linux Arm on >= Armv7 systems and Raspberry Pi OS Lite on ARMv6 systems)  

* driver must support full monitor mode and full packet injection

* tshark or Wireshark to monitor traffic on the same INTERFACE

* tcpdump to create BPF code

Raspberry Pi onboard WiFi chip must be disabled by boot options: dtoverlay=pi3-disable-wifi


General workflow
--------------

connect WiFi adapter

run hcxlabtool

hcxlabtool will create a pcapng file which contain the recorded traffic

traffic can be monitored on the fly by tshark or Wireshark on the same INTERFACE 


Usual commandlines:
--------------

$ sudo hcxlabtool  <br /> use first suitable INTERFACE and scan all available frequencies

$ sudo hcxlabtool -gpio_button=4 --gpio_statusled=17 <br />  control behavior on a modified RPI 

$ sudo hcxlabtool --bpf=own.bpfc <br /> we need to protect own devices

$ sudo hcxlabtool -c 1a,6a,11a  <br /> scan this channels only

$ sudo hcxlabtool -c 1a  <br /> use this channel only

$ sudo hcxlabtool -i interface <br /> use this interface - otherwise the first detected interface is used  <br /> on a RPI the internal WiFi chip must be disabled by boot options

or a combination of this options. See -h or --help for more options


Lessons learned (to be continued)
--------------

a beautiful status output make the attack tool slow and sluggish.

too many features make an attack slow and sluggish.

response time behavior becomes very bad on big ringbuffers.

transmitting too many packets make a channel busy.

a Raspberry Pi is not able to handle more than one interface at the same time.

multiple interfaces interfere with each other.

pselect doesn't like to be interrupted by another timer.

active monitor require to set MAC on interface - that is too slow.

setting a short preamble in radiotap header is ignored on tx.

entire AUTHENTICATION process should be done using a low data rate of 1.0 Mb/s and a small bandwidth.

there are (much) better ways than injecting stupid DEAUTHENTICATION frames to disconnect a CLIENT. 

the most useful frame is an EAPOL M2 frame!

NL80211 provide more options than WIRLESS EXTENSIONS

NL80211 / RTNETLINK can be used without libnl dependency


Warning
--------------

hcxlabtool is designed to be an analysis tool. 

It should only be used in a 100% controlled environment(!).

If you can't control the environment it is absolutely mandatory to set the BPF.

Everything is requested/stored by default and unwanted information must be filtered out by option/filter or later on (offline)! 

You must use hcxlabtool only on networks you have permission to do this and if you know what you are doing.
