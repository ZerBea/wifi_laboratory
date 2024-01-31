hcxlabtool
============

A tool to test updates on hcxdumptool.

Expect compiler warnings and ERRORs.

Expect missing or incomplete functions.

Do not reoport issues or feature requests.


What Doesn't hcxlabtool Do?
-----------------------------

* It does not crack WPA PSK related hashes. (Use Hashcat or JtR to recover the PSK.)

* It does not crack WEP. (Use the aircrack-ng suite instead.)

* It does not crack WPS. (Use Reaver or Bully instead.)

* It does not decrypt encrypted traffic. (Use tshark or Wireshark in parallel.)

* It does not record all traffic captured on the WLAN device. (Use tshark or Wireshark in parallel.)

* It does not perform Evil Twin attacks.

* It is not a honey pot.

**Unsupported:** Windows OS, macOS, Android, emulators or wrappers!


Work Flow
----------

hcxlabtool -> hcxpcapngtool -> hcxhashtool (additional hcxpsktool/hcxeiutool) -> Hashcat or JtR


Requirements
-------------

* Knowledge of radio technology.
* Knowledge of electromagnetic-wave engineering.
* Detailed knowledge of 802.11 protocol.
* Detailed knowledge of key derivation functions.
* Detailed knowledge of Linux.
* Detailed knowledge of filter procedures. (Berkeley Packet Filter, capture filter, display filter, etc.)
* Operating system: Linux (recommended: kernel >= 6.4, mandatory: kernel >= 5.10)
* Recommended: Arch Linux on notebooks and desktop systems, Arch Linux Arm on Raspberry Pi >= ARMv7 systems, Raspbian OS Lite or Debian on Raspberry Pi ARMv6 systems .
* WLAN device chipset must be able to run in monitor mode. MediaTek chipsets are preferred due to active monitor mode capabilities.
* WLAN device driver *must* support monitor and full frame injection mode.
* gcc >= 13 recommended (deprecated versions are not supported: https://gcc.gnu.org/)
* make
* libpcap and libpcap-dev (If internal BPF compiler has been enabled.)
* Raspberry Pi A, B, A+, B+, Zero (WH). (Recommended: Zero (WH) or A+, because of a very low power consumption), but notebooks and desktops will work as well.
* GPIO hardware mod recommended (push button and LED) on Raspberry Pi
* To allow 5/6/7GHz packet injection, it is mandatory to uncomment a regulatory domain that support this: /etc/conf.d/wireless-regdom 

**If you decide to compile latest git head, make sure that your distribution is updated to it's latest version!**

**Important Notice**: If you are running Debian on ARM, it is **mandatory** to add "iomem=relaxed" to cmdline.txt to allow IO memory mapping.
