#define _GNU_SOURCE
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <linux/filter.h>
#include <linux/genetlink.h>
#include <linux/if_packet.h>
#include <linux/limits.h>
#include <linux/nl80211.h>
#include <linux/rtnetlink.h>
#include <linux/version.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/reboot.h> 
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <termios.h>
#include <unistd.h>

#include "include/types.h"
#include "include/byteorder.h"
#include "include/frames.h"
#include "include/ieee80211.h"
#include "include/pcapng.h"
#include "include/radiotap.h"
#include "include/raspberry.h"
#include "include/hcxm2hunter.h"
/*===========================================================================*/
/* global var */

static uid_t uid = 1000;
static pid_t pid = 0;
static pid_t sid = 0;
static size_t proberesponsetxindex = 0;
static unsigned int seed = 3;

static bool deauthflag = false;

static u16 nlfamily = 0;
static u32 nlseqcounter = 1;

static u16 eventflag = 0;

static int fd_socket_rx = 0;
static int fd_socket_tx = 0;
static int fd_socket_rt = 0;
static int fd_socket_nl = 0;
static int fd_pcapng = 0;
static int fd_timer1 = 0;
static int fd_timer2 = 0;
static int fd_timer3 = 0;
static int fd_timer4 = 0;
static int fd_timer5 = 0;

static long int	timer1_vsec = TIMER1_VSEC;
static long int	timer1_vnsec = TIMER1_VNSEC;
static long int	timer1_isec = TIMER1_ISEC;
static long int	timer1_insec = TIMER1_INSEC;

static long int	timer2_vsec = TIMER2_VSEC;
static long int	timer2_vnsec = TIMER2_VNSEC;
static long int	timer2_isec = TIMER2_ISEC;
static long int	timer2_insec = TIMER2_INSEC;

static long int	timer3_vsec = TIMER3_VSEC;
static long int	timer3_vnsec = TIMER3_VNSEC;
static long int	timer3_isec = TIMER3_ISEC;
static long int	timer3_insec = TIMER3_INSEC;

static long int	timer4_vsec = TIMER4_VSEC;
static long int	timer4_vnsec = TIMER4_VNSEC;
static long int	timer4_isec = TIMER4_ISEC;
static long int	timer4_insec = TIMER4_INSEC;

static int fi = 0;
static frequencylist_t *frequencylist;
static conlist_t *conlist = NULL;
static aplist_t *aprglist = NULL;
static aplist_t *apprdlist = NULL;
static aplist_t *apprlist = NULL;
static aplist_t *apbclist = NULL;

static u64 prtimestamp = 1;

static u16 seqcounter0 = 0; /* proberequest */
static u16 seqcounter1 = 0; /* proberesponse */
static u16 seqcounter2 = 0; /* authenticationrequest */
static u16 seqcounter3 = 0; /* authenticationresponse */
static u16 seqcounter4 = 0; /* associationresponse */
static u16 seqcounter5 = 0; /* reassociationresponse */
static u16 seqcounter6 = 0; /* eapol m1 */
static u16 seqcounter7 = 0; /* deauthentication */
static u16 seqcounter8 = 0; /* disassociation */

static ssize_t packetlen = 0;
static rth_t *rth = NULL;
static u8 *packetptr = NULL;
static u16 ieee82011len = 0;
static u8 *ieee82011ptr = NULL;
static u16 payloadlen = 0;
static u8 *payloadptr = NULL;
static ieee80211_mac_t *macfrx = NULL;
static u8 *llcptr = NULL;
static ieee80211_llc_t *llc = NULL;
static u16 eapauthlen = 0;
static ieee80211_eapauth_t *eapauth;
static u16 eapauthpllen = 0;
static u8 *eapauthplptr = NULL;
static u16 eapolpllen = 0;
static u8 *eapolplptr = NULL;
static ieee80211_wpakey_t *wpakey;
static u16 keyinfo = 0;
static u8 kdv = 0;

static u32 errorcount = 0;
static u32 errortxcount = 0;

static u32 ouiclrg = 0;
static u32 nicclrg = 0;
static u32 ouiaprg = 0;
static u32 nicaprg = 0;
static u64 replaycountrg = 0;

static struct timespec tsakt = { 0 };

static enhanced_packet_block_t *epbhdr = NULL;

static bool holdfrequencyflag = false;
static bool rdsflag = false;

static const u8 rogue1[] = { "rogue1" };
static const u8 regdbin[] = { "DE" };

static const u32 frequencies[] =
{
2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472, 2484,
5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320, 5500, 5520, 5540, 5560, 5580,
5600, 5620, 5640, 5660, 5680, 5700, 5720, 5745, 5765, 5785, 5805, 5825, 5845, 5865,
5885,
5935, 5955, 5975, 5995, 6015, 6035, 6055, 6075, 6095, 6115, 6135, 6155, 6175, 6195,
6215, 6235, 6255, 6275, 6295, 6315, 6335, 6355, 6375, 6395, 6415, 6435, 6455, 6475,
6495, 6515, 6535, 6555, 6575, 6595, 6615, 6635, 6655, 6675, 6695, 6715, 6735, 6755,
6775, 6795, 6815, 6835, 6855, 6875, 6895, 6915, 6935, 6955, 6975, 6995, 7015, 7035,
7055, 7075, 7095, 7115
};

static const char *preinitessid[] =
{
"home", "Home", "internet", "Internet"
};

static struct tpacket_stats lStats = { 0 };
static socklen_t lStatsLength = sizeof(lStats);

static u8 macclrg[ETH_ALEN];
static u8 macaprg[ETH_ALEN];

static u8 anoncerg[32] = { 0 };
static u8 snoncerg[32] = { 0 };

static struct sock_fprog bpf = { 0 };

static interface_t interfaceakt = { 0 };

static u8 nltxbuffer[NLTX_SIZE] = { 0 };
static u8 nlrxbuffer[NLRX_SIZE] = { 0 };

static u8 epb[SNAPLEN] = { 0 };

/*===========================================================================*/
static u16 addoption(u8 *posopt, u16 optioncode, u16 optionlen, char *option)
{
static u16 padding;
static option_header_t *optionhdr;

if (optionlen == 0) return 0;
optionhdr = (option_header_t*)posopt;
optionhdr->option_code = optioncode;
optionhdr->option_length = optionlen;
padding = (4 - (optionlen % 4)) % 4;
memset(optionhdr->option_data, 0, optionlen + padding);
memcpy(optionhdr->option_data, option, optionlen);
return optionlen + padding + 4;
}
/*---------------------------------------------------------------------------*/
static u16 addcustomoption(u8 *pospt)
{
static u16 colen;
static option_header_t *optionhdr;
static optionfield64_t *of;

optionhdr = (option_header_t*)pospt;
optionhdr->option_code = SHB_CUSTOM_OPT;
colen = OH_SIZE;
memcpy(pospt + colen, &hcxmagic, 4);
colen += 4;
memcpy(pospt + colen, &hcxmagic, 32);
colen += 32;
colen += addoption(pospt +colen, OPTIONCODE_MACAP, 6, (char*)macaprg);
of = (optionfield64_t*)(pospt + colen);
of->option_code = OPTIONCODE_RC;
of->option_length = 8;
of->option_value = replaycountrg;
colen += 12;
colen += addoption(pospt + colen, OPTIONCODE_ANONCE, 32, (char*)anoncerg);
colen += addoption(pospt + colen, OPTIONCODE_MACCLIENT, 6, (char*)macclrg);
colen += addoption(pospt + colen, OPTIONCODE_SNONCE, 32, (char*)snoncerg);
colen += addoption(pospt + colen, OPTIONCODE_WEAKCANDIDATE, 8, "12345678");
colen += addoption(pospt + colen, 0, 0, NULL);
optionhdr->option_length = colen - OH_SIZE;
return colen;
}
/*---------------------------------------------------------------------------*/
static bool writecb(void)
{
static ssize_t cblen;
static custom_block_t *cbhdr;
static optionfield64_t *of;
static total_length_t *totallength;
static u8 cb[PCAPNG_BLOCK_SIZE];

memset(cb, 0, PCAPNG_BLOCK_SIZE);
cbhdr = (custom_block_t*)cb;
cblen = CB_SIZE;
cbhdr->block_type = CBID;
cbhdr->total_length = CB_SIZE;
memcpy(cbhdr->pen, hcxmagic, 4);
memcpy(cbhdr->hcxm, hcxmagic, 32);
cblen += addoption(cb + cblen, OPTIONCODE_MACAP, 6, (char*)macaprg);
of = (optionfield64_t*)(cb + cblen);
of->option_code = OPTIONCODE_RC;
of->option_length = 8;
of->option_value = replaycountrg;
cblen += 12;
cblen += addoption(cb + cblen, OPTIONCODE_ANONCE, 32, (char*)anoncerg);
cblen += addoption(cb + cblen, OPTIONCODE_MACCLIENT, 6, (char*)macclrg);
cblen += addoption(cb + cblen, OPTIONCODE_SNONCE, 32, (char*)snoncerg);
cblen += addoption(cb + cblen, OPTIONCODE_WEAKCANDIDATE, 8, "12345678");
cblen += addoption(cb + cblen, 0, 0, NULL);
totallength = (total_length_t*)(cb + cblen);
cblen += TOTAL_SIZE;
cbhdr->total_length = cblen;
totallength->total_length = cblen;
if(write(fd_pcapng, cb, cblen) != cblen) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool writeidb(void)
{
static ssize_t idblen;
static interface_description_block_t *idbhdr;
static total_length_t *totallength;
static char tr[1];
static u8 idb[PCAPNG_BLOCK_SIZE];

memset(idb, 0, PCAPNG_BLOCK_SIZE);
idblen = IDB_SIZE;
idbhdr = (interface_description_block_t*)idb;
idbhdr->block_type = IDBID;
idbhdr->linktype = DLT_IEEE802_11_RADIO;
idbhdr->reserved = 0;
idbhdr->snaplen = SNAPLEN;
idblen += addoption(idb + idblen, IF_NAME, 5, "wlan0");
idblen += addoption(idb + idblen, IF_MACADDR, 6, (char*)interfaceakt.hwmac);
tr[0] = TSRESOL_NSEC;
idblen += addoption(idb + idblen, IF_TSRESOL, 1, tr);
idblen += addoption(idb + idblen, SHB_EOC, 0, NULL);
totallength = (total_length_t*)(idb + idblen);
idblen += TOTAL_SIZE;
idbhdr->total_length = idblen;
totallength->total_length = idblen;
if(write(fd_pcapng, idb, idblen) != idblen) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool writeshb(void)
{
static ssize_t shblen;
static section_header_block_t *shbhdr;
static total_length_t *totallength;
static struct utsname unameData;
static char sysinfo[SHB_SYSINFO_LEN];
static u8 shb[PCAPNG_BLOCK_SIZE];

memset(shb, 0, PCAPNG_BLOCK_SIZE);
shblen = SHB_SIZE;
shbhdr = (section_header_block_t*)shb;
shbhdr->block_type = PCAPNGBLOCKTYPE;
shbhdr->byte_order_magic = PCAPNGMAGICNUMBER;
shbhdr->major_version = PCAPNG_MAJOR_VER;
shbhdr->minor_version = PCAPNG_MINOR_VER;
shbhdr->section_length = -1;
if(uname(&unameData) == 0)
	{
	shblen += addoption(shb + shblen, SHB_HARDWARE, strlen(unameData.machine), unameData.machine);
	snprintf(sysinfo, SHB_SYSINFO_LEN, "%s %s", unameData.sysname, unameData.release);
	shblen += addoption(shb + shblen, SHB_OS, strlen(sysinfo), sysinfo);
	snprintf(sysinfo, SHB_SYSINFO_LEN, "hcxdumptool %s", VERSION_TAG);
	shblen += addoption(shb + shblen, SHB_USER_APPL, strlen(sysinfo), sysinfo);
	}
shblen += addcustomoption(shb + shblen);
shblen += addoption(shb +shblen, SHB_EOC, 0, NULL);
totallength = (total_length_t*)(shb + shblen);
shblen += TOTAL_SIZE;
shbhdr->total_length = shblen;
totallength->total_length = shblen;
if(write(fd_pcapng, shb, shblen) != shblen) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void writeepb(void)
{
static ssize_t epblen;
static u16 padding;
static total_length_t *totallength;
static u64 tspcapng;

epbhdr = (enhanced_packet_block_t*)epb;
epblen = EPB_SIZE;
epbhdr->block_type = EPBID;
epbhdr->interface_id = 0;
epbhdr->cap_len = packetlen;
epbhdr->org_len = packetlen;
tspcapng = ((u64)tsakt.tv_sec * 1000000000ULL) + tsakt.tv_nsec;
epbhdr->timestamp_high = tspcapng >> 32;
epbhdr->timestamp_low = (u32)tspcapng & 0xffffffff;
padding = (4 - (epbhdr->cap_len % 4)) % 4;
epblen += packetlen;
memset(epb + epblen, 0, padding);
epblen += padding;
epblen += addoption(epb + epblen, SHB_EOC, 0, NULL);
totallength = (total_length_t*)(epb + epblen);
epblen += TOTAL_SIZE;
epbhdr->total_length = epblen;
totallength->total_length = epblen;
if(write(fd_pcapng, epb, epblen) != epblen) errorcount += 1;
return;
}
/*===========================================================================*/
static inline __attribute__((always_inline)) void send_deauthentication6(u8 *mc, u8 *ma)
{
CLFMAP3(&tx_deauthentication6, mc, ma);
ADDSEQUENCENR(tx_deauthentication6, seqcounter7);
if(seqcounter6 > 4095) seqcounter7 = 0;
if(write(fd_socket_tx, &tx_deauthentication6, sizeof(tx_deauthentication6)) != sizeof(tx_deauthentication6)) errortxcount += 1;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_disassociation7(u8 *mc, u8 *ma)
{
CLFMAP3(&tx_disassociation7, mc, ma);
ADDSEQUENCENR(tx_disassociation7, seqcounter8);
if(seqcounter8 > 4095) seqcounter8 = 0;
if(write(fd_socket_tx, &tx_disassociation7, sizeof(tx_disassociation7)) != sizeof(tx_disassociation7)) errortxcount += 1;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_disassociation1(u8 *mc, u8 *ma)
{
CLFMAP3(&tx_disassociation1, mc, ma);
ADDSEQUENCENR(tx_disassociation1, seqcounter8);
if(seqcounter8 > 4095) seqcounter8 = 0;
if(write(fd_socket_tx, &tx_disassociation1, sizeof(tx_disassociation1)) != sizeof(tx_disassociation1)) errortxcount += 1;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_proberequest(void)
{
ADDSEQUENCENR(tx_proberequest, seqcounter0);
if(seqcounter0 > 4095) seqcounter0 = 0;
tx_proberequest[56] = (uint8_t)(frequencylist + fi)->channel;
if(write(fd_socket_tx, &tx_proberequest, sizeof(tx_proberequest)) != sizeof(tx_proberequest)) errortxcount += 1;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_proberesponse(u8 *mc, u8 *ma, u8 el, u8 *es)
{
CLFMAP3(&tx_proberesponse_head, mc, ma);
tx_proberesponse_head[49] = el;
memcpy(&tx_proberesponse_head[50], es, el);
ADDSEQUENCENR(tx_proberesponse_head, seqcounter1);
if(seqcounter1 > 4095) seqcounter1 = 0;
ADDCHANNEL(tx_proberesponse_wpa12_short, (frequencylist + fi)->channel);
ADDTIMESTAMP
memcpy(&tx_proberesponse_head[PROBERESPONSEHEAD_SIZE + el], tx_proberesponse_wpa12_short, PROBERESPONSE_WAP12_SHORT_SIZE);
if(write(fd_socket_tx, &tx_proberesponse_head, PROBERESPONSEHEAD_SIZE + el + PROBERESPONSE_WAP12_SHORT_SIZE) != (PROBERESPONSEHEAD_SIZE + el + PROBERESPONSE_WAP12_SHORT_SIZE)) errortxcount += 1;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_authenticationrequest(u8 *mc, u8 *ma)
{
APFMCL3(&tx_authenticationrequest, ma, mc);
ADDSEQUENCENR(tx_authenticationrequest, seqcounter2);
if(seqcounter2 > 4095) seqcounter2 = 9;
if(write(fd_socket_tx, &tx_authenticationrequest, sizeof(tx_authenticationrequest)) != sizeof(tx_authenticationrequest)) errortxcount += 1;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_authenticationresponse(u8 *mc, u8 *ma)
{
CLFMAP3(&tx_authenticationresponse, mc, ma);
ADDSEQUENCENR(tx_authenticationresponse, seqcounter3);
if(seqcounter3 > 4095) seqcounter3 = 9;
if(write(fd_socket_tx, &tx_authenticationresponse, sizeof(tx_authenticationresponse)) != sizeof(tx_authenticationresponse)) errortxcount += 1;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_reassociationresponse(u8 *mc, u8 *ma)
{
CLFMAP3(&tx_reassociationresponse, mc, ma);
ADDSEQUENCENR(tx_reassociationresponse, seqcounter5);
if(seqcounter5 > 4095) seqcounter5 = 0;
if(write(fd_socket_tx, &tx_reassociationresponse, sizeof(tx_reassociationresponse)) != sizeof(tx_reassociationresponse)) errortxcount += 1;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_associationresponse(u8 *mc, u8 *ma)
{
CLFMAP3(&tx_associationresponse, mc, ma);
ADDSEQUENCENR(tx_associationresponse, seqcounter4);
if(seqcounter4 > 4095) seqcounter4 = 0;
if(write(fd_socket_tx, &tx_associationresponse, sizeof(tx_associationresponse)) != sizeof(tx_associationresponse)) errortxcount += 1;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_eapolm1_wpa1(u8 *mc, u8 *ma)
{
CLFMAP3M1(&tx_eapolm1_wpa1, mc, ma);
ADDSEQUENCENRM1(tx_eapolm1_wpa1, seqcounter6);
if(seqcounter6 > 4095) seqcounter6 = 0;
if(write(fd_socket_tx, &tx_eapolm1_wpa1[EAPOLM1_OFFSET], EAPOLM1_SIZE) != EAPOLM1_SIZE) errortxcount += 1;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_eapolm1_wpa2v3(u8 *mc, u8 *ma)
{
CLFMAP3M1(&tx_eapolm1_wpa2v3, mc, ma);
ADDSEQUENCENRM1(tx_eapolm1_wpa2v3, seqcounter6);
if(seqcounter6 > 4095) seqcounter6 = 0;
if(write(fd_socket_tx, &tx_eapolm1_wpa2v3[EAPOLM1_OFFSET], EAPOLM1_SIZE) != EAPOLM1_SIZE) errortxcount += 1;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_eapolm1_wpa2(u8 *mc, u8 *ma)
{
CLFMAP3M1(&tx_eapolm1_wpa2, mc, ma);
ADDSEQUENCENRM1(tx_eapolm1_wpa2, seqcounter6);
if(seqcounter6 > 4095) seqcounter6 = 0;
if(write(fd_socket_tx, &tx_eapolm1_wpa2[EAPOLM1_OFFSET], EAPOLM1_SIZE) != EAPOLM1_SIZE) errortxcount += 1;
return;
}
/*===========================================================================*/
static inline __attribute__((always_inline)) void process80211eapol_m3(void)
{
static size_t i;

writeepb();
for(i = 0; i < CONLIST_MAX - 1; i++)
	{
	if(memcmp((conlist + i)->condata->maccl, macfrx->addr1, ETH_ALEN) != 0) continue;
	if(memcmp((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN) != 0) continue;
	(conlist + i)->sec = tsakt.tv_sec;
	if((((conlist + i)->condata->status & CON_ASSOCREQ) != CON_ASSOCREQ) && (((conlist + i)->condata->status & CON_REASSOCREQ) != CON_REASSOCREQ)) return;
	if(((conlist + i)->condata->rcm1 + 1) != __hcx64be(wpakey->replaycount)) return;
	if(((conlist + i)->condata->rcm2 + 1) != __hcx64be(wpakey->replaycount)) return;
	if(memcmp((conlist + i)->condata->anonce, &wpakey->nonce[28], 4) != 0) return;
	if((tsakt.tv_sec - (conlist + i)->condata->secm1) != 0) return;
	if((tsakt.tv_sec - (conlist + i)->condata->secm2) != 0) return;
	if(((conlist + i)->condata->nsecm2 - (conlist + i)->condata->nsecm1) > EAPOL_M12TOT) return;
	if((tsakt.tv_nsec - (conlist + i)->condata->nsecm2) > EAPOL_M23TOT) return;
	(conlist + i)->condata->countm3 += 1;
	if(rdsflag == false) return;
	printf("M123  %u ", (conlist + i)->condata->countm3);
	for(int x = 0; x < 6; x++) printf("%02x", macfrx->addr1[x]);
	printf(" ");
	for(int x = 0; x < 6; x++) printf("%02x",macfrx->addr3[x]);
	printf("\n");
	return;
	}
(conlist + i)->sec = tsakt.tv_sec;
memset((conlist + i)->condata, 0, CONDATA_SIZE);
(conlist + i)->condata->nsecm1 = tsakt.tv_nsec;
(conlist + i)->condata->rcm1 = __hcx64be(wpakey->replaycount);
memcpy((conlist + i)->condata->maccl, macfrx->addr1, ETH_ALEN);
memcpy((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN);
qsort(conlist, i + 1, CONLIST_SIZE, sort_conlist_by_sec);
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211eapol_m2(void)
{
static size_t i;

writeepb();
for(i = 0; i < CONLIST_MAX - 1; i++)
	{
	if(memcmp((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN) != 0) continue;
	if(memcmp((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN) != 0) continue;
	(conlist + i)->sec = tsakt.tv_sec;
	if((((conlist + i)->condata->status & CON_ASSOCREQ) != CON_ASSOCREQ) && (((conlist + i)->condata->status & CON_REASSOCREQ) != CON_REASSOCREQ)) return;
	if((conlist + i)->condata->rcm1 != __hcx64be(wpakey->replaycount)) return;
	(conlist + i)->condata->secm2 = tsakt.tv_sec;
	(conlist + i)->condata->nsecm2 = tsakt.tv_nsec;
	(conlist + i)->condata->rcm2 = __hcx64be(wpakey->replaycount);
	return;
	}
(conlist + i)->sec = tsakt.tv_sec;
memset((conlist + i)->condata, 0, CONDATA_SIZE);
memcpy((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN);
memcpy((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN);
qsort(conlist, i + 1, CONLIST_SIZE, sort_conlist_by_sec);
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211eapol_m2rg(void)
{
static size_t i;
static enhanced_packet_block_t *epbwpahdr;
static u64 tspcapng;

for(i = 0; i < CONLIST_MAX - 1; i++)
	{
	if(memcmp((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN) != 0) continue;
	if(memcmp((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN) != 0) continue;
	(conlist + i)->sec = tsakt.tv_sec;
	if((((conlist + i)->condata->status & CON_ASSOCREQ) != CON_ASSOCREQ) && (((conlist + i)->condata->status & CON_REASSOCREQ) != CON_REASSOCREQ)) return;
	if(memcmp((conlist + i)->condata->mic, wpakey->keymic, KEYMIC_MAX) == 0) return;
	memcpy((conlist + i)->condata->mic, wpakey->keymic, KEYMIC_MAX);
	(conlist + i)->condata->status |= CON_M2RG;
	(conlist + i)->condata->countm2rg += 1;
	if(kdv == 2)
		{
		epbwpahdr = (enhanced_packet_block_t*)tx_eapolm1_wpa2;
		tspcapng = ((u64)(tsakt.tv_sec * 1000000000ULL) + tsakt.tv_nsec - 1);
		epbwpahdr->timestamp_high = tspcapng >> 32;
		epbwpahdr->timestamp_low = (u32)tspcapng & 0xffffffff;
		CLFMAP3M1(&tx_eapolm1_wpa2, macfrx->addr2, macfrx->addr3);
		if(write(fd_pcapng, tx_eapolm1_wpa2, sizeof(tx_eapolm1_wpa2)) != sizeof(tx_eapolm1_wpa2)) errorcount += 1;
		writeepb();
		}
	else if(kdv == 1)
		{
		epbwpahdr = (enhanced_packet_block_t*)tx_eapolm1_wpa1;
		tspcapng = ((u64)(tsakt.tv_sec * 1000000000ULL) + tsakt.tv_nsec - 1);
		epbwpahdr->timestamp_high = tspcapng >> 32;
		epbwpahdr->timestamp_low = (u32)tspcapng & 0xffffffff;
		CLFMAP3M1(&tx_eapolm1_wpa1, macfrx->addr2, macfrx->addr3);
		if(write(fd_pcapng, tx_eapolm1_wpa1, sizeof(tx_eapolm1_wpa1)) != sizeof(tx_eapolm1_wpa1)) errorcount += 1;
		writeepb();
		}
	if(kdv == 3)
		{
		epbwpahdr = (enhanced_packet_block_t*)tx_eapolm1_wpa2v3;
		tspcapng = ((u64)(tsakt.tv_sec * 1000000000ULL) + tsakt.tv_nsec - 1);
		epbwpahdr->timestamp_high = tspcapng >> 32;
		epbwpahdr->timestamp_low = (u32)tspcapng & 0xffffffff;
		CLFMAP3M1(&tx_eapolm1_wpa2v3, macfrx->addr2, macfrx->addr3);
		if(write(fd_pcapng, tx_eapolm1_wpa2v3, sizeof(tx_eapolm1_wpa2v3)) != sizeof(tx_eapolm1_wpa2v3)) errorcount += 1;
		writeepb();
		}
	holdfrequencyflag = false;
	if(rdsflag == false) return;
	printf("M12RG %u ", (conlist + i)->condata->countm2rg);
	for(int x = 0; x < 6; x++) printf("%02x", macfrx->addr2[x]);
	printf(" ");
	for(int x = 0; x < 6; x++) printf("%02x",macfrx->addr3[x]);
	printf("\n");
	return;
	}
return;
}

/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211eapol_m1(void)
{
static size_t i;

writeepb();
for(i = 0; i < CONLIST_MAX - 1; i++)
	{
	if(memcmp((conlist + i)->condata->maccl, macfrx->addr1, ETH_ALEN) != 0) continue;
	if(memcmp((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN) != 0) continue;
	(conlist + i)->sec = tsakt.tv_sec;
	(conlist + i)->condata->secm1 = tsakt.tv_sec;
	(conlist + i)->condata->nsecm1 = tsakt.tv_nsec;
	(conlist + i)->condata->rcm1 = __hcx64be(wpakey->replaycount);
	memcpy((conlist + i)->condata->anonce, &wpakey->nonce[28], 4);
	(conlist + i)->condata->status |= CON_M1;
	return;
	}
(conlist + i)->sec = tsakt.tv_sec;
memset((conlist + i)->condata, 0, CONDATA_SIZE);
(conlist + i)->condata->secm1 = tsakt.tv_sec;
(conlist + i)->condata->nsecm1 = tsakt.tv_nsec;
(conlist + i)->condata->rcm1 = __hcx64be(wpakey->replaycount);
memcpy((conlist + i)->condata->anonce, &wpakey->nonce[28], 4);
memcpy((conlist + i)->condata->maccl, macfrx->addr1, ETH_ALEN);
memcpy((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN);
(conlist + i)->condata->status = CON_M1;
qsort(conlist, i + 1, CONLIST_SIZE, sort_conlist_by_sec);
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) int get_keyinfo(u16 kyif)
{
if(kyif & WPA_KEY_INFO_ACK)
	{
	if(kyif & WPA_KEY_INFO_INSTALL) return 3; /* handshake 3 */
	else return 1; /* handshake 1 */
	}
else
	{
	if(kyif & WPA_KEY_INFO_SECURE) return 4; /* handshake 4 */
	else return 2; /* handshake 2 */
	}
return 0;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211eapol(void)
{
eapolplptr = eapauthplptr + IEEE80211_EAPAUTH_SIZE;
eapolpllen = eapauthpllen - IEEE80211_EAPAUTH_SIZE;
if((eapolpllen + IEEE80211_EAPAUTH_SIZE + IEEE80211_LLC_SIZE) > payloadlen) return;
wpakey = (ieee80211_wpakey_t*)eapolplptr;
if((kdv = __hcx16be(wpakey->keyinfo) & WPA_KEY_INFO_TYPE_MASK) == 0)
	{
	writeepb();
	return;
	}
keyinfo = (get_keyinfo(__hcx16be(wpakey->keyinfo)));
switch(keyinfo)
	{
	case M1:
	process80211eapol_m1();
	break;

	case M2:
	if(replaycountrg == __hcx64be(wpakey->replaycount)) process80211eapol_m2rg();
	else process80211eapol_m2();
	break;

	case M3:
	process80211eapol_m3();
	break;

	case M4:
	writeepb();
	break;
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211eapauthentication(void)
{
holdfrequencyflag = true;
eapauthplptr = payloadptr + IEEE80211_LLC_SIZE;
eapauthpllen = payloadlen - IEEE80211_LLC_SIZE;
eapauth = (ieee80211_eapauth_t*)eapauthplptr;
eapauthlen = __hcx16be(eapauth->len);
if(eapauthlen > (eapauthpllen - IEEE80211_EAPAUTH_SIZE)) return;
if(eapauth->type == EAPOL_KEY) process80211eapol();
else if(eapauth->type == EAP_PACKET) writeepb();
else if(eapauth->type > EAPOL_KEY) writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) u8 get_tags_security(int infolen, u8 *infostart)
{
static ieee80211_ietag_t *infoptr;
static ieee80211_rsnsectag_t *rsnsecptr;
static ieee80211_wpasectag_t *wpasecptr;

while(0 < infolen)
	{
	infoptr = (ieee80211_ietag_t*)infostart;
	if(infolen < (int)(infoptr->len + IEEE80211_IETAG_SIZE)) return 0;
	else if(infoptr->id == TAG_RSN)
		{
		if(infoptr->len >= RSNLEN_MIN)
			{
			rsnsecptr = (ieee80211_rsnsectag_t*)infoptr->ie;
			if(__hcx16le(rsnsecptr->version) != RSN1) return 0;
			if(__hcx16le(rsnsecptr->pcscount) != 1) return 0;
			if(__hcx16le(rsnsecptr->akmcount) != 1) return 0;
			if((memcmp(rsntkip, rsnsecptr->gcs, SUITE_SIZE) != 0) && (memcmp(rsnccmp, rsnsecptr->gcs, SUITE_SIZE) != 0))  return 0;
			if((memcmp(rsntkip, rsnsecptr->pcs, SUITE_SIZE) != 0) && (memcmp(rsnccmp, rsnsecptr->pcs, SUITE_SIZE) != 0))  return 0;
			if(memcmp(rsnpsk, rsnsecptr->akm, SUITE_SIZE) == 0) return 2;
			if(memcmp(rsnpsk256, rsnsecptr->akm, SUITE_SIZE) == 0) return 3;
			return 0;
			}
		}
	else if(infoptr->id == TAG_VENDOR)
		{
		if(infoptr->len >= WPALEN_MIN)
			{
			wpasecptr = (ieee80211_wpasectag_t*)infoptr->ie;
			if(memcmp(wpatype, wpasecptr->ouitype, SUITE_SIZE) != 0) return 0;
			if(__hcx16le(wpasecptr->version) != 1) return 0;
			if(__hcx16le(wpasecptr->ucscount) != 1) return 0;
			if(__hcx16le(wpasecptr->akmcount) != 1) return 0;
			if((memcmp(wpatkip, wpasecptr->mcs, SUITE_SIZE) != 0) && (memcmp(wpaccmp, wpasecptr->mcs, SUITE_SIZE) != 0))  return 0;
			if((memcmp(wpatkip, wpasecptr->ucs, SUITE_SIZE) != 0) && (memcmp(wpaccmp, wpasecptr->ucs, SUITE_SIZE) != 0))  return 0;
			if(memcmp(wpapsk, wpasecptr->akm, SUITE_SIZE) != 0) return 0;
			return 1;
			}
		}
	infostart += infoptr->len + IEEE80211_IETAG_SIZE;
	infolen -= infoptr->len + IEEE80211_IETAG_SIZE;
	}
return 0;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211data(void)
{
static size_t i;

if(macfrx->from_ds == 1)
	{
	for(i = 0; i < CONLIST_MAX - 1; i++)
		{
		if((conlist + i)->sec == 0) break;
		if(memcmp((conlist + i)->condata->maccl, macfrx->addr1, ETH_ALEN) != 0) continue;
		if(memcmp((conlist + i)->condata->macap, macfrx->addr2, ETH_ALEN) != 0) continue;
		(conlist + i)->sec = tsakt.tv_sec;
		if((conlist + i)->condata->countm3 > COUNT_M123MAX) return;
		(conlist + i)->condata->countdata1 += 1;
		if(deauthflag == false)
			{
			if((conlist + i)->condata->countdata1 > COUNT_DATA1_MAX) return;
			if(((conlist + i)->condata->countdata1 % 10) == 0) send_authenticationrequest(macfrx->addr1, macfrx->addr2);
			}
		return;
		}
	(conlist + i)->sec = tsakt.tv_sec;
	memset((conlist + i)->condata, 0, CONDATA_SIZE);
	memcpy((conlist + i)->condata->maccl, macfrx->addr1, ETH_ALEN);
	memcpy((conlist + i)->condata->macap, macfrx->addr2, ETH_ALEN);
	(conlist + i)->condata->countdata1 += 1;
	qsort(conlist, i + 1, CONLIST_SIZE, sort_conlist_by_sec);
	if(deauthflag == false) send_authenticationrequest(macfrx->addr1, macfrx->addr2);
	return;
	}
if(macfrx->to_ds == 1)
	{
	for(i = 0; i < CONLIST_MAX - 1; i++)
		{
		if((conlist + i)->sec == 0) break;
		if(memcmp((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN) != 0) continue;
		if(memcmp((conlist + i)->condata->macap, macfrx->addr1, ETH_ALEN) != 0) continue;
		(conlist + i)->sec = tsakt.tv_sec;
		if((conlist + i)->condata->countm3 > COUNT_M123MAX) return;
		(conlist + i)->condata->countdata2 += 1;
		if(deauthflag == false)
			{
			if((conlist + i)->condata->countdata1 > COUNT_DATA1_MAX) return;
			if(((conlist + i)->condata->countdata1 % 10) == 0) send_disassociation1(macfrx->addr2, macfrx->addr1);
			}
		return;
		}
	(conlist + i)->sec = tsakt.tv_sec;
	memset((conlist + i)->condata, 0, CONDATA_SIZE);
	memcpy((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN);
	memcpy((conlist + i)->condata->macap, macfrx->addr1, ETH_ALEN);
	(conlist + i)->condata->countdata2 += 1;
	qsort(conlist, i + 1, CONLIST_SIZE, sort_conlist_by_sec);
	if(deauthflag == false) send_disassociation1(macfrx->addr2, macfrx->addr1);
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211null(void)
{
static size_t i;

for(i = 0; i < CONLIST_MAX - 1; i++)
	{
	if((conlist + i)->sec == 0) break;
	if(memcmp((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN) != 0) continue;
	if(memcmp((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN) != 0) continue;
	(conlist + i)->sec = tsakt.tv_sec;
	if((conlist + i)->condata->countm3 > COUNT_M123MAX) return;
	(conlist + i)->condata->countnull += 1;
	if(deauthflag == false)
		{
		if((conlist + i)->condata->countnull > COUNT_NULL_MAX) return;
		if(((conlist + i)->condata->countnull % 10) == 0) send_authenticationrequest(macfrx->addr2, macfrx->addr3);
		}
	return;
	}
(conlist + i)->sec = tsakt.tv_sec;
memset((conlist + i)->condata, 0, CONDATA_SIZE);
memcpy((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN);
memcpy((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN);
(conlist + i)->condata->countnull += 1;
qsort(conlist, i + 1, CONLIST_SIZE, sort_conlist_by_sec);
if(deauthflag == false) send_authenticationrequest(macfrx->addr2, macfrx->addr3);
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211action(void)
{
static size_t i;
static ieee80211_action_t *action;


if(payloadlen < IEEE80211_ACTION_SIZE) return;
if(memcmp(macfrx->addr1, macfrx->addr3, ETH_ALEN) == 0)
	{
	action = (ieee80211_action_t*)payloadptr;
	for(i = 0; i < CONLIST_MAX - 1; i++)
		{
		if(memcmp((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN) != 0) continue;
		if(memcmp((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN) != 0) continue;
		(conlist + i)->sec = tsakt.tv_sec;
		if((conlist + i)->condata->seqaction1 == macfrx->sequence) return;
		(conlist + i)->condata->seqaction1 = macfrx->sequence;
		if(payloadlen > (IEEE80211_ACTION_SIZE + IEEE80211_IETAG_SIZE))
			{
			if((macfrx->prot == 0) && (action->category == RADIO_MEASUREMENT) && (action->code == NEIGHBOR_REPORT_REQUEST))
				{
				if(((conlist + i)->condata->status & CON_ACTION_ESSID) == CON_ACTION_ESSID) return;
				(conlist + i)->condata->status |= CON_ACTION_ESSID;
				writeepb();
				}
			}
		return;
		}
	(conlist + i)->sec = tsakt.tv_sec;
	memset((conlist + i)->condata, 0, CONDATA_SIZE);
	memcpy((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN);
	memcpy((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN);
	(conlist + i)->condata->seqaction1 = macfrx->sequence;
	if(payloadlen > (IEEE80211_ACTION_SIZE + IEEE80211_IETAG_SIZE))
		{
		if((macfrx->prot == 0) && (action->category == RADIO_MEASUREMENT) && (action->code == NEIGHBOR_REPORT_REQUEST))
			{
			(conlist + i)->condata->status = CON_ACTION_ESSID;
			writeepb();
			}
		}
	qsort(conlist, i + 1, CONLIST_SIZE, sort_conlist_by_sec);
	return;
	}
if(memcmp(macbc, macfrx->addr1, ETH_ALEN) == 0) return;
for(i = 0; i < CONLIST_MAX - 1; i++)
	{
	if(memcmp((conlist + i)->condata->maccl, macfrx->addr1, ETH_ALEN) != 0) continue;
	if(memcmp((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN) != 0) continue;
	(conlist + i)->sec = tsakt.tv_sec;
	if((conlist + i)->condata->countm3 > COUNT_M123MAX) return;
	if((conlist + i)->condata->seqaction2 == macfrx->sequence) return;
	(conlist + i)->condata->seqaction2 = macfrx->sequence;
	(conlist + i)->condata->countaction2 += 1;
	if(deauthflag == false)
		{
		if((conlist + i)->condata->countaction2 > COUNT_ACTION2_MAX) return;
		if(((conlist + i)->condata->countaction2 % 10) == 0) send_authenticationrequest(macfrx->addr1, macfrx->addr3);
		}
	return;
	}
(conlist + i)->sec = tsakt.tv_sec;
memset((conlist + i)->condata, 0, CONDATA_SIZE);
memcpy((conlist + i)->condata->maccl, macfrx->addr1, ETH_ALEN);
memcpy((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN);
(conlist + i)->condata->seqaction2 = macfrx->sequence;
(conlist + i)->condata->countaction2 += 1;
qsort(conlist, i + 1, CONLIST_SIZE, sort_conlist_by_sec);
if(deauthflag == false) send_disassociation1(macfrx->addr1, macfrx->addr3);
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211reassociationrequest(void)
{
static size_t i;
static ieee80211_reassoc_req_t *reassociationrequest;
static ieee80211_ietag_t * essidtag;
static u16 reassociationrequestlen;

holdfrequencyflag = true;
reassociationrequest = (ieee80211_reassoc_req_t*)payloadptr;
if((reassociationrequestlen = payloadlen - IEEE80211_REASSOCIATIONREQUEST_SIZE) < IEEE80211_IETAG_SIZE) return;
holdfrequencyflag = true;
for(i = 0; i < CONLIST_MAX - 1; i++)
	{
	if(memcmp((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN) != 0) continue;
	if(memcmp((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN) != 0) continue;
	(conlist + i)->sec = tsakt.tv_sec;
	(conlist + i)->condata->countreassoc += 1;
	if((conlist + i)->condata->countreassoc > COUNT_REASSOC_MAX) return;
	if((conlist + i)->condata->countm2rg > COUNT_M12RGMAX) return;
	if((conlist + i)->condata->seqreassocreq == macfrx->sequence) return;
	(conlist + i)->condata->status |= CON_REASSOCREQ;
	(conlist + i)->condata->seqreassocreq = macfrx->sequence;
	(conlist + i)->condata->akdv = get_tags_security(reassociationrequestlen, reassociationrequest->ie);
	if(((conlist + i)->condata->akdv > 0) && ((conlist + i)->condata->akdv <= 3)) send_reassociationresponse(macfrx->addr2, macfrx->addr3);
	essidtag = (ieee80211_ietag_t*)reassociationrequest->ie;
	if(essidtag->id == TAG_SSID)
		{
		if((essidtag->len > 0) && (essidtag->len <= ESSID_MAX) && (essidtag->ie[0] != 0)) (conlist + i)->condata->status |= CON_ESSID;
		}
	writeepb();
	if((conlist + i)->condata->akdv == 2) send_eapolm1_wpa2(macfrx->addr2, macfrx->addr3);
	else if((conlist + i)->condata->akdv == 1) send_eapolm1_wpa1(macfrx->addr2, macfrx->addr3);
	else if((conlist + i)->condata->akdv == 3) send_eapolm1_wpa2v3(macfrx->addr2, macfrx->addr3);
	qsort(conlist, i + 1, CONLIST_SIZE, sort_conlist_by_sec);
	return;
	}
(conlist + i)->sec = tsakt.tv_sec;
memset((conlist + i)->condata, 0, CONDATA_SIZE);
(conlist + i)->condata->countreassoc += 1;
(conlist + i)->condata->status = CON_REASSOCREQ;
memcpy((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN);
memcpy((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN);
(conlist + i)->condata->seqreassocreq = macfrx->sequence;
(conlist + i)->condata->akdv = get_tags_security(reassociationrequestlen, reassociationrequest->ie);
if(((conlist + i)->condata->akdv > 0) && ((conlist + i)->condata->akdv <= 3)) send_reassociationresponse(macfrx->addr2, macfrx->addr3);
essidtag = (ieee80211_ietag_t*)reassociationrequest->ie;
if(essidtag->id == TAG_SSID)
	{
	if((essidtag->len > 0) && (essidtag->len <= ESSID_MAX) && (essidtag->ie[0] != 0)) (conlist + i)->condata->status |= CON_ESSID;
	}
writeepb();
if((conlist + i)->condata->akdv == 2) send_eapolm1_wpa2(macfrx->addr2, macfrx->addr3);
else if((conlist + i)->condata->akdv == 1) send_eapolm1_wpa1(macfrx->addr2, macfrx->addr3);
else if((conlist + i)->condata->akdv == 3) send_eapolm1_wpa2v3(macfrx->addr2, macfrx->addr3);
qsort(conlist, i + 1, CONLIST_SIZE, sort_conlist_by_sec);
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211associationrequest(void)
{
static size_t i;
static ieee80211_assoc_req_t *associationrequest;
static ieee80211_ietag_t * essidtag;
static u16 associationrequestlen;

holdfrequencyflag = true;
if((associationrequestlen = payloadlen - IEEE80211_ASSOCIATIONREQUEST_SIZE) < IEEE80211_IETAG_SIZE) return;
associationrequest = (ieee80211_assoc_req_t*)payloadptr;
for(i = 0; i < CONLIST_MAX - 1; i++)
	{
	if(memcmp((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN) != 0) continue;
	if(memcmp((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN) != 0) continue;
	(conlist + i)->sec = tsakt.tv_sec;
	(conlist + i)->condata->countassoc += 1;
	if((conlist + i)->condata->countassoc > COUNT_ASSOC_MAX) return;
	if((conlist + i)->condata->countm2rg > COUNT_M12RGMAX) return;
	if((conlist + i)->condata->seqassocreq == macfrx->sequence) return;
	(conlist + i)->condata->status |= CON_ASSOCREQ;
	(conlist + i)->condata->seqassocreq = macfrx->sequence;
	(conlist + i)->condata->akdv = get_tags_security(associationrequestlen, associationrequest->ie);
	if(((conlist + i)->condata->akdv > 0) && ((conlist + i)->condata->akdv <= 3)) send_associationresponse(macfrx->addr2, macfrx->addr3);
	essidtag = (ieee80211_ietag_t*)associationrequest->ie;
	if(essidtag->id == TAG_SSID)
		{
		if((essidtag->len > 0) && (essidtag->len <= ESSID_MAX) && (essidtag->ie[0] != 0)) (conlist + i)->condata->status |= CON_ESSID;
		}
	writeepb();
	if((conlist + i)->condata->akdv == 2) send_eapolm1_wpa2(macfrx->addr2, macfrx->addr3);
	else if((conlist + i)->condata->akdv == 1) send_eapolm1_wpa1(macfrx->addr2, macfrx->addr3);
	else if((conlist + i)->condata->akdv == 3) send_eapolm1_wpa2v3(macfrx->addr2, macfrx->addr3);
	qsort(conlist, i + 1, CONLIST_SIZE, sort_conlist_by_sec);
	return;
	}
(conlist + i)->sec = tsakt.tv_sec;
memset((conlist + i)->condata, 0, CONDATA_SIZE);
(conlist + i)->condata->countassoc += 1;
(conlist + i)->condata->status = CON_ASSOCREQ;
memcpy((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN);
memcpy((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN);
(conlist + i)->condata->seqassocreq = macfrx->sequence;
(conlist + i)->condata->akdv = get_tags_security(associationrequestlen, associationrequest->ie);
if(((conlist + i)->condata->akdv > 0) && ((conlist + i)->condata->akdv <= 3)) send_associationresponse(macfrx->addr2, macfrx->addr3);
essidtag = (ieee80211_ietag_t*)associationrequest->ie;
if(essidtag->id == TAG_SSID)
	{
	if((essidtag->len > 0) && (essidtag->len <= ESSID_MAX) && (essidtag->ie[0] != 0)) (conlist + i)->condata->status |= CON_ESSID;
	}
writeepb();
if((conlist + i)->condata->akdv == 2) send_eapolm1_wpa2(macfrx->addr2, macfrx->addr3);
else if((conlist + i)->condata->akdv == 1) send_eapolm1_wpa1(macfrx->addr2, macfrx->addr3);
else if((conlist + i)->condata->akdv == 3) send_eapolm1_wpa2v3(macfrx->addr2, macfrx->addr3);
qsort(conlist, i + 1, CONLIST_SIZE, sort_conlist_by_sec);
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211authentication(void)
{
static size_t i;
static ieee80211_auth_t *auth;

holdfrequencyflag = true;
if(payloadlen < IEEE80211_AUTH_SIZE) return;
auth = (ieee80211_auth_t*)payloadptr;
if(auth->algorithm != OPEN_SYSTEM) return;
if(__hcx16le(auth->sequence) == 1)
	{
	for(i = 0; i < CONLIST_MAX - 1; i++)
		{
		if(memcmp((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN) != 0) continue;
		if(memcmp((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN) != 0) continue;
		(conlist + i)->sec = tsakt.tv_sec;
		(conlist + i)->condata->countauth += 1;
		if((conlist + i)->condata->countauth > COUNT_AUTH_MAX) return;
		if((conlist + i)->condata->countm2rg > COUNT_M12RGMAX) return;
		if((conlist + i)->condata->seqauthreq == macfrx->sequence) return;
		(conlist + i)->condata->seqauthreq = macfrx->sequence;
		send_authenticationresponse(macfrx->addr2, macfrx->addr3);
		return;
		}
	(conlist + i)->sec = tsakt.tv_sec;
	memset((conlist + i)->condata, 0, CONDATA_SIZE);
	(conlist + i)->condata->countauth += 1;
	memcpy((conlist + i)->condata->maccl, macfrx->addr2, ETH_ALEN);
	memcpy((conlist + i)->condata->macap, macfrx->addr3, ETH_ALEN);
	(conlist + i)->condata->seqauthreq = macfrx->sequence;
	send_authenticationresponse(macfrx->addr2, macfrx->addr3);
	qsort(conlist, i + 1, CONLIST_SIZE, sort_conlist_by_sec);
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211proberequestdirected(void)
{
static size_t i;
static u16 proberequestlen;
static ieee80211_proberequest_t *proberequest;
static ieee80211_ietag_t * essidtag;

if((proberequestlen = payloadlen - IEEE80211_PROBEREQUEST_SIZE) < IEEE80211_IETAG_SIZE) return;
proberequest = (ieee80211_proberequest_t*)payloadptr;
essidtag = (ieee80211_ietag_t*)proberequest->ie;
if(essidtag->len > ESSID_MAX) return;
if((essidtag->len == 0) || (essidtag->ie[0] == 0))
	{
	if(macfrx->retry != 1) send_proberesponse(macfrx->addr2, macfrx->addr3, essidtag->len, essidtag->ie);
	return;
	}
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if((apprdlist + i)->sec == 0) break;
	if(memcmp((apprdlist + i)->apdata->maccl, macfrx->addr2, ETH_ALEN) != 0) continue;
	if(memcmp((apprdlist + i)->apdata->macap, macfrx->addr3, ETH_ALEN) != 0) continue;
	(apprdlist + i)->sec = tsakt.tv_sec;
	if((apprdlist + i)->apdata->essidlen != essidtag->len) continue;
	if(memcmp((apprdlist + i)->apdata->essid, essidtag->ie, essidtag->len) != 0) continue;
	if((apprdlist + i)->apdata->seqprobereq == macfrx->sequence) return;
	(apprdlist + i)->apdata->seqprobereq = macfrx->sequence;
	send_proberesponse(macfrx->addr2, (apprdlist + i)->apdata->macap, (apprdlist + i)->apdata->essidlen, (apprdlist + i)->apdata->essid);
	if(i > APLIST_HALF) qsort(apprdlist, i + 1, APLIST_SIZE, sort_aplist_by_sec);
	return;
	}
(apprdlist + i)->sec = tsakt.tv_sec;
memset((apprdlist + i)->apdata, 0, APDATA_SIZE);
memcpy((apprdlist + i)->apdata->maccl, macfrx->addr2, ETH_ALEN);
memcpy((apprdlist + i)->apdata->macap, macfrx->addr3, ETH_ALEN);
(apprdlist + i)->apdata->seqprobereq = macfrx->sequence;
(apprdlist + i)->apdata->essidlen = essidtag->len;
memcpy((apprdlist + i)->apdata->essid, essidtag->ie, essidtag->len);
send_proberesponse(macfrx->addr2, (apprdlist + i)->apdata->macap, (apprdlist + i)->apdata->essidlen, (apprdlist + i)->apdata->essid);
qsort(apprdlist, i + 1, APLIST_SIZE, sort_aplist_by_sec);
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211proberesponse(void)
{
static size_t i;
static u16 proberesponselen;

if((proberesponselen = payloadlen - IEEE80211_PROBERESPONSE_SIZE) < IEEE80211_IETAG_SIZE) return;
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if((apprlist + i)->sec == 0) break;
	if(memcmp((apprlist + i)->apdata->macap, macfrx->addr3, ETH_ALEN) != 0) continue;
	(apprlist + i)->sec = tsakt.tv_sec;
	if((apprlist + i)->apdata->seqproberesp == macfrx->sequence) return;
	(apprlist + i)->apdata->seqproberesp = tsakt.tv_sec;
	if(i > APLIST_HALF) qsort(apprlist, i + 1, APLIST_SIZE, sort_aplist_by_sec);
	return;
	}
(apprlist + i)->sec = tsakt.tv_sec;
memset((apprlist + i)->apdata, 0, APDATA_SIZE);
memcpy((apprlist + i)->apdata->macap, macfrx->addr3, ETH_ALEN);
(apprlist + i)->apdata->seqproberesp = tsakt.tv_sec;
qsort(apprlist, i + 1, APLIST_SIZE, sort_aplist_by_sec);
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211proberequest(void)
{
static size_t i;
static u16 proberequestlen;
static ieee80211_proberequest_t *proberequest;
static ieee80211_ietag_t * essidtag;

if((proberequestlen = payloadlen - IEEE80211_PROBEREQUEST_SIZE) < IEEE80211_IETAG_SIZE) return;
proberequest = (ieee80211_proberequest_t*)payloadptr;
essidtag = (ieee80211_ietag_t*)proberequest->ie;
if(essidtag->len > ESSID_MAX) return;
if((essidtag->len == 0) || (essidtag->ie[0] == 0))
	{
	if(macfrx->retry == 1) return;
	send_proberesponse(macfrx->addr2, (aprglist + proberesponsetxindex)->apdata->macap, (aprglist + proberesponsetxindex)->apdata->essidlen, (aprglist + proberesponsetxindex)->apdata->essid);
	proberesponsetxindex += 1;
	if((proberesponsetxindex >= ESSIDLIST_MAX))
		{
		proberesponsetxindex = 0;
		return;
		}
	if((aprglist + proberesponsetxindex)->apdata->essidlen == 0) proberesponsetxindex = 0;
	return;
	}
for(i = 0; i < ESSIDLIST_MAX - 1; i++)
	{
	if((aprglist + i)->sec == 0) break;
	if ((aprglist + i)->apdata->essidlen != essidtag->len) continue;
	if(memcmp((aprglist + i)->apdata->essid, essidtag->ie, essidtag->len) != 0) continue;
	(aprglist + i)->sec = tsakt.tv_sec;
	send_proberesponse(macfrx->addr2, (aprglist + i)->apdata->macap, (aprglist + i)->apdata->essidlen, (aprglist + i)->apdata->essid);
	if(i > APLIST_HALF) qsort(aprglist, i + 1, APLIST_SIZE, sort_aplist_by_sec);
	return;
	}
(aprglist + i)->sec = tsakt.tv_sec;
memset((aprglist + i)->apdata, 0, APDATA_SIZE);
(aprglist + i)->apdata->essidlen = essidtag->len;
memcpy((aprglist + i)->apdata->essid, essidtag->ie, essidtag->len);
(aprglist + i)->apdata->macap[5] = nicaprg & 0xff;
(aprglist + i)->apdata->macap[4] = (nicaprg >> 8) & 0xff;
(aprglist + i)->apdata->macap[3] = (nicaprg >> 16) & 0xff;
(aprglist + i)->apdata->macap[2] = ouiaprg & 0xff;
(aprglist + i)->apdata->macap[1] = (ouiaprg >> 8) & 0xff;
(aprglist + i)->apdata->macap[0] = (ouiaprg >> 16) & 0xff;
nicaprg++;
send_proberesponse(macfrx->addr2, (aprglist + i)->apdata->macap, (aprglist + i)->apdata->essidlen, (aprglist + i)->apdata->essid);
qsort(aprglist, i + 1, APLIST_SIZE, sort_aplist_by_sec);
memcpy(&tx_proberequest[22], macfrx->addr2, ETH_ALEN);
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211beacon(void)
{
static size_t i;
static ieee80211_beacon_proberesponse_t *beacon;
static u16 beaconlen;

if((beaconlen = payloadlen - IEEE80211_BEACON_SIZE) < IEEE80211_IETAG_SIZE) return;
beacon = (ieee80211_beacon_proberesponse_t*)payloadptr;
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if((apbclist + i)->sec == 0) break;
	if(memcmp((apbclist + i)->apdata->macap, macfrx->addr3, ETH_ALEN) != 0) continue;
	(apbclist + i)->sec = tsakt.tv_sec;
	(apbclist + i)->apdata->count1 += 1;
	if(deauthflag == false)
		{
		if((apbclist + i)->apdata->count1 <= COUNT_BC_MAX)
			{
			if(((apbclist + i)->apdata->count1 % 20) == 0)
				{
				if(__hcx16le(beacon->capability) & WLAN_CAPABILITY_PRIVACY) send_disassociation7(macfrx->addr1, macfrx->addr3);
				else send_deauthentication6(macfrx->addr1, macfrx->addr3);
				}
			}
		}
	if(i > APLIST_HALF) qsort(apbclist, i + 1, APLIST_SIZE, sort_aplist_by_sec);
	return;
	}
if(deauthflag == false)
	{
	if(__hcx16le(beacon->capability) & WLAN_CAPABILITY_PRIVACY) send_disassociation7(macfrx->addr1, macfrx->addr3);
	else send_deauthentication6(macfrx->addr1, macfrx->addr3);
	}
(apbclist + i)->sec = tsakt.tv_sec;
(apbclist + i)->apdata->count1 += 1;
memset((apbclist + i)->apdata, 0, APDATA_SIZE);
memcpy((apbclist + i)->apdata->macap, macfrx->addr3, ETH_ALEN);
qsort(apbclist, i + 1, APLIST_SIZE, sort_aplist_by_sec);
writeepb();
return;
}
/*===========================================================================*/
/* SCAN LOOP */
static inline __attribute__((always_inline)) void process_packet(void)
{
if((packetlen = read(fd_socket_rx, packetptr, SNAPLEN)) < RTHRX_SIZE)
	{
	if(packetlen == -1) errorcount += 1;
	return;
	}
if(packetlen > SNAPLEN_WANTED) return;
rth = (rth_t*)packetptr;
if((__hcx32le(rth->it_present) & IEEE80211_RADIOTAP_DBM_ANTSIGNAL) == 0) return;
if(__hcx16le(rth->it_len) > packetlen)
	{
	errorcount += 1;
	return;
	}
ieee82011ptr = packetptr + __hcx16le(rth->it_len);
ieee82011len = packetlen - __hcx16le(rth->it_len);
if(ieee82011len <= MAC_SIZE_RTS) return;
macfrx = (ieee80211_mac_t*)ieee82011ptr;
if((macfrx->from_ds == 1) && (macfrx->to_ds == 1)) return;
payloadptr = ieee82011ptr +MAC_SIZE_NORM;
payloadlen = ieee82011len -MAC_SIZE_NORM;
clock_gettime(CLOCK_REALTIME, &tsakt);
if(macfrx->type == IEEE80211_FTYPE_MGMT)
	{
	if(macfrx->subtype == IEEE80211_STYPE_BEACON) process80211beacon();
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_REQ)
		{
		if(memcmp(macbc, macfrx->addr1, ETH_ALEN) == 0) process80211proberequest();
		else process80211proberequestdirected();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_AUTH) process80211authentication();
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ) process80211associationrequest();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ) process80211reassociationrequest();
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP) process80211proberesponse();
	else if(macfrx->subtype == IEEE80211_STYPE_ACTION) process80211action();
	else if(macfrx->subtype == IEEE80211_STYPE_DEAUTH) holdfrequencyflag = true;
	else if(macfrx->subtype == IEEE80211_STYPE_DISASSOC) holdfrequencyflag = true;
	}
if(macfrx->type == IEEE80211_FTYPE_DATA)
	{
	if((macfrx->subtype & IEEE80211_STYPE_QOS_DATA) == IEEE80211_STYPE_QOS_DATA)
		{
		payloadptr += IEEE80211_QOS_SIZE;
		payloadlen -= IEEE80211_QOS_SIZE;
		}
	if(payloadlen > IEEE80211_LLC_SIZE)
		{
		llcptr = payloadptr;
		llc = (ieee80211_llc_t*)llcptr;
		if((__hcx16be(llc->type) == LLC_TYPE_AUTH) && (llc->dsap == IEEE80211_LLC_SNAP) && (llc->ssap == IEEE80211_LLC_SNAP))
			{
			process80211eapauthentication();
			return;
			}
		}

	if((macfrx->duration != 0) && ((macfrx->subtype == IEEE80211_STYPE_DATA) || (macfrx->subtype == IEEE80211_STYPE_QOS_DATA))) process80211data();
	else if((macfrx->to_ds == 1) && ((macfrx->subtype == IEEE80211_STYPE_NULLFUNC) || (macfrx->subtype == IEEE80211_STYPE_QOS_NULLFUNC))) process80211null();
	}
return;
}
/*---------------------------------------------------------------------------*/
static void *nla_data(const struct nlattr *nla)
{
return (u8*)nla + NLA_HDRLEN;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) bool set_frequency(void)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;

i = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = pid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_SET_WIPHY;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_IFINDEX;
*(u32*)nla_data(nla) = interfaceakt.ifindex;
i += 8;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_WIPHY_FREQ;
*(u32*)nla_data(nla) = (frequencylist + fi)->frequency;
i += 8;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_CHANNEL_WIDTH;
*(u32*)nla_data(nla) = 0;
i += 8;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_WIPHY_CHANNEL_TYPE;
*(u32*)nla_data(nla) = 0;
i += 8;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_CENTER_FREQ1;
*(u32*)nla_data(nla) = (frequencylist + fi)->frequency;
i += 8;
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			return false;
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool scanloop(void)
{
static ssize_t i;
static struct itimerspec tm5;
static int fd_epoll = 0;
static int epi = 0;
static int epret = 0;
static u64 tc1, tc2, tc3, tc4, tc5;
static struct epoll_event ev, events[EPOLL_EVENTS_MAX];
static struct timespec tswd = { 0 };

clock_gettime(CLOCK_REALTIME, &tswd);
if((fd_epoll= epoll_create(1)) < 0) return false;
ev.data.fd = fd_socket_rx;
ev.events = EPOLLIN;
if(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_socket_rx, &ev) < 0) return false;
epi++;

ev.data.fd = fd_timer1;
ev.events = EPOLLIN;
if(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_timer1, &ev) < 0) return false;
epi++;

ev.data.fd = fd_timer2;
ev.events = EPOLLIN;
if(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_timer2, &ev) < 0) return false;
epi++;

ev.data.fd = fd_timer3;
ev.events = EPOLLIN;
if(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_timer3, &ev) < 0) return false;
epi++;

ev.data.fd = fd_timer4;
ev.events = EPOLLIN;
if(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_timer4, &ev) < 0) return false;
epi++;

ev.data.fd = fd_timer5;
ev.events = EPOLLIN;
if(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_timer5, &ev) < 0) return false;
epi++;

fi = 0;
if(set_frequency() == false) return false;
send_proberequest();
while(!eventflag)
	{
	if((epret = epoll_pwait(fd_epoll, events, epi, - 1, NULL)) == -1)
		{
		if(errno == EINTR) return true;
		return false;
		}
	for(i = 0; i < epret; i++)
		{
		if(events[i].data.fd == fd_socket_rx) process_packet();
		else if(events[i].data.fd == fd_timer1)
			{
			if(read(fd_timer1, &tc1, sizeof(u64)) != sizeof(u64)) return false;
			if(timer1_isec > TIMER_HOLD)
				{
				fi++;
				if(((frequencylist + fi)->frequency == 0) || (fi >= FREQUENCYLIST_MAX)) fi = 0;
				if(set_frequency() == false) return false;
				}
			else if(holdfrequencyflag == false)
				{
				fi++;
				if(((frequencylist + fi)->frequency == 0) || (fi >= FREQUENCYLIST_MAX)) fi = 0;
				if(set_frequency() == false) return false;
				}
			else holdfrequencyflag = false;
			send_proberequest();
			}
		else if(events[i].data.fd == fd_timer2)
			{
			if(read(fd_timer2, &tc2, sizeof(u64)) != sizeof(u64)) return false;
			if(tswd.tv_sec >= tsakt.tv_sec) eventflag |= EVENT_WATCHDOG;
			clock_gettime(CLOCK_REALTIME, &tswd);
			}
		else if(events[i].data.fd == fd_timer3)
			{
			if(read(fd_timer3, &tc3, sizeof(u64)) != sizeof(u64)) return false;
			eventflag |= EVENT_TOT;
			}
		else if(events[i].data.fd == fd_timer4)
			{
			if(read(fd_timer4, &tc4, sizeof(u64)) != sizeof(u64)) return false;
			if(GET_GPIO(GPIO_BUTTON) > 0) eventflag |= EVENT_GPIO_BUTTON;
			GPIO_SET = 1 << GPIO_LED;
			tm5.it_value.tv_sec = TIMER5_VSEC;
			tm5.it_value.tv_nsec = TIMER5_VNSEC;
			tm5.it_interval.tv_sec = TIMER5_ISEC;
			tm5.it_interval.tv_nsec = TIMER5_INSEC;
			if(timerfd_settime(fd_timer5, 0, &tm5, NULL) == -1) return false;
			}
		else if(events[i].data.fd == fd_timer5)
			{
			if(read(fd_timer5, &tc5, sizeof(u64)) != sizeof(u64)) return false;
			if(GET_GPIO(GPIO_BUTTON) > 0) eventflag |= EVENT_GPIO_BUTTON;
			else GPIO_CLR = 1 << GPIO_LED;
			}
		}
	}
return true;
}
/*===========================================================================*/
static void deinit_all(void)
{
static size_t i;

if(fd_timer1 != 0) close(fd_timer1);
if(fd_timer2 != 0) close(fd_timer2);
if(fd_timer3 != 0) close(fd_timer3);
if(fd_timer4 != 0) close(fd_timer4);
if(fd_timer5 != 0) close(fd_timer5);

if(getsockopt(fd_socket_rx, SOL_PACKET, PACKET_STATISTICS, &lStats, &lStatsLength) != 0) fprintf(stdout, "failed to get packet statistics\n");

if(bpf.filter != NULL)
	{
	if(fd_socket_rx > 0) setsockopt(fd_socket_rx, SOL_SOCKET, SO_DETACH_FILTER, &bpf, sizeof(bpf));
	free(bpf.filter);
	}

if(fd_socket_rx != 0) close(fd_socket_rx);
if(fd_socket_tx != 0) close(fd_socket_tx);
if(fd_socket_nl != 0) close(fd_socket_nl);
if(fd_socket_rt != 0) close(fd_socket_rt);

if(fd_pcapng != 0)
	{
	fsync(fd_pcapng);
	close(fd_pcapng);
	}

if(frequencylist != NULL) free(frequencylist);

for(i = 0; i < CONLIST_MAX; i++)
	{
	if((conlist + i)->condata != NULL) free((conlist + i)->condata);
	}
if(conlist != NULL) free(conlist);

for(i = 0; i < ESSIDLIST_MAX; i++)
	{
	if((aprglist + i)->apdata != NULL) free((aprglist + i)->apdata);
	}
if(aprglist != NULL) free(aprglist);

for(i = 0; i < APLIST_MAX; i++)
	{
	if((apprdlist + i)->apdata != NULL) free((apprdlist + i)->apdata);
	}
if(apprdlist != NULL) free(apprdlist);

for(i = 0; i < APLIST_MAX; i++)
	{
	if((apprlist + i)->apdata != NULL) free((apprlist + i)->apdata);
	}
if(apprlist != NULL) free(apprlist);

for(i = 0; i < APLIST_MAX; i++)
	{
	if((apbclist + i)->apdata != NULL) free((apbclist + i)->apdata);
	}
if(apbclist != NULL) free(apbclist);
return;
}
/*===========================================================================*/
static size_t chop(char *buffer, size_t len)
{
char *ptr = NULL;

ptr = buffer +len - 1 ;
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
static int fgetline(FILE *inputstream, size_t size, char *buffer)
{
static size_t len = 0;
static char *buffptr = NULL;

if(feof(inputstream)) return -1;
buffptr = fgets(buffer, size, inputstream);
if(buffptr == NULL) return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
static void read_essidlist(char *listname)
{
static size_t i;
static int len;
static FILE *fh_essidlist;
static char linein[ESSID_MAX];

if((fh_essidlist = fopen(listname, "r")) == NULL)
	{
	fprintf(stdout, "failed to open ESSID list %s\n", listname);
	return;
	}
i = 0;
while(i < (ESSIDLIST_MAX - 1))
	{
	if((len = fgetline(fh_essidlist, ESSID_MAX, linein)) == -1) break;
	if((len == 0) || (len > ESSID_MAX)) continue;
	(aprglist + i)->sec = tsakt.tv_sec -i;
	(aprglist + i)->apdata->essidlen = len;
	memcpy((aprglist + i)->apdata->essid, linein, len);
	(aprglist + i)->apdata->macap[5] = nicaprg & 0xff;
	(aprglist + i)->apdata->macap[4] = (nicaprg >> 8) & 0xff;
	(aprglist + i)->apdata->macap[3] = (nicaprg >> 16) & 0xff;
	(aprglist + i)->apdata->macap[2] = ouiaprg & 0xff;
	(aprglist + i)->apdata->macap[1] = (ouiaprg >> 8) & 0xff;
	(aprglist + i)->apdata->macap[0] = (ouiaprg >> 16) & 0xff;
	nicaprg++;
	i++;
	}
(aprglist + i)->apdata->essidlen = 0;
fclose(fh_essidlist);
return;
}
/*===========================================================================*/
static bool read_bpf(char *bpfname)
{
static int len;
static struct sock_filter *bpfptr;
static FILE *fh_filter;
static char linein[128];

if((fh_filter = fopen(bpfname, "r")) == NULL) return false;
if((bpf.filter = (struct sock_filter*)calloc(BPF_MAXINSNS, sizeof(struct sock_filter))) == NULL) return false;
bpf.len = 0;
bpfptr = bpf.filter;
while(bpf.len < BPF_MAXINSNS +1)
	{
	if((len = fgetline(fh_filter, 128, linein)) == -1) break;
	if(bpf.len == BPF_MAXINSNS)
		{
		bpf.len = 0;
		break;
		}
	if(len < 7) continue;
	if(linein[0] != '{')
		{
		if(sscanf(linein, "%" SCNu16 "%" SCNu8 "%" SCNu8 "%" SCNu32, &bpfptr->code, &bpfptr->jt, &bpfptr->jf, &bpfptr->k) != 4)
			{
			bpf.len = 0;
			break;
			}
		}
	else
		{
		if(sscanf(linein, "{ %" SCNx16 ", %"  SCNu8 ", %" SCNu8 ", %" SCNx32 " },",&bpfptr->code, &bpfptr->jt, &bpfptr->jf, &bpfptr->k) != 4)
			{
			bpf.len = 0;
			break;
			}
		}
	bpfptr++;
	bpf.len++;
	}
fclose(fh_filter);
if(bpf.len == 0) return false;
return true;
}
/*===========================================================================*/
/* SIGNALHANDLER */
static void signal_handler(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL) || (signum == SIGTSTP)) eventflag |= EVENT_SIGTERM;
return;
}
/*---------------------------------------------------------------------------*/
static bool init_signal_handler(void)
{
struct sigaction sa;

sa.sa_handler = signal_handler;
sigemptyset(&sa.sa_mask);
sa.sa_flags = SA_RESTART;
if(sigaction(SIGINT, &sa, NULL) < 0) return false;
if(sigaction(SIGTERM, &sa, NULL) < 0) return false;
if(sigaction(SIGTSTP, &sa, NULL) < 0) return false;
return true;
}
/*===========================================================================*/
/* TIMER */
static bool init_timer(void)
{
static struct itimerspec tm1;
static struct itimerspec tm2;
static struct itimerspec tm3;
static struct itimerspec tm4;
static struct itimerspec tm5;

/* stay time */
if((fd_timer1 = timerfd_create(CLOCK_BOOTTIME, 0)) < 0) return false;
tm1.it_value.tv_sec = timer1_vsec;
tm1.it_value.tv_nsec = timer1_vnsec;
tm1.it_interval.tv_sec = timer1_isec;
tm1.it_interval.tv_nsec = timer1_insec;
if(timerfd_settime(fd_timer1, 0, &tm1, NULL) == -1) return false;

/* watchdog */
if((fd_timer2 = timerfd_create(CLOCK_BOOTTIME, 0)) < 0) return false;
tm2.it_value.tv_sec = timer2_vsec;
tm2.it_value.tv_nsec = timer2_vnsec;
tm2.it_interval.tv_sec = timer2_isec;
tm2.it_interval.tv_nsec = timer2_insec;
if(timerfd_settime(fd_timer2, 0, &tm2, NULL) == -1) return false;

/* tot */
if((fd_timer3 = timerfd_create(CLOCK_BOOTTIME, 0)) < 0) return false;
tm3.it_value.tv_sec = timer3_vsec;
tm3.it_value.tv_nsec = timer3_vnsec;
tm3.it_interval.tv_sec = timer3_isec;
tm3.it_interval.tv_nsec = timer3_insec;
if(timerfd_settime(fd_timer3, 0, &tm3, NULL) == -1) return false;

/* LED on */
if((fd_timer4 = timerfd_create(CLOCK_BOOTTIME, 0)) < 0) return false;
tm4.it_value.tv_sec = timer4_vsec;
tm4.it_value.tv_nsec = timer4_vnsec;
tm4.it_interval.tv_sec = timer4_isec;
tm4.it_interval.tv_nsec = timer4_insec;
if(timerfd_settime(fd_timer4, 0, &tm4, NULL) == -1) return false;

/* LED of */
if((fd_timer5 = timerfd_create(CLOCK_BOOTTIME, 0)) < 0) return false;
tm5.it_value.tv_sec = 0;
tm5.it_value.tv_nsec = 0;
tm5.it_interval.tv_sec = 0;
tm5.it_interval.tv_nsec = 0;
if(timerfd_settime(fd_timer5, 0, &tm5, NULL) == -1) return false;

return true;
}
/*===========================================================================*/
/* RAW PACKET SOCKET */
static bool open_socket_rx(char *bpfname)
{
static size_t c = 10;
static struct sockaddr_ll saddr;
static struct packet_mreq mrq;
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
 static int enable = 1;
#endif
static int socket_rx_flags;
static int prioval;
static ssize_t rv;
static socklen_t priolen;

bpf.len = 0;
if(bpfname != NULL)
	{
	if(read_bpf(bpfname) == false)
		{
		fprintf(stdout, "failed to read BPF\n");
		return false;
		}
	}
if((fd_socket_rx = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL))) < 0) return false;
memset(&mrq, 0, sizeof(mrq));
mrq.mr_ifindex = interfaceakt.ifindex;
mrq.mr_type = PACKET_MR_PROMISC;
if(setsockopt(fd_socket_rx, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mrq, sizeof(mrq)) < 0) return false;
priolen = sizeof(prioval);
prioval = 20;
if(setsockopt(fd_socket_rx, SOL_SOCKET, SO_PRIORITY, &prioval, priolen) < 0) return false;
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
if(setsockopt(fd_socket_rx, SOL_PACKET, PACKET_IGNORE_OUTGOING, &enable, sizeof(int)) < 0) fprintf(stdout, "PACKET_IGNORE_OUTGOING is not supported by kernel\nfalling back to validate radiotap header length\n");
#endif
if(bpf.len > 0)
	{
	if(setsockopt(fd_socket_rx, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
		{
		fprintf(stdout, "failed to attach BPF (SO_ATTACH_FILTER): %s\n", strerror(errno));
		}
	}
memset(&saddr, 0, sizeof(saddr));
saddr.sll_family = AF_PACKET;
saddr.sll_ifindex = interfaceakt.ifindex;
saddr.sll_protocol = htons(ETH_P_ALL);
saddr.sll_halen = ETH_ALEN;
saddr.sll_pkttype = PACKET_OTHERHOST;
if(bind(fd_socket_rx, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) return false;
if((socket_rx_flags = fcntl(fd_socket_rx, F_GETFL, 0)) < 0) return false;
if(fcntl(fd_socket_rx, F_SETFL, socket_rx_flags | O_NONBLOCK) < 0) return false;
while((!eventflag) || (c != 0))
	{
	if((rv = read(fd_socket_rx, packetptr, SNAPLEN)) == -1) break;
	c--;
	}
return true;
}
/*---------------------------------------------------------------------------*/
static bool open_socket_tx(void)
{
static struct sockaddr_ll saddr;
static struct packet_mreq mrq;
static int socket_tx_flags;
static int prioval;
static socklen_t priolen;

if((fd_socket_tx = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL))) < 0) return false;
memset(&mrq, 0, sizeof(mrq));
mrq.mr_ifindex = interfaceakt.ifindex;
mrq.mr_type = PACKET_MR_PROMISC;
if(setsockopt(fd_socket_tx, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mrq, sizeof(mrq)) < 0) return false;
priolen = sizeof(prioval);
prioval = 20;
if(setsockopt(fd_socket_tx, SOL_SOCKET, SO_PRIORITY, &prioval, priolen) < 0) return false;
memset(&saddr, 0, sizeof(saddr));
saddr.sll_family = AF_PACKET;
saddr.sll_ifindex = interfaceakt.ifindex;
saddr.sll_protocol = htons(ETH_P_ALL);
saddr.sll_halen = ETH_ALEN;
saddr.sll_pkttype = PACKET_OTHERHOST;
if(bind(fd_socket_tx, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) return false;
if((socket_tx_flags = fcntl(fd_socket_tx, F_GETFL, 0)) < 0) return false;
if(fcntl(fd_socket_tx, F_SETFL, socket_tx_flags | O_NONBLOCK) < 0) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool init_raw_sockets(char *bpfname)
{
if(open_socket_rx(bpfname) == false)
	{
	fprintf(stdout, "failed to open raw packet socket\n");
	return false;
	}
if(open_socket_tx() == false)
	{
	fprintf(stdout, "failed to open transmit socket\n");
	return false;
	}
return true;
}
/*===========================================================================*/
/* NETLINK */
static struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
int totlen = NLA_ALIGN(nla->nla_len);

*remaining -= totlen;
return (struct nlattr*)((u8*)nla + totlen);
}
/*---------------------------------------------------------------------------*/
static int nla_ok(const struct nlattr *nla, int remaining)
{
size_t r = remaining;

return r >= sizeof(*nla) && nla->nla_len >= sizeof(*nla) && nla->nla_len <= r;
}
/*---------------------------------------------------------------------------*/
static int nla_datalen(const struct nlattr *nla)
{
return nla->nla_len - NLA_HDRLEN;
}
/*---------------------------------------------------------------------------*/
static bool nl_set_reregdomain(void)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;

i = 0;
memset(nltxbuffer, 0, NLTX_SIZE);
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = pid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_REQ_SET_REG;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 7;
nla->nla_type = NL80211_ATTR_REG_ALPHA2;
memcpy(nla_data(nla), regdbin, sizeof(regdbin));
i += 8;
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			return false;
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool nl_add_interface_rogue1(u32 wiphyadd)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;

i = 0;
memset(nltxbuffer, 0, NLTX_SIZE);
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = pid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_NEW_INTERFACE;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_WIPHY;
*(u32*)nla_data(nla) = wiphyadd;
i += 8;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 11;
nla->nla_type = NL80211_ATTR_IFNAME;
memcpy(nla_data(nla), rogue1, sizeof(rogue1));
i += 12;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_IFTYPE;
*(u32*)nla_data(nla) = NL80211_IFTYPE_MONITOR;
i += 8;
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			return false;
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool nl_del_interface(u32 ifindexdel)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;

i = 0;
memset(nltxbuffer, 0, NLTX_SIZE);
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = pid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_DEL_INTERFACE;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_IFINDEX;
*(u32*)nla_data(nla) = ifindexdel;
i += 8;
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			return false;
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static size_t nl_get_interfacelist(interface_t *interfacelist)
{
static ssize_t i;
static ssize_t msglen;
static size_t ifc;
static int nlremlen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;

i = 0;
nlremlen = 0;
memset(nltxbuffer, 0, NLTX_SIZE);
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = pid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_GET_INTERFACE;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return 0;
ifc = 0;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return ifc;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return ifc;
			return 0;
			}
		glh = (struct genlmsghdr*)NLMSG_DATA(nlh);
		if(glh->cmd != NL80211_CMD_NEW_INTERFACE) continue;
		nla = (struct nlattr*)((unsigned char*)NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen = NLMSG_PAYLOAD(nlh, 0) -4;
		if(ifc >= INTERFACE_MAX) return ifc;
		while(nla_ok(nla, nlremlen))
			{
			if(nla->nla_type == NL80211_ATTR_WIPHY) (interfacelist + ifc)->wiphy = *(u32*)nla_data(nla);
			if(nla->nla_type == NL80211_ATTR_IFINDEX) (interfacelist + ifc)->ifindex = *(u32*)nla_data(nla);
			if(nla->nla_type == NL80211_ATTR_IFTYPE)
				{
				(interfacelist + ifc)->iftype = *(u32*)nla_data(nla);
				if(*((u32*)nla_data(nla)) == NL80211_IFTYPE_MONITOR) (interfacelist + ifc)->modeakt = MODE_MONITOR;
				}
			if((nla->nla_type == NL80211_ATTR_IFNAME) && (nla->nla_len <= IFNAMSIZ + 4))
					{
					(interfacelist + ifc)->ifnamlen = nla->nla_len - 4;
					memcpy((interfacelist + ifc)->ifnam, (u8*)nla_data(nla), nla->nla_len - 4);
					}
			if((nla->nla_type == NL80211_ATTR_MAC) && (nla->nla_len == 10)) memcpy((interfacelist + ifc)->vimac, nla_data(nla), ETH_ALEN);
			nla = nla_next(nla, &nlremlen);
			}
		ifc++;
		}
	}
return 0;
}
/*---------------------------------------------------------------------------*/
static u8 nl_get_supported_iftypes(struct nlattr* nla)
{
struct nlattr *pos = (struct nlattr*)nla_data(nla);
int nestremlen = nla_datalen(nla);
while(nla_ok(pos, nestremlen))
	{
	if(pos->nla_type == NL80211_IFTYPE_MONITOR) return MODE_MONITOR;
	pos = nla_next(pos, &nestremlen);
	}
return 0;
}
/*---------------------------------------------------------------------------*/
static size_t nl_get_wiphylist(interface_t *interfacelist)
{
static ssize_t msglen;
static ssize_t i;
static size_t ifc;
static int nlremlen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;

memset(nltxbuffer, 0, NLTX_SIZE);
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = pid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_GET_WIPHY;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 4;
nla->nla_type = NL80211_ATTR_SPLIT_WIPHY_DUMP;
i += 4;
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return 0;
ifc = 0;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	if(ifc >= INTERFACE_MAX) return ifc;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return ifc;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return ifc;
			return 0;
			}
		nlremlen = 0;
		glh = (struct genlmsghdr*)NLMSG_DATA(nlh);
		if(glh->cmd != NL80211_CMD_NEW_WIPHY) continue;
		nla = (struct nlattr*)((unsigned char*)NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen = NLMSG_PAYLOAD(nlh, 0) -4;
		while(nla_ok(nla, nlremlen))
			{
			if(nla->nla_type == NL80211_ATTR_WIPHY) (interfacelist + ifc)->wiphy = *(u32*)nla_data(nla);
			if((nla->nla_type == NL80211_ATTR_WIPHY_NAME) && (nla->nla_len < (NL80211_WIPHY_NAME_MAXLEN +4)))
					{
					(interfacelist + ifc)->wiphynamelen = nla->nla_len - 4;
					memcpy((interfacelist + ifc)->wiphyname, nla_data(nla), nla->nla_len - 4);
					}
			if(nla->nla_type == NL80211_ATTR_SUPPORTED_IFTYPES) (interfacelist + ifc)->mode |= nl_get_supported_iftypes(nla);
			if(nla->nla_type == NL80211_ATTR_FEATURE_FLAGS)
				{
				if((*((u32*)nla_data(nla)) & NL80211_FEATURE_ACTIVE_MONITOR) == NL80211_FEATURE_ACTIVE_MONITOR) (interfacelist + ifc)->mode |= MODE_ACTIVE;
				}
			nla = nla_next(nla, &nlremlen);
			}
		}
	ifc++;
	}
return 0;
}
/*---------------------------------------------------------------------------*/
static size_t nl_get_protocol_features(void)
{
static ssize_t i;
static ssize_t msglen;
static int nlremlen;
static u32 pfret;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;

i = 0;
nlremlen = 0;
pfret = 0;
memset(nltxbuffer, 0, NLTX_SIZE);
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily;
nlh->nlmsg_flags = NLM_F_REQUEST| NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = pid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_GET_PROTOCOL_FEATURES;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return pfret;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return pfret;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return pfret;
			return 0;
			}
		glh = (struct genlmsghdr*)NLMSG_DATA(nlh);
		if(glh->cmd != NL80211_CMD_GET_PROTOCOL_FEATURES) continue;
		nla = (struct nlattr*)((unsigned char*)NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen = NLMSG_PAYLOAD(nlh, 0) -4;
		while(nla_ok(nla, nlremlen))
			{
			if(nla->nla_type == NL80211_ATTR_PROTOCOL_FEATURES) pfret = *((u32*)nla_data(nla));
			nla = nla_next(nla, &nlremlen);
			}
		}
	}
return pfret;
}
/*---------------------------------------------------------------------------*/
static bool nl_get_familyid(void)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;
static int nlremlen = 0;

i = 0;
nlfamily = 0;
memset(nltxbuffer, 0, NLTX_SIZE);
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = GENL_ID_CTRL;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = pid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = CTRL_CMD_GETFAMILY;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_type = CTRL_ATTR_FAMILY_NAME;
i += sizeof(struct nlattr);
memcpy(nltxbuffer + i, NL80211_GENL_NAME, sizeof(NL80211_GENL_NAME));
i += sizeof(NL80211_GENL_NAME);
nla->nla_len = sizeof(struct nlattr) + sizeof(NL80211_GENL_NAME);
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			nlfamily = 0;
			return false;
			}
		glh = (struct genlmsghdr*)NLMSG_DATA(nlh);
		nla = (struct nlattr*)((unsigned char*)NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen = 0;
		nlremlen = NLMSG_PAYLOAD(nlh, 0) -4;
		while(nla_ok(nla, nlremlen))
			{
			if(nla->nla_type == CTRL_ATTR_FAMILY_ID) nlfamily = *((u16*)nla_data(nla));
			nla = nla_next(nla, &nlremlen);
			}
		}
	}
nlfamily = 0;
return false;
}
/*---------------------------------------------------------------------------*/
static bool open_socket_nl(void)
{
static struct sockaddr_nl saddr;
static int nltxbuffsize = NLTX_SIZE;
static int nlrxbuffsize = NLRX_SIZE;

if((fd_socket_nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC)) < 0) return false;
if(setsockopt(fd_socket_nl, SOL_SOCKET, SO_SNDBUF, &nltxbuffsize, sizeof(nltxbuffsize)) < 0) return false;
if(setsockopt(fd_socket_nl, SOL_SOCKET, SO_RCVBUF, &nlrxbuffsize, sizeof(nlrxbuffsize)) < 0) return false;
if(fcntl(fd_socket_nl, F_SETFL, O_NONBLOCK) < 0) return false;
memset(&saddr, 0, sizeof(saddr));
saddr.nl_family = AF_NETLINK;
saddr.nl_pid = pid;
if(bind(fd_socket_nl, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) return false;
return true;
}
/*===========================================================================*/
/* RTLINK */
static void *rta_data(const struct rtattr *rta)
{
return (u8*)rta +4;
}
/*---------------------------------------------------------------------------*/
static bool rt_set_interface_up(void)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct ifinfomsg *ifih;
static struct nlmsgerr *nle;

i = 0;
memset(nltxbuffer, 0, NLTX_SIZE);
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = RTM_NEWLINK;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = pid;
i += sizeof(struct nlmsghdr);
ifih = (struct ifinfomsg*)(nltxbuffer + i);
ifih->ifi_family = 0;
ifih->ifi_type = 0;
ifih->ifi_index = interfaceakt.ifindex;
ifih->ifi_flags = IFF_UP;
ifih->ifi_change = 1;
i += sizeof(struct ifinfomsg);
nlh->nlmsg_len = i;
if((write(fd_socket_rt, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_rt, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return false;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			return false;
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool rt_set_interfacemac(void)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct ifinfomsg *ifih;
static struct rtattr *rta;
static struct nlmsgerr *nle;

i = 0;
memset(nltxbuffer, 0, NLTX_SIZE);
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = RTM_NEWLINK;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = pid;
i += sizeof(struct nlmsghdr);
ifih = (struct ifinfomsg*)(nltxbuffer + i);
ifih->ifi_family = 0;
ifih->ifi_type = 0;
ifih->ifi_index = interfaceakt.ifindex;
ifih->ifi_flags = 0;
ifih->ifi_change = 0;
i += sizeof(struct ifinfomsg);
rta = (struct rtattr*)(nltxbuffer + i);
rta->rta_len = 10;
rta->rta_type = IFLA_ADDRESS;
memcpy(rta_data(rta), macclrg, ETH_ALEN);
i += 12;
nlh->nlmsg_len = i;
if((write(fd_socket_rt, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_rt, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return false;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			return false;
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool rt_get_interface_rogue1(interface_t *interfacelist)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct ifinfomsg *ifih;
static struct nlmsgerr *nle;
static struct rtattr *rta;
static int rtaremlen;

i = 0;
memset(nltxbuffer, 0, NLTX_SIZE);
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = RTM_GETLINK;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = pid;
i += sizeof(struct nlmsghdr);
ifih = (struct ifinfomsg*)(nltxbuffer + i);
ifih->ifi_family = AF_PACKET;
ifih->ifi_type = 0;
ifih->ifi_index = 0;
ifih->ifi_flags = 0;
ifih->ifi_change = 0;
i += sizeof(struct ifinfomsg);
rta = (struct rtattr*)(nltxbuffer + i);
rta->rta_type = IFLA_EXT_MASK;
*(u32*)rta_data(rta) = 1;
rta->rta_len = 8;
i += 8;
rta = (struct rtattr*)(nltxbuffer + i);
rta->rta_len = 11;
rta->rta_type = IFLA_IFNAME;
memcpy(rta_data(rta), rogue1, sizeof(rogue1));
i += 12;
nlh->nlmsg_len = i;
if((write(fd_socket_rt, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_rt, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			return false;
			}
		ifih = (struct ifinfomsg*)NLMSG_DATA(nlh);
		if((ifih->ifi_flags & IFF_UP) == IFF_UP) (interfacelist)->flags |= IFF_UP;
		rta = (struct rtattr*)((unsigned char*)NLMSG_DATA(nlh) + sizeof(struct ifinfomsg));
		rtaremlen = NLMSG_PAYLOAD(nlh, 0) - sizeof(struct ifinfomsg);
		while(RTA_OK(rta, rtaremlen))
			{
			#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
			if((rta->rta_type == IFLA_PERM_ADDRESS) && (rta->rta_len == 10)) memcpy((interfacelist)->hwmac, rta_data(rta), ETH_ALEN);
			#else
			if((rta->rta_type == IFLA_ADDRESS) && (rta->rta_len == 10)) memcpy((interfacelist)->hwmac, rta_data(rta), ETH_ALEN);
			#endif
			rta = RTA_NEXT(rta, rtaremlen);
			}
		}
	}
return false;
}
/*===========================================================================*/
static bool open_socket_rt(void)
{
static struct sockaddr_nl saddr;
static int nltxbuffsize = NLTX_SIZE;
static int nlrxbuffsize = NLRX_SIZE;

if((fd_socket_rt = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)) < 0) return false;
if(setsockopt(fd_socket_rt, SOL_SOCKET, SO_SNDBUF, &nltxbuffsize, sizeof(nltxbuffsize)) < 0) return false;
if(setsockopt(fd_socket_rt, SOL_SOCKET, SO_RCVBUF, &nlrxbuffsize, sizeof(nlrxbuffsize)) < 0) return false;
memset(&saddr, 0, sizeof(saddr));
saddr.nl_family = AF_NETLINK;
saddr.nl_pid = getpid();
if(bind(fd_socket_rt, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) return false;
return true;
}
/*===========================================================================*/
static void set_ftc(void)
{
static struct timespec tsakt = { 0 };
static struct timespec tssaved = { 0 };
static int fd_fakeclock = 0;

clock_gettime(CLOCK_REALTIME, &tsakt);
if((fd_fakeclock = open("/home/.hcxftc", O_RDONLY)) > 0)
	{
	if(read(fd_fakeclock, &tssaved, sizeof(struct timespec)) == sizeof(struct timespec))
		{
		if(tsakt.tv_sec < tssaved.tv_sec) clock_settime(CLOCK_REALTIME, &tssaved);
		}
	close(fd_fakeclock);
	}
return;
}
/*---------------------------------------------------------------------------*/
static void save_ftc(void)
{
static struct timespec tsakt = { 0 };
static int fd_fakeclock = 0;

clock_gettime(CLOCK_REALTIME, &tsakt);
if((fd_fakeclock = open("/home/.hcxftc", O_WRONLY | O_TRUNC | O_CREAT, 0644)) > 0)
	{
	if(write(fd_fakeclock, &tsakt, sizeof(struct timespec)) != sizeof(struct timespec)) fprintf(stdout, "failed to write timestamp\n");
	fsync(fd_fakeclock);
	close(fd_fakeclock);
	}
return;
}
/*===========================================================================*/
static bool init_interface_rogue1(u32 phyidx)
{
static size_t ifc;
static size_t c;
static interface_t *interfacelist; 

if(open_socket_nl() == false) return false;
if(open_socket_rt() == false) return false;
if(nl_get_familyid() == false) return false;
if(nl_set_reregdomain() == false) return false;
if(nl_get_protocol_features() != 1) return false;
if((interfacelist = (interface_t*)calloc(INTERFACE_MAX, INTERFACE_SIZE)) == NULL) return false;
if((ifc = nl_get_interfacelist(interfacelist)) != 0)
	{
	for(c = 0; c < ifc; c++)
		{
		fprintf(stdout, "removing phy: %2u ifindex: %2u ifname: %.*s\n", (interfacelist + c)->wiphy, (interfacelist + c)->ifindex, (int)(interfacelist + c)->ifnamlen, (interfacelist + c)->ifnam);
		if(nl_del_interface((interfacelist + c)->ifindex) == false)
			{
			free(interfacelist);
			return false;
			}
		}
	}
for(c = 0; c < INTERFACE_MAX; c++) memset((interfacelist + c), 0, INTERFACE_SIZE);
if((ifc = nl_get_wiphylist(interfacelist)) == 0)
	{
	free(interfacelist);
	return false;
	}
qsort(interfacelist, ifc, INTERFACE_SIZE, sort_interface_by_mode);
if(phyidx != 0xffffffff)
	{
	if(nl_add_interface_rogue1(phyidx) == false) return false;
	}
else
	{
	if(nl_add_interface_rogue1((interfacelist)->wiphy) == false) return false;
	}
for(c = 0; c < INTERFACE_MAX; c++) memset((interfacelist + c), 0, INTERFACE_SIZE);
if((ifc = nl_get_interfacelist(interfacelist)) == 0)
	{
	free(interfacelist);
	return false;
	}
if(interfacelist->modeakt != MODE_MONITOR)
	{
	free(interfacelist);
	return false;
	}
interfaceakt.ifindex = interfacelist->ifindex;
interfaceakt.wiphy = (interfacelist)->wiphy;
memcpy(interfaceakt.vimac, (interfacelist)->vimac, ETH_ALEN);
memcpy(interfaceakt.ifnam, rogue1, sizeof(rogue1));
if(rt_set_interfacemac() == false)
	{
	free(interfacelist);
	return false;
	}
if(rt_set_interface_up() == false)
	{
	free(interfacelist);
	return false;
	}
if(rt_get_interface_rogue1(interfacelist) == false)
	{
	free(interfacelist);
	return false;
	}
if(interfacelist->flags != IFF_UP)
	{
	free(interfacelist);
	return false;
	}
memcpy(interfaceakt.hwmac, (interfacelist)->hwmac, ETH_ALEN);
if(interfacelist != NULL) free(interfacelist);
fprintf(stdout, "using    phy: %2u ifindex: %2u ifname: %s\n", interfaceakt.wiphy, interfaceakt.ifindex, interfaceakt.ifnam);
return true;
}
/*===========================================================================*/
static u16 frequency_to_channel(u32 frequency)
{
if(frequency == 2484) return 14;
else if(frequency < 2484) return (frequency - 2407) / 5;
else if(frequency >= 4910 && frequency <= 4980) return (frequency - 4000) / 5;
else if(frequency < 5925) return (frequency - 5000) / 5;
else if(frequency == 5935) return 2;
else if(frequency <= 45000) return (frequency - 5950) / 5;
else if(frequency >= 58320 && frequency <= 70200) return (frequency - 56160) / 2160;
else return 0;
}
/*---------------------------------------------------------------------------*/
static u32 channel_to_frequency(u16 channel, char band)
{
if(channel <= 0) return 0;
switch(band)
	{
	case 'a':
	if(channel == 14) return 2484;
	else if (channel < 14) return 2407 + (channel * 5);
	break;

	case 'b':
	if(channel >= 182 && channel <= 196) return 4000 + (channel * 5);
	else return 5000 + channel * 5;
	break;

	#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
	case 'c':
	if(channel == 2) return 5935;
	if(channel <= 233) return 5950 + (channel * 5);
	break;

	case 'd':
	if(channel < 7) return 56160 + (channel * 2160);
	break;

	case 'e':
	return 902000 + (channel * 500);
	#endif
	}
return 0;
}
/*---------------------------------------------------------------------------*/
static void init_scanlist(char *scanlist)
{
static char *sres = NULL;
static char *spos = NULL;
static char *band = NULL;
static size_t c;
static u32 sval = 0;
static u32 frequency = 0;

fi = 0;
sres = scanlist;
while((spos = strsep(&sres, ",")) != NULL)
	{
	frequency = 0;
	sval = strtoul(spos, &band, 10);
	if(*band != '\0') frequency = channel_to_frequency(sval, band[0]);
	else frequency = sval;
	for(c = 0; c < ENTRIES(frequencies); c++)
		{
		if(frequency == frequencies[c])
			{
			(frequencylist + fi)->channel = frequency_to_channel(frequency);
			(frequencylist + fi)->frequency = frequency;
			fi++;
			if(fi > (FREQUENCYLIST_MAX - 2)) return;
			break;
			}
		}
	}
return;
}
/*===========================================================================*/
static bool open_dumpfile(void)
{
static struct timespec tsakt = { 0 };
static struct stat statinfo;
static char dumpname[PATH_MAX];

clock_gettime(CLOCK_REALTIME, &tsakt);
snprintf(dumpname, PATH_MAX, "%lld.pcapng", (long long int)tsakt.tv_sec);
while(stat(dumpname, &statinfo) == 0)
	{
	tsakt.tv_sec += 1;
	snprintf(dumpname, PATH_MAX, "%lld.pcapng", (long long int)tsakt.tv_sec);
	}
if((fd_pcapng = open(dumpname, O_WRONLY | O_TRUNC | O_CREAT, 0666)) < 0) return false;
if(writeshb() == false) return false;
if(writeidb() == false) return false;
if(writecb() == false) return false;
return true;
}
/*===========================================================================*/
static bool init_values(void)
{
static struct timespec tsakt;
static size_t i;

packetptr = &epb[EPB_SIZE];
clock_gettime(CLOCK_REALTIME, &tsakt);
seed += (unsigned int) tsakt.tv_nsec & 0xffffffff;
srand(seed);
ouiclrg = (vendorclientrg[rand() % ((VENDORCLIENTRG_SIZE / sizeof(int)))]) &0xffffff;
nicclrg = rand() & 0xffffff;
macclrg[5] = nicclrg & 0xff;
macclrg[4] = (nicclrg >> 8) & 0xff;
macclrg[3] = (nicclrg >> 16) & 0xff;
macclrg[2] = ouiclrg & 0xff;
macclrg[1] = (ouiclrg >> 8) & 0xff;
macclrg[0] = (ouiclrg >> 16) & 0xff;
memcpy(&tx_proberequest[22], macclrg, ETH_ALEN);

ouiaprg = (vendoraprg[rand() % ((VENDORAPRG_SIZE / sizeof(int)))]) &0xffffff;
nicaprg = rand() & 0xffffff;
macaprg[5] = nicaprg & 0xff;
macaprg[4] = (nicaprg >> 8) & 0xff;
macaprg[3] = (nicaprg >> 16) & 0xff;
macaprg[2] = ouiaprg & 0xff;
macaprg[1] = (ouiaprg >> 8) & 0xff;
macaprg[0] = (ouiaprg >> 16) & 0xff;

replaycountrg = (rand() % 0xfff) + 0xf000;
tx_eapolm1_wpa1[EAPOLM1_OFFSET + 60] = replaycountrg & 0xff;
tx_eapolm1_wpa1[EAPOLM1_OFFSET + 59] = (replaycountrg >> 8) & 0xff;
tx_eapolm1_wpa2[EAPOLM1_OFFSET + 60] = replaycountrg & 0xff;
tx_eapolm1_wpa2[EAPOLM1_OFFSET + 59] = (replaycountrg >> 8) & 0xff;

for(i = 0; i < 32; i++)
	{
	anoncerg[i] = rand() % 0xff;
	snoncerg[i] = rand() % 0xff;
	}
memcpy(&tx_eapolm1_wpa1[EAPOLM1_OFFSET + 61], anoncerg, 32);
memcpy(&tx_eapolm1_wpa2[EAPOLM1_OFFSET + 61], anoncerg, 32);
memcpy(&tx_eapolm1_wpa2v3[EAPOLM1_OFFSET + 61], anoncerg, 32);

if((frequencylist = (frequencylist_t*)calloc(FREQUENCYLIST_MAX, FREQUENCYLIST_SIZE)) == NULL) return false;

if((conlist = (conlist_t*)calloc(CONLIST_MAX, CONLIST_SIZE)) == NULL) return false;
for(i = 0; i < CONLIST_MAX; i++)
	{
	if(((conlist + i)->condata = (condata_t*)calloc(1, CONDATA_SIZE)) == NULL) return false;
	}

if((aprglist = (aplist_t*)calloc(ESSIDLIST_MAX, APLIST_SIZE)) == NULL) return false;
for(i = 0; i < ESSIDLIST_MAX; i++)
	{
	if(((aprglist + i)->apdata = (apdata_t*)calloc(1, APDATA_SIZE)) == NULL) return false;
	}

if((apprdlist = (aplist_t*)calloc(APLIST_MAX, APLIST_SIZE)) == NULL) return false;
for(i = 0; i < APLIST_MAX; i++)
	{
	if(((apprdlist + i)->apdata = (apdata_t*)calloc(1, APDATA_SIZE)) == NULL) return false;
	}

if((apprlist = (aplist_t*)calloc(APLIST_MAX, APLIST_SIZE)) == NULL) return false;
for(i = 0; i < APLIST_MAX; i++)
	{
	if(((apprlist + i)->apdata = (apdata_t*)calloc(1, APDATA_SIZE)) == NULL) return false;
	}

if((apbclist = (aplist_t*)calloc(APLIST_MAX, APLIST_SIZE)) == NULL) return false;
for(i = 0; i < APLIST_MAX; i++)
	{
	if(((apbclist + i)->apdata = (apdata_t*)calloc(1, APDATA_SIZE)) == NULL) return false;
	}

for(i = 0; i < (sizeof(preinitessid) / sizeof(char*)); i++)
	{
	(aprglist + i)->sec = tsakt.tv_sec - i;
	(aprglist + i)->apdata->essidlen = (u8)strlen(preinitessid[i]);
	memcpy((aprglist + i)->apdata->essid, preinitessid[i], (aprglist + i)->apdata->essidlen);
	(aprglist + i)->apdata->macap[5] = nicaprg & 0xff;
	(aprglist + i)->apdata->macap[4] = (nicaprg >> 8) & 0xff;
	(aprglist + i)->apdata->macap[3] = (nicaprg >> 16) & 0xff;
	(aprglist + i)->apdata->macap[2] = ouiaprg & 0xff;
	(aprglist + i)->apdata->macap[1] = (ouiaprg >> 8) & 0xff;
	(aprglist + i)->apdata->macap[0] = (ouiaprg >> 16) & 0xff;
	nicaprg++;
	}
return true;
}
/*===========================================================================*/
/* RASPBERRY PI */
static bool init_rpi(void)
{
static FILE *modinfo = NULL;
static FILE *procinfo = NULL;
static int fd_devinfo = 0;
static int len = 0;
static unsigned int gpioperibase = 0;
static char linein[RASPBERRY_INFO] = { 0 };

gpio_map = MAP_FAILED;
if((modinfo = fopen("/proc/device-tree/model", "r")) == NULL) return false;
len = fgetline(modinfo, RASPBERRY_INFO, linein);
fclose(modinfo);
if(len < RPINAME_SIZE) return false;
if(memcmp(rpiname, linein, RPINAME_SIZE) != 0) return false;
if((procinfo = fopen("/proc/cpuinfo", "r")) != NULL)
	{
	while(1)
		{
		if((len = fgetline(procinfo, RASPBERRY_INFO, linein)) == -1) break;
		if(len > 8)
			{
			if(strstr(linein, "Serial") != NULL) seed += strtoul(&linein[len - 6], NULL, 16);
			}
		}
	fclose(procinfo);
	}
if((fd_devinfo = open("/dev/gpiomem", O_RDWR | O_SYNC)) > 0)
	{
	gpio_map = mmap(NULL, RPI_BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd_devinfo, gpioperibase);
	close(fd_devinfo);
	}
else
	{
	if((procinfo = fopen("/proc/iomem", "r")) != NULL)
		{
		while(1)
			{
			if((len = fgetline(procinfo, RASPBERRY_INFO, linein)) == -1) break;
			if(strstr(linein, ".gpio") != NULL)
				{
				if(linein[8] != '-') break;
					{
					linein[8] = 0;
					gpioperibase = strtoul(linein, NULL, 16);
					if(gpioperibase != 0)
						{
						if((fd_devinfo = open("/dev/mem", O_RDWR | O_SYNC)) > 0)
							{
							gpio_map = mmap(NULL, RPI_BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd_devinfo, gpioperibase);
							close(fd_devinfo);
							}
						}
					break;
					}
				}
			}
		fclose(procinfo);
		}
	}
if(gpio_map == MAP_FAILED)
	{
	fprintf(stdout, "failed to map GPIO memory\n");
	return false;
	}
gpio = (volatile unsigned *)gpio_map;
INP_GPIO(GPIO_LED);
OUT_GPIO(GPIO_LED);
INP_GPIO(GPIO_BUTTON);
return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
fprintf(stdout, "%s %s  (C) %s ZeroBeat\n"
	"usage: %s <options>\n\n"
	"most common options:\n"
	"--------------------\n"
	"p <phy index> : use this physical interface\n"
	"b <file>      : input Berkeley Packet Filter (BPF) code file in tcpdump decimal numbers format\n"
	"s <seconds>   : stay time on channel in seconds\n"
	"t <minutes>   : TOT time in minutes\n"
	"T <event>     : exit on TOT\n"
	"                 reboot\n"
	"                 poweroff\n"
	"w <minutes>   : watchdog time out in minutes\n"
	"W <event>     : exit on watchdog\n"
	"                 reboot\n"
	"                 poweroff\n"
	"E <event>     : exit on ERROR\n"
	"                 reboot\n"
	"                 poweroff\n"
	"I <event>     : exit on init ERROR\n"
	"                 reboot\n"
	"                 poweroff\n"
	"l <seconds>   : status LED interval\n"
	"f <digit>     : frequency or channel & band\n"
	"e <file>      : ESSID list\n"
	"D             : disable DEAUTHENTICATION, DISASSOCIATION and AUTHENTICATIONREQUEST\n"
	"S             : show very limited realtime display\n"
	"d             : daemonize\n"
	"                 to terminate %s send SIGTERM to its PID\n"
	"                 or press push button (modified Raspberry Pi)\n"
	"\n",
	eigenname, VERSION_TAG, VERSION_YEAR, eigenname, eigenname);
fprintf(stdout, "less common options:\n--------------------\n"
	"--help        : show additional help (example and trouble shooting)\n"
	"--version     : show version\n\n");
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s by ZeroBeat\n"
	"This is a penetration testing tool!\n"
	"It is made to detect vulnerabilities in your NETWORK mercilessly!\n"
	"\n"
	"usage:\n"
	" $ %s -h for an overview of all options\n"
	" $ %s --help for an example and trouble shooting\n",
	 eigenname, VERSION_TAG, VERSION_YEAR, eigenname, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl = -1;
static int index = 0;

static struct timespec slp = { 0 }; 
static u32 phyidx = 0xffffffff;

static bool rpi = false;
static bool daemon = false;
static char *bpfname = NULL;
static char *scanlist = NULL;
static char *exitwatchdog = NULL;
static char *exittot = NULL;
static char *exiterror = NULL;
static char *exitiniterror = NULL;
static char *essidlistname = NULL;

static const char *short_options = "p:b:s:t:T:w:W:E:I:l:f:e:DSdhv";
static const struct option long_options[] =
{
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};
optind = 1;
optopt = 0;
while((auswahl = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_PHY_IDX:
		phyidx = strtol(optarg, NULL, 10);
		break;

		case HCX_BPF:
		bpfname = optarg;
		break;

		case HCX_STAY_TIME:
		timer1_vsec = strtol(optarg, NULL, 10);
		timer1_isec = strtol(optarg, NULL, 10);
		break;

		case HCX_WATCHDOG:
		timer2_vsec = strtol(optarg, NULL, 10) * 60;
		timer2_isec = strtol(optarg, NULL, 10) * 60;
		break;

		case HCX_EXIT_WATCHDOG:
		exitwatchdog = optarg;
		break;

		case HCX_TOT:
		timer3_vsec = strtoll(optarg, NULL, 10) * 60;
		timer3_isec = strtoll(optarg, NULL, 10) * 60;
		break;

		case HCX_EXIT_TOT:
		exittot = optarg;
		break;

		case HCX_EXIT_ERROR:
		exiterror = optarg;
		break;

		case HCX_EXIT_INIT_ERROR:
		exitiniterror = optarg;
		break;

		case HCX_LED:
		timer4_vsec = strtol(optarg, NULL, 10);
		timer4_isec = strtol(optarg, NULL, 10);
		break;

		case HCX_FREQUENCY:
		scanlist = optarg;
		break;

		case HCX_ESSID_LIST:
		essidlistname = optarg;
		break;

		case HCX_DISABLE_DE_AUTH:
		deauthflag = true;
		break;

		case HCX_RDS:
		rdsflag = true;
		break;

		case HCX_DAEMON:
		daemon = true;
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

		default:
		usageerror(basename(argv[0]));
		}
	}
if((uid = getuid()) != 0)
	{
	fprintf(stdout, "%s must be run as root\n", basename(argv[0]));
	return EXIT_FAILURE;
	}
if(daemon == true)
	{
	if((pid = fork()) < 0)
		{
		fprintf(stdout, "failed to daemonize %s\n", basename(argv[0]));
		return EXIT_FAILURE;
		}
	if(pid > 0)
		{
		fprintf(stdout, "daemonize %s (pid: %d)\n", basename(argv[0]), pid);
		return EXIT_SUCCESS;
		}
	if((sid = setsid()) < 0)
		{
		fprintf(stdout, "failed to daemonize %s\n", basename(argv[0]));
		return EXIT_FAILURE;
		}
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	}
else pid = getpid();
umask(0);
if((rpi = init_rpi()) == true)
	{
	set_ftc();
	if(GET_GPIO(GPIO_BUTTON) > 0)
		{
		GPIO_SET = 1 << GPIO_LED;
		return EXIT_SUCCESS;
		}
	if(chdir("/home/dumpfiles/") != 0)
		{
		eventflag |= EVENT_INIT_ERROR;
		goto byebye;
		}
	}
else fprintf(stdout, "Raspberry Pi not detected\n");
if(init_signal_handler() == false)
	{
	fprintf(stdout, "failed to initialize signal handler\n");
	goto byebye;
	}
fprintf(stdout, "init signal handle done\n");
if(init_values() == false)
	{
	fprintf(stdout, "initialization of lists and values failed\n");
	eventflag |= EVENT_INIT_ERROR;
	goto byebye;
	}
fprintf(stdout, "init pi done\n");
if(scanlist != NULL) init_scanlist(scanlist);
if(fi == 0)
	{
	frequencylist->frequency = 2412;
	frequencylist->channel = 1;
	(frequencylist + 1)->frequency = 2437;
	(frequencylist + 1)->channel = 6;
	(frequencylist + 2)->frequency = 2462;
	(frequencylist + 2)->channel = 11;
	fi = 3;
	}
if(fi == 1)
	{
	timer1_vsec = 0;
	timer1_vnsec = 0;
	timer1_isec = 0;
	timer1_insec = 0;
	}
fprintf(stdout, "init scanlist done\n");
if(essidlistname != NULL) read_essidlist(essidlistname); 
fprintf(stdout, "init essidlist done\nwaiting 10 seconds for interface to be ready\n");
slp.tv_sec = 10;
if(nanosleep(&slp, NULL) == -1) 
	{
	fprintf(stdout, "nanosleep failed\n");
	eventflag |= EVENT_INIT_ERROR;
	goto byebye;
	}
if(init_interface_rogue1(phyidx) == false)
	{
	fprintf(stdout, "initialization of Interface failed\n");
	eventflag |= EVENT_INIT_ERROR;
	goto byebye;
	}
fprintf(stdout, "init interface done\n");
if(init_raw_sockets(bpfname) == false)
	{
	fprintf(stdout, "initialization of raw packet sockets failed\n");
	eventflag |= EVENT_INIT_ERROR;
	goto byebye;
	}
fprintf(stdout, "init sockets done\n");

if(init_timer() == false)
	{
	fprintf(stdout, "initialization of timer failed\n");
	eventflag |= EVENT_INIT_ERROR;
	goto byebye;
	}
fprintf(stdout, "init timer done\n");

if(open_dumpfile() == false)
	{
	fprintf(stdout, "failed to open hcxpcap file\n");
	eventflag |= EVENT_INIT_ERROR;
	}
fprintf(stdout, "open dumpfile done\n");

if(scanloop() == false)
	{
	fprintf(stdout, "scan loop error\n");
	eventflag |= EVENT_SCANLOOP_ERROR;
	}

byebye:
deinit_all();
fprintf(stdout, "\n"
		"packets captured..: %u\n"
		"packets dropped...: %u\n"
		"eventflag:........: %04" PRIx16 "\n"
		"\n",
		lStats.tp_packets, lStats.tp_drops, eventflag);

if(rpi == true)
	{
	save_ftc();
	sync();
	if((eventflag & EVENT_GPIO_BUTTON) == EVENT_GPIO_BUTTON)
		{
		if(reboot(RB_POWER_OFF) == -1) fprintf(stdout, "failed to power off\n");
		}
	}
sync();
if((eventflag & EVENT_INIT_ERROR) == EVENT_INIT_ERROR)
	{
	if(exitiniterror != NULL)
		{
		if(exitiniterror[0] == 'p')
			{
			if(reboot(RB_POWER_OFF) == -1) fprintf(stdout, "failed to power off\n");
			}
		if(exitiniterror[0] == 'r')
			{
			if(reboot(RB_AUTOBOOT) == -1) fprintf(stdout, "failed to reboot\n");
			}
		}
	}

if((eventflag & EVENT_SCANLOOP_ERROR) == EVENT_SCANLOOP_ERROR)
	{
	if(exiterror != NULL)
		{
		if(exiterror[0] == 'p')
			{
			if(reboot(RB_POWER_OFF) == -1) fprintf(stdout, "failed to power off\n");
			}
		if(exiterror[0] == 'r')
			{
			if(reboot(RB_AUTOBOOT) == -1) fprintf(stdout, "failed to reboot\n");
			}
		}
	}

if((eventflag & EVENT_WATCHDOG) == EVENT_WATCHDOG)
	{
	if(exitwatchdog != NULL)
		{
		if(exitwatchdog[0] == 'p')
			{
			if(reboot(RB_POWER_OFF) == -1) fprintf(stdout, "failed to power off\n");
			}
		if(exitwatchdog[0] == 'r')
			{
			if(reboot(RB_AUTOBOOT) == -1) fprintf(stdout, "failed to reboot\n");
			}
		}
	}

if((eventflag & EVENT_TOT) == EVENT_TOT)
	{
	if(exittot != NULL)
		{
		if(exittot[0] == 'p')
			{
			if(reboot(RB_POWER_OFF) == -1) fprintf(stdout, "failed to power off\n");
			}
		if(exittot[0] == 'r')
			{
			if(reboot(RB_AUTOBOOT) == -1) fprintf(stdout, "failed to reboot\n");
			}
		}
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/
