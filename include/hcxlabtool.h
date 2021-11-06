#define VERSIONTAG		"0.1.0"
#define VERSIONYEAR		"2021"
#define VERSIONNAME		"hcxlabtool"

#define HCX_GPIO_BUTTON		1
#define HCX_GPIO_STATUSLED	2
#define HCX_BPFC		3
#define HCX_ESSIDLIST		4
#define HCX_ESSIDMAX		5
#define HCX_M2ATTEMPT		7
#define HCX_TOT			8
#define HCX_WEAKCANDIDATE	9

#define HCX_INTERFACE_NAME	'i'
#define HCX_CHANNEL		'c'
#define HCX_STAYTIME		't'
#define HCX_SET_MONITORMODE	'm'
#define HCX_SHOW_INTERFACES	'I'
#define HCX_HELP		'h'
#define HCX_VERSION		'v'

#define ERROR_MAX		100
#define WATCHDOG		600

#define CHANNEL_MAX		256

#define M2ATTEMPTS		10

#define ESSID_LEN_MAX		32
#define FDNSECTIMER		10000000 /* 10msec */
#define RGAPLISTCOUNT		10
#define STAYTIME		5

#define LEDFLASHINTERVAL	10
#define RESUMEINTERVAL		36000

/*===========================================================================*/
#define	EAPOLM1M2TIMEOUT	20000
#define	EAPOLM2M3TIMEOUT	20000
#define	EAPOLM3M4TIMEOUT	20000
#define EAPOLLIST_MAX		4
typedef struct
{
 uint64_t		timestamp;
 uint8_t		macap[6];
 uint8_t		macclient[6];
 uint64_t		rc;
}eapollist_t;
#define	EAPOLLIST_SIZE (sizeof(eapollist_t))

static int sort_eapollist_by_time(const void *a, const void *b)
{
const eapollist_t *ia = (const eapollist_t *)a;
const eapollist_t *ib = (const eapollist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
#define RGAPLIST_MAX	4096
typedef struct
{
 uint64_t		timestamp;
 int			sequence;
 uint8_t		macrgap[6];
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
}rgaplist_t;
#define	RGAPLIST_SIZE (sizeof(rgaplist_t))

static int sort_rgaplist_by_time(const void *a, const void *b)
{
const rgaplist_t *ia = (const rgaplist_t *)a;
const rgaplist_t *ib = (const rgaplist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
#define APLIST_MAX	256
typedef struct
{
 uint64_t		timestamp;
 uint8_t		macap[6];
 uint8_t		macclient[6];
 uint32_t		count;
 uint32_t		count2;
 uint8_t		status;
#define STATUS_BEACON	0b00000001
#define STATUS_PRESP	0b00000010
#define STATUS_AUTH	0b00000001
#define STATUS_ASSOC	0b00000010
#define STATUS_REASSOC	0b00000100
#define STATUS_M2	0b00001000
#define STATUS_M2DONE	0b01000000
#define STATUS_EAPDONE	0b10000000
 uint8_t		eapolstatus;
#define EAPOLM1		0b00000001
#define EAPOLM1M2RG	0b00000010
#define EAPOLM1M2	0b00000100
#define EAPOLM2M3	0b00001000
#define EAPOLM1M2M3	0b00010000
#define EAPOLPMKID	0b10000001
 uint8_t		eapstatus;
 int			channel;
 uint8_t		kdversion;
#define KV_RSNIE	0b00000001
#define KV_WPAIE	0b00000010
 uint8_t		groupcipher;
 uint8_t		cipher;
#define TCS_WEP40	0b00000001
#define TCS_TKIP	0b00000010
#define TCS_WRAP	0b00000100
#define TCS_CCMP	0b00001000
#define TCS_WEP104	0b00010000
#define TCS_BIP		0b00100000
#define TCS_NOT_ALLOWED	0b01000000
 uint16_t		akm;
#define	TAK_PMKSA	0b0000000000000001
#define	TAK_PSK		0b0000000000000010
#define TAK_FT		0b0000000000000100
#define TAK_FT_PSK	0b0000000000001000
#define	TAK_PMKSA256	0b0000000000010000
#define	TAK_PSKSHA256	0b0000000000100000
#define	TAK_TDLS	0b0000000001000000
#define	TAK_SAE_SHA256	0b0000000010000000
#define TAK_FT_SAE	0b0000000100000000
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
}aplist_t;
#define	APLIST_SIZE (sizeof(aplist_t))

static int sort_aplist_by_time(const void *a, const void *b)
{
const aplist_t *ia = (const aplist_t *)a;
const aplist_t *ib = (const aplist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/

