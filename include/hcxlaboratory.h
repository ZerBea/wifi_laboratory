#define VERSIONTAG		"0.0.1"
#define VERSIONYEAR		"2021"
#define VERSIONNAME		"hcxlabtool"

#define HCX_GPIO_BUTTON		1
#define HCX_GPIO_STATUSLED	2
#define HCX_BPFC		3
#define HCX_HELP		'h'
#define HCX_VERSION		'v'

#define FDTIMER			1

#define ERROR_MAX		100
#define WATCHDOG		600

#define ESSID_LEN_MAX		32

/*===========================================================================*/
#define OWNDLIST_MAX	64
typedef struct
{
 uint64_t			timestamp;
 uint8_t			eapolstatus;
#define OWND_EAPOLM1M2		0b00000001
#define OWND_EAPOLM2M3		0b00000010
#define OWND_EAPOLM3M4		0b00000100
#define OWND_PMKID_AP		0b00001000
#define OWND_NO_PMKID		0b10000000
 uint8_t			eapstatus;
#define OWND_EAP		0b00000001
#define OWND_NO_EAP		0b10000000
 uint8_t			macap[6];
 uint8_t			macclient[6];
}owndlist_t;
#define	OWNDLIST_SIZE (sizeof(owndlist_t))

static int sort_owndlist_by_time(const void *a, const void *b)
{
const owndlist_t *ia = (const owndlist_t *)a;
const owndlist_t *ib = (const owndlist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
#define	EAPOLM1M2TIMEOUT	25000
#define	EAPOLM2M3TIMEOUT	50000
#define	EAPOLM3M4TIMEOUT	50000
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
#define RGAPLIST_MAX	64
typedef struct
{
 uint64_t		timestamp;
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
#define APLIST_MAX	64
typedef struct
{
 uint64_t		timestamp;
 uint32_t		count;
 uint16_t		status;
 int			channel;
#define STATUS_BEACON	0b0000000000000001
#define STATUS_PRESP	0b0000000000000010
 uint8_t		macap[6];
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
#define INTERFACE_MAX	4
typedef struct
{
 int		fd;
 char		ifname[IFNAMSIZ +1];
 uint8_t	ifmac[6];
 int		fdpcapng;
 uint32_t	ouirgap;
 uint32_t	nicrgap;
 uint8_t	macrgap[6];
 uint8_t	anonce[32];
 uint32_t	ouirgclient;
 uint32_t	nicrgclient;
 uint8_t	macrgclient[6];
 uint8_t	snonce[32];
 uint64_t	rc;
 int		channel;
 aplist_t	*aplist;
 rgaplist_t	*rgaplist;
 eapollist_t	*eapolm1list;
 eapollist_t	*eapolm2list;
 eapollist_t	*eapolm3list;
 owndlist_t	*owndlist;
}interfacelist_t;
#define	INTERFACELIST_SIZE (sizeof(interfacelist_t))
/*===========================================================================*/

