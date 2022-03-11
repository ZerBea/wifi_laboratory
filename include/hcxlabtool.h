#define VERSIONTAG		"1.0.0"
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
#define HCX_SHOW_CHANNEL	'C'
#define HCX_STAYTIME		't'
#define HCX_SET_MONITORMODE	'm'
#define HCX_SHOW_INTERFACES	'I'
#define HCX_HELP		'h'
#define HCX_VERSION		'v'

#define ERROR_MAX		100
#define WATCHDOG		600

#define SCANLIST_MAX		256

#define M2ATTEMPTS		10

#define ESSID_LEN_MAX		32

#ifdef GETM2PR
#define FDRXSECTIMER		1 /* 1 second interval */
#define FDRXNSECTIMER		0
#else
#define FDRXSECTIMER		0
#ifdef BEACONUNSET
#define FDRXNSECTIMER		100000000 /* 0,1 second interval */
#else
#define FDRXNSECTIMER		200000000 /* 0,2 second interval */
#endif
#endif
#define FDTXSECTIMER		5 /* 5 second timeout */
#define RGAPLISTCOUNT		10
#define STAYTIME		5

#define LEDFLASHINTERVAL	10
#define RESUMEINTERVAL		36000

/*===========================================================================*/
typedef struct
{
int	frequency;
int	channel;
}scanlist_t;
#define	SCANLIST_SIZE (sizeof(scanlist_t))
/*===========================================================================*/
typedef struct
{
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
}essid_t;
#define	ESSID_SIZE (sizeof(essid_t))
/*===========================================================================*/
#define		CLIENTLIST_MAX		1024
typedef struct
{
 uint64_t		timestamp;
 uint32_t		count;
 uint8_t		mac[6];
 uint8_t		macap[6];
 uint8_t		mic[16];
 }clientlist_t;
#define	CLIENTLIST_SIZE (sizeof(clientlist_t))

static int sort_clientlist_by_time(const void *a, const void *b)
{
const clientlist_t *ia = (const clientlist_t *)a;
const clientlist_t *ib = (const clientlist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
#define		RGBSSIDLIST_MAX		1024
#define		RGBSSIDLISTTX_MAX	10
typedef struct
{
 uint64_t		timestamp;
 int			sequence;
 uint8_t		mac[6];
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
}rgbssidlist_t;
#define	RGBSSIDLIST_SIZE (sizeof(rgbssidlist_t))

static int sort_rgbssidlist_by_time(const void *a, const void *b)
{
const rgbssidlist_t *ia = (const rgbssidlist_t *)a;
const rgbssidlist_t *ib = (const rgbssidlist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
#define		BSSID_COUNT_MAX		1024
typedef struct
{
 uint64_t	timestampfirst;
 uint64_t	replaycountm1;
 uint64_t	timestampm1;
 uint64_t	timestampm2;
 uint64_t	timestampm3;
 uint16_t	capabilities;
 uint16_t	aid;
 uint32_t	beaconcount;
 uint32_t	proberesponsecount;
 uint32_t	deauthattackcount;
 uint32_t	deauthattackfactor;
 uint8_t	status;
 uint8_t	channel;
#define		BSSID_NONE		0b00000000
#define		BSSID_BEACON		0b00000001
#define		BSSID_PROBERESPONSE	0b00000010
#define		BSSID_M1		0b00000100
#define		BSSID_M2		0b00001000
#define		BSSID_M3		0b00010000
#define		BSSID_M4		0b00100000
#define		BSSID_PMKID		0b01000000
 uint8_t	kdv;
#define		BSSID_KDV_WPA		0b00000001
#define		BSSID_KDV_RSN		0b00000010
 uint8_t	groupcipher;
 uint8_t	cipher;
#define TCS_WEP40	0b00000001
#define TCS_TKIP	0b00000010
#define TCS_WRAP	0b00000100
#define TCS_CCMP	0b00001000
#define TCS_WEP104	0b00010000
#define TCS_BIP		0b00100000
#define TCS_NOT_ALLOWED	0b01000000
 uint16_t		rsnakm;
 uint16_t		wpaakm;
#define	TAK_PSK		0b0000000000000001
#define	TAK_PSKSHA256	0b0000000000000010
#define TAK_FT_PSK	0b0000000000000100
#define TAK_PSK_ALL	0b0000000000000111
#define TAK_FT		0b0000000000001000
#define	TAK_PMKSA	0b0000000000010000
#define	TAK_PMKSA256	0b0000000000100000
#define	TAK_TDLS	0b0000000001000000
#define	TAK_SAE_SHA256	0b0000000010000000
#define TAK_FT_SAE	0b0000000100000000
 uint16_t		rsncapa;
 uint64_t	timestampclient;
 uint8_t	macclient[6];
 uint8_t	essidlen;
 uint8_t	essid[ESSID_LEN_MAX];
}bssidinfo_t;
#define	BSSIDINFO_SIZE (sizeof(bssidinfo_t))
/*===========================================================================*/
#define BSSIDLIST_MAX		512
#define BSSIDLIST_SORT_MAX	256
typedef struct
{
 uint64_t	timestamp;
 bssidinfo_t	*bssidinfo;
 uint8_t	mac[6];
}bssidlist_t;
#define	BSSIDLIST_SIZE (sizeof(bssidlist_t))

static int sort_bssidlist_by_time(const void *a, const void *b)
{
const bssidlist_t *ia = (const bssidlist_t *)a;
const bssidlist_t *ib = (const bssidlist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
