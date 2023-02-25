/*===========================================================================*/
#define VERSIONTAG		"2.0.0"
#define VERSIONYEAR		"2023"
#define VERSIONNAME		"hcxlabtool"
/*---------------------------------------------------------------------------*/
#define HCX_BPF				1
#define HCX_DISABLE_BEACON		2
#define HCX_DISABLE_DEAUTHENTICATION	3
#define HCX_DISABLE_PROBEREQUEST	4
#define HCX_DISABLE_ASSOCIATION		5
#define HCX_DISABLE_REASSOCIATION	6
#define HCX_GPIO_BUTTON			7
#define HCX_GPIO_STATUSLED		8
#define HCX_TOT				9
#define HCX_ERROR_MAX			10
#define HCX_WATCHDOG_MAX		11
#define HCX_ATTEMPT_CLIENT_MAX		12
#define HCX_ATTEMPT_AP_MAX		13
#define HCX_ON_SIGTERM			14
#define HCX_ON_TOT			15
#define HCX_ON_GPIOBUTTON		16
#define HCX_ON_WATCHDOG			17
#define HCX_ON_ERROR			18
#define HCX_ESSIDLIST			19

#define HCX_IFNAME			'i'
#define HCX_INTERFACE_INFO		'I'
#define HCX_SET_MONITORMODE		'm'
#define HCX_SET_SCANLIST_FROM_USER_CH	'c'
#define HCX_SET_SCANLIST_FROM_USER_FREQ	'f'
#define HCX_SET_SCANLIST_FROM_INTERFACE	'F'
#define HCX_SHOW_INTERFACE_LIST		'L'
#define HCX_HOLD_TIME			't'
#define HCX_HELP			'h'
#define HCX_VERSION			'v'
/*---------------------------------------------------------------------------*/
#define EXIT_EVENT_MASK		0b00011111
#define EXIT_ON_SIGTERM		0b00000001
#define EXIT_ON_GPIOBUTTON	0b00000010
#define EXIT_ON_TOT		0b00000100
#define EXIT_ON_WATCHDOG	0b00001000
#define EXIT_ON_ERROR		0b00010000

#define EXIT_ACTION_REBOOT	0b00000001
#define EXIT_ACTION_POWEROFF	0b00000010

#define ERROR_MAX		100
#define WATCHDOG_MAX		600
#define ATTEMPTCLIENT_MAX	10
#define ATTEMPTAP_MAX		10

#define IFTYPENL		0b00000001
#define IFTYPEWE		0b00000010
#define IFTYPENLWE		0b00000011
#define IFTYPEMON		0b00000100
#define ETHTOOL_STD_LEN		32

#define TIMER1_VALUE_SEC	1
#define TIMER1_VALUE_NSEC	0L
#define TIMER1_INTERVAL_SEC	1
#define TIMER1_INTERVAL_NSEC	0L
#define TIMEHOLD		2000000ULL
#define TIMEBEACONWAIT		1000000ULL
#define TIMEBEACONNEW		3600000000ULL
#define EPOLL_EVENTS_MAX	5

#define APLIST_MAX		250
#define APRGLIST_MAX		500
#define CLIENTLIST_MAX		500
#define MACLIST_MAX		250
#define ESSID_MAX		32
#define PMKID_MAX		32
#define PSK_MAX			64
#define DRIVERNAME_MAX		32

#define EAPOLM2TIMEOUT		100000ULL
#define EAPOLM3TIMEOUT		40000ULL
#define CLIENTM2COUNT		10;
#define M1_RETRY_SLEEP		100;

#define PCAPNG_SNAPLEN		0xffff

#define NLTX_SIZE		0xff
#define NLRX_SIZE		0xffff

#define WEAKCANDIDATEDEF	"12345678"
/*===========================================================================*/
typedef struct
{
 u8	status;
 u8	macap[6];
 u8	kdv1;
 u64	replaycountm1;
 u8	noncem1[4];
 u8	kdv2;
 u64	replaycountm2;
}authseqakt_t;
#define AUTHSEQAKT_SIZE (sizeof(authseqakt_t))
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u8 	len;
 u8	*essid;
}essid_t;
#define ESSID_SIZE (sizeof(essid_t))
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__)) 
{
#define	APIE_ESSID	0b0000000000000001
#define APGS_CCMP	0b0000000000000010
#define APGS_TKIP	0b0000000000000100
#define APCS_CCMP	0b0000000000001000
#define APCS_TKIP	0b0000000000010000
#define APRSNAKM_PSK	0b0000000000100000
#define APRSNAKM_PSK256	0b0000000001000000
#define APRSNAKM_PSKFT	0b0000000010000000
#define APWPAAKM_PSK	0b0000000100000000
#define APAKM_MASK	0b0000000111100000
#define AP_MFP		0b0000001000000000
 u8	flags;
 u8	essidlen;
 u8	essid[ESSID_MAX];
 u16	channel;
}infoelement_t;
#define INFOELEMENT_SIZE (sizeof(infoelement_t))
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__)) 
{
 u64	tsakt;
 u64	tshold1;
 u64	tshold2;
 u8	count;
 u8	macap[6];
 u8	macclient[6];
 u8	status;
#define AP_ESSID		0b00000001
#define AP_BEACON		0b00000010
#define AP_PROBERESPONSE	0b00000100
#define AP_EAPOL_M1		0b00001000
#define AP_EAPOL_M2		0b00010000
#define AP_EAPOL_M3		0b00100000
#define AP_PMKID		0b01000000
 infoelement_t	ie;
}aplist_t;
#define APLIST_SIZE (sizeof(aplist_t))
/*---------------------------------------------------------------------------*/
static int sort_aplist_by_tsakt(const void *a, const void *b)
{
const aplist_t *ai = (const aplist_t *)a;
const aplist_t *bi = (const aplist_t *)b;

if(ai->tsakt < bi->tsakt) return 1;
else if(ai->tsakt > bi->tsakt) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__)) 
{
 u64	tsakt;
 u8	macaprg[6];
 u8	essidlen;
 u8	essid[ESSID_MAX];
}aprglist_t;
#define APRGLIST_SIZE (sizeof(aprglist_t))
static int sort_aprglist_by_tsakt(const void *a, const void *b)
{
const aprglist_t *ai = (const aprglist_t *)a;
const aprglist_t *bi = (const aprglist_t *)b;

if(ai->tsakt < bi->tsakt) return 1;
else if(ai->tsakt > bi->tsakt) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__)) 
{
 u64	tsakt;
 u16	aid;
 u8	macclient[6];
 u8	macap[6];
 u8	mic[4];
#define CLIENT_AUTHENTICATION	0b00000001
#define CLIENT_ASSOCIATION	0b00000010
#define CLIENT_REASSOCIATION	0b00000100
 u8	status;
 u8	count;
 infoelement_t	ie;
}clientlist_t;
#define CLIENTLIST_SIZE (sizeof(clientlist_t))

static int sort_clientlist_by_tsakt(const void *a, const void *b)
{
const clientlist_t *ai = (const clientlist_t *)a;
const clientlist_t *bi = (const clientlist_t *)b;

if(ai->tsakt < bi->tsakt) return 1;
else if(ai->tsakt > bi->tsakt) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__)) 
{
 u64	tsakt;
 u8	mac[6];
}maclist_t;
#define MACLIST_SIZE (sizeof(maclist_t))

static int sort_maclist_by_tsakt(const void *a, const void *b)
{
const maclist_t *ai = (const maclist_t *)a;
const maclist_t *bi = (const maclist_t *)b;

if(ai->tsakt < bi->tsakt) return 1;
else if(ai->tsakt > bi->tsakt) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
#define SCANLIST_MAX		1024
#define FREQUENCYLIST_MAX	1024
typedef struct __attribute__((__packed__))
{
 u32	frequency;
 u32	channel;
 u32	pwr;
#define IF_STAT_FREQ_DISABLED	0b00000001
 u8	status;
}frequencylist_t;
#define FREQUENCYLIST_SIZE (sizeof(frequencylist_t))
/*---------------------------------------------------------------------------*/
#define INTERFACELIST_MAX	1024
typedef struct __attribute__((__packed__)) 
{
 u32	index;
 u32	wiphy;
#define IF_HAS_WEXT		0b00000001
#define IF_HAS_NETLINK		0b00000010
#define IF_HAS_NLWEXT		0b00000011
#define IF_HAS_MONITOR		0b00000100
#define IF_HAS_NLMON		0b00000110
 u8	type;
#define IF_STAT_MONITOR		0b00000001
#define IF_STAT_UP		0b00000010
#define IF_STAT_OK		0b00000011
 u8	status;
 u8	hwmac[6];
 u8	vimac[6];
 char	name[IFNAMSIZ];
 char	driver[DRIVERNAME_MAX];
}interface_t;
#define INTERFACELIST_SIZE (sizeof(interface_t))
/*===========================================================================*/
typedef struct
{
 struct nlmsghdr  nlh;
 struct ifinfomsg ifinfo;
 char attrbuf[512];
}req_t;
/*===========================================================================*/
static bool read_bpf(char *bpfname);
static bool nl_get_interfacelist(interface_t *iffoundlist);
static inline bool nl_set_frequency();
/*===========================================================================*/
