/*===========================================================================*/
#define HCX_BPF			'b'
#define HCX_STAY_TIME		's'
#define HCX_TOT			't'
#define HCX_EXIT_TOT		'T'
#define HCX_WATCHDOG		'w'
#define HCX_EXIT_WATCHDOG	'W'
#define HCX_LED			'l'
#define HCX_FREQUENCY		'f'
#define HCX_ESSID_LIST		'e'
#define HCX_HELP		'h'
#define HCX_VERSION		'v'

#define GPIO_BUTTON		4
#define GPIO_LED		17

#define SNAPLEN			0xffff
#define SNAPLEN_WANTED		1024

#define ESSID_MAX		32

#define NLTX_SIZE		0xfff
#define NLRX_SIZE		0xffff

#define EVENT_SIGTERM		0x0001
#define EVENT_GPIO_BUTTON	0x0002
#define EVENT_WATCHDOG		0x0004
#define EVENT_TOT		0x0008
#define EVENT_INIT_ERROR	0x0100
#define EVENT_SCANLOOP_ERROR	0x0200
#define EVENT_PKT_READ_ERROR	0x0400
#define EVENT_PKT_SEND_ERROR	0x0800
#define EVENT_PKT_STORE_ERROR	0x1000

#define LASTM4			10
#define LASTM12RG		10
#define LASTAUTHREQ		2
#define M12RGMAX		5
#define M4MAX			5
#define ONEHOUR			3600

#define EPOLL_EVENTS_MAX	10
/* staytime on frequency */
#define TIMER1_VSEC		5
#define TIMER1_VNSEC		0
#define TIMER1_ISEC		5
#define TIMER1_INSEC		0

/* watchdog */
#define TIMER2_VSEC		600
#define TIMER2_VNSEC		0
#define TIMER2_ISEC		600
#define TIMER2_INSEC		0

/* tot */
#define TIMER3_VSEC		0
#define TIMER3_VNSEC		0
#define TIMER3_ISEC		0
#define TIMER3_INSEC		0

/* LED */
#define TIMER4_VSEC		0
#define TIMER4_VNSEC		0
#define TIMER4_ISEC		0
#define TIMER4_INSEC		0

/*===========================================================================*/
#define ENTRIES(entries) (int)(sizeof(entries) / sizeof(*entries))
/*===========================================================================*/
#define INTERFACE_MAX	64
typedef struct
{
 u32		wiphy;
 u32		ifindex;
 u32		iftype;
 u8		hwmac[ETH_ALEN];
 u8		vimac[ETH_ALEN];
 size_t		wiphynamelen;
 u8		wiphyname[NL80211_WIPHY_NAME_MAXLEN];
 size_t		ifnamlen;
 u8		ifnam[IFNAMSIZ];
#define MODE_MONITOR	0x01
#define MODE_ACTIVE	0x02
 u8		mode;
 u8		modeakt;
 u8		flags;
}interface_t;
#define INTERFACE_SIZE (sizeof(interface_t))

static int sort_interface_by_mode(const void *a, const void *b)
{
const interface_t *ia = (const interface_t *)a;
const interface_t *ib = (const interface_t *)b;

if(ia->mode < ib->mode) return 1;
else if(ia->mode > ib->mode) return -1;
if(ia->wiphy < ib->wiphy) return 1;
else if(ia->wiphy > ib->wiphy) return -1;
return 0;
}
/*===========================================================================*/
#define FREQUENCYLIST_MAX	256
typedef struct
{
 u32	frequency;
 u32	channel;
}frequencylist_t;
#define FREQUENCYLIST_SIZE (sizeof(frequencylist_t))
/*===========================================================================*/
typedef struct
{
 time_t		secfirst;
 time_t		seclastauthreq;
 time_t		seclastassocreq;
 time_t		secrc1;
 time_t		secrc2;
 time_t		seclastm2rg;
 time_t		secrc3;
 time_t		seclastm4;
 u64		rc1;
 u64		rc2;
 u64		rc3;
#define CON_ESSID	0x0001
#define CON_ASSOCREQ	0x0002
#define CON_M1		0x0004
#define CON_M12RG	0x0008
#define CON_M1234	0x0010
#define CON_PMKID	0x0020
 u16		status;
 u16		frequency;
 u16		m12rgcount;
 u16		m1234count;
 u16		seqauthreq;
 u16		seqassocreq;
 u16		seqreassocreq;
 u16		seqproberesp;
 u16		seqaction;
 u16		seqauthresp;
 u16		seqassocresp;
 u16		seqreassocresp;
 u16		aid;
 u8		maccl[ETH_ALEN];
 u8		macap[ETH_ALEN];
 u8		anonce1[4];
 u8		anonce3[4];
 u8		m2rgmic[KEYMIC_MAX];
 u8		essidlen;
 u8		essid[ESSID_MAX];
 }condata_t;
#define CONDATA_SIZE (sizeof(condata_t))
/*---------------------------------------------------------------------------*/
#define CONLIST_MAX	512
typedef struct
{
 time_t		sec;
 condata_t	*condata;
}conlist_t;
#define CONLIST_SIZE (sizeof(conlist_t))

static int sort_conlist_by_sec(const void *a, const void *b)
{
const conlist_t *ai = (const conlist_t *)a;
const conlist_t *bi = (const conlist_t *)b;

if(ai->sec < bi->sec) return 1;
else if(ai->sec > bi->sec) return -1;
return 0;
}
/*===========================================================================*/
typedef struct
{
 time_t		secfirst;
 time_t		seclast;
 u16		status;
 u16		frequency;
 u8		maca1[ETH_ALEN];
 u8		maca2[ETH_ALEN];
 }ratadata_t;
#define RATADATA_SIZE (sizeof(ratadata_t))
/*---------------------------------------------------------------------------*/
#define RATALIST_MAX	512
typedef struct
{
 time_t		sec;
 ratadata_t	*ratadata;
}ratalist_t;
#define RATALIST_SIZE (sizeof(ratalist_t))

static int sort_ratalist_by_sec(const void *a, const void *b)
{
const ratalist_t *ai = (const ratalist_t *)a;
const ratalist_t *bi = (const ratalist_t *)b;

if(ai->sec < bi->sec) return 1;
else if(ai->sec > bi->sec) return -1;
return 0;
}
/*===========================================================================*/
typedef struct
{
 time_t		secfirst;
 time_t		seclastbeacon;
 time_t		seclastproberesponse;
#define AP_BEACON		0x0001
#define AP_PROBERESPONSE	0x0002
 u16		status;
 u16		frequency;
 u8		macap[ETH_ALEN];
 u8		essidlen;
 u8		essid[ESSID_MAX];
 }apdata_t;
#define APDATA_SIZE (sizeof(apdata_t))
/*---------------------------------------------------------------------------*/
#define APLIST_MAX	256
#define APLIST_HALF	128
#define ESSIDLIST_MAX	256
typedef struct
{
 time_t		sec;
 apdata_t	*apdata;
}aplist_t;
#define APLIST_SIZE (sizeof(aplist_t))

static int sort_aplist_by_sec(const void *a, const void *b)
{
const aplist_t *ai = (const aplist_t *)a;
const aplist_t *bi = (const aplist_t *)b;

if(ai->sec < bi->sec) return 1;
else if(ai->sec > bi->sec) return -1;
return 0;
}
/*===========================================================================*/

