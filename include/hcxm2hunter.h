/*===========================================================================*/
#define HCX_PHY_IDX		'p'
#define HCX_BPF			'b'
#define HCX_STAY_TIME		's'
#define HCX_TOT			't'
#define HCX_EXIT_TOT		'T'
#define HCX_WATCHDOG		'w'
#define HCX_EXIT_WATCHDOG	'W'
#define HCX_EXIT_ERROR		'E'
#define HCX_EXIT_INIT_ERROR	'I'
#define HCX_LED			'l'
#define HCX_FREQUENCY		'f'
#define HCX_ESSID_LIST		'e'
#define HCX_DISABLE_DE_AUTH	'D'
#define HCX_RDS			'S'
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

#define EAPOL_M12TOT		40000000
#define EAPOL_M23TOT		20000000

#define TIMER_HOLD		10
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

static inline __attribute__((always_inline)) int sort_interface_by_mode(const void *a, const void *b)
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
#define COUNT_AUTH_MAX		25
#define COUNT_ASSOC_MAX		25
#define COUNT_REASSOC_MAX	25
#define COUNT_M12RGMAX		4
#define COUNT_M123MAX		4
#define COUNT_NULL_MAX		100
#define COUNT_DATA1_MAX		100
#define COUNT_ACTION2_MAX	100
typedef struct
{
#define CON_ESSID		0x0001
#define CON_ACTION_ESSID	0x0002
#define CON_AUTHREQ		0x0004
#define CON_ASSOCREQ		0x0008
#define CON_REASSOCREQ		0x0010
#define CON_M1			0x0020
#define CON_M2			0x0040
#define CON_M2RG		0x0080
 time_t		secm1;
 time_t		secm2;
 long int	nsecm1;
 long int	nsecm2;
 u64		rcm1;
 u64		rcm2;
 u16		status;
 u16		seqauthreq;
 u16		seqassocreq;
 u16		seqreassocreq;
 u16		seqaction1;
 u16		seqaction2;
 u16		countm2rg;
 u16		countm3;
 u16		countauth;
 u16		countassoc;
 u16		countreassoc;
 u16		countnull;
 u16		countdata1;
 u16		countdata2;
 u16		countaction2;
 u8		akdv;
 u8		macap[ETH_ALEN];
 u8		maccl[ETH_ALEN];
 u8		mic[KEYMIC_MAX];
 u8		anonce[4];
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

static inline __attribute__((always_inline)) int sort_conlist_by_sec(const void *a, const void *b)
{
const conlist_t *ai = (const conlist_t *)a;
const conlist_t *bi = (const conlist_t *)b;

if(ai->sec < bi->sec) return 1;
else if(ai->sec > bi->sec) return -1;
return 0;
}
/*===========================================================================*/
#define COUNT_BC_MAX	100
typedef struct
{
 time_t		secat;
 u32		count1;
 u16		seqprobereq;
 u16		seqproberesp;
 u8		macap[ETH_ALEN];
 u8		maccl[ETH_ALEN];
 u8		essidlen;
 u8		essid[ESSID_MAX];
 }apdata_t;
#define APDATA_SIZE (sizeof(apdata_t))
/*---------------------------------------------------------------------------*/
#define APLIST_MAX	128
#define APLIST_HALF	64
#define ESSIDLIST_MAX	256
typedef struct
{
 time_t		sec;
 apdata_t	*apdata;
}aplist_t;
#define APLIST_SIZE (sizeof(aplist_t))

static inline __attribute__((always_inline)) int sort_aplist_by_sec(const void *a, const void *b)
{
const aplist_t *ai = (const aplist_t *)a;
const aplist_t *bi = (const aplist_t *)b;

if(ai->sec < bi->sec) return 1;
else if(ai->sec > bi->sec) return -1;
return 0;
}
/*===========================================================================*/

