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
#define HCX_DAEMON		'd'
#define HCX_HELP		'h'
#define HCX_VERSION		'v'

#define GPIO_BUTTON		4
#define GPIO_LED		17

#define SNAPLEN			0xffff
#define SNAPLEN_WANTED		1024

#define ESSID_MAX		32

#define NLTX_SIZE		0xfff
#define NLRX_SIZE		0xffff

#define EVENT_SIGTERM		0x00000001
#define EVENT_SIGUSR1		0x00000002
#define EVENT_SIGUSR2		0x00000004
#define EVENT_GPIO_BUTTON	0x00000008
#define EVENT_WATCHDOG		0x00000010
#define EVENT_TOT		0x00000020
#define EVENT_INIT_ERROR	0x00000040
#define EVENT_SCANLOOP_ERROR	0x00000080
#define EVENT_PKT_READ_ERROR	0x00000100
#define EVENT_PKT_SEND_ERROR	0x00000200
#define EVENT_PKT_STORE_ERROR	0x00000400

#define EAPOL_M12TOT		40000000
#define EAPOL_M23TOT		20000000

#define TIMER_HOLD		10
#define EPOLL_EVENTS_MAX	10
/* staytime on frequency */
#define TIMER1_VSEC		5L
#define TIMER1_VNSEC		0L
#define TIMER1_ISEC		5L
#define TIMER1_INSEC		0L

/* watchdog */
#define TIMER2_VSEC		600L
#define TIMER2_VNSEC		0L
#define TIMER2_ISEC		600L
#define TIMER2_INSEC		0L

/* tot */
#define TIMER3_VSEC		0L
#define TIMER3_VNSEC		0L
#define TIMER3_ISEC		0L
#define TIMER3_INSEC		0L

/* LED on */
#define TIMER4_VSEC		0L
#define TIMER4_VNSEC		0L
#define TIMER4_ISEC		0L
#define TIMER4_INSEC		0L

/* LED off */
#define TIMER5_VSEC		0L
#define TIMER5_VNSEC		500000000L
#define TIMER5_ISEC		0L
#define TIMER5_INSEC		0L

#define MOD_INTERVAL		15
#define MOD_INTERVAL0		0
#define MOD_INTERVAL1		1
#define MOD_INTERVAL2		2
#define MOD_INTERVAL3		3
#define MOD_INTERVAL4		4
#define MOD_INTERVAL5		5
#define MOD_INTERVAL6		6
#define MOD_INTERVAL7		7
#define MOD_INTERVAL8		8
#define MOD_INTERVAL9		9
#define MOD_INTERVAL10		10

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
typedef struct
{
 time_t		secfirst;
 u8		mac[ETH_ALEN];
 u8		len;
 u8		essid[ESSID_MAX];
 }ed_t;
#define ED_SIZE (sizeof(ed_t))
/*---------------------------------------------------------------------------*/
#define ESSIDL_MAX	256
#define ESSIDL_SORT	24
typedef struct
{
 time_t		sec;
 ed_t		*ed;
}essidl_t;
#define ESSIDL_SIZE (sizeof(essidl_t))

static inline __attribute__((always_inline)) int sort_essidl_by_sec(const void *a, const void *b)
{
const essidl_t *ai = (const essidl_t *)a;
const essidl_t *bi = (const essidl_t *)b;

if(ai->sec < bi->sec) return 1;
else if(ai->sec > bi->sec) return -1;
return 0;
}
/*===========================================================================*/
#define	RSN_GCS_TKIP		0x0001
#define	RSN_GCS_CCMP		0x0002
#define	RSN_PCS_TKIP		0x0004
#define	RSN_PCS_CCMP		0x0008
#define	RSN_AKM_PSK		0x0010
#define	RSN_AKM_PSK256		0x0020
#define	RSN_AKM_PSKFT		0x0040
#define RSN_MFP			0x0c00
#define RSN_MFP_MANDATORY	0x0400
#define RSN_MFP_CAPABLE		0x0800
#define STAT_M1			0x0001
#define STAT_M4			0x0002
#define STAT_PMKID		0x0004
typedef struct
{
 time_t		secfirst;
 time_t		seccount;
 time_t		seccl;
 u16		status;
 u16		rsninfo;
 u8		mac[ETH_ALEN];
 u8		maccl[ETH_ALEN];
 u8		len;
 u8		essid[ESSID_MAX];
 u8		pmkid[PMKID_MAX];
 }bd_t;
#define BD_SIZE (sizeof(bd_t))
/*---------------------------------------------------------------------------*/
#define BSSIDL_MAX	256
#define BSSIDL_SORT	24
typedef struct
{
 time_t		sec;
 bd_t		*bd;
}bssidl_t;
#define BSSIDL_SIZE (sizeof(bssidl_t))

static inline __attribute__((always_inline)) int sort_bssidl_by_sec(const void *a, const void *b)
{
const bssidl_t *ai = (const bssidl_t *)a;
const bssidl_t *bi = (const bssidl_t *)b;

if(ai->sec < bi->sec) return 1;
else if(ai->sec > bi->sec) return -1;
return 0;
}
/*===========================================================================*/

