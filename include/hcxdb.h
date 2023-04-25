#define CPU_MAX		256
#define PMK_MAX		32
#define PSK_MIN		8
#define PSK_MAX		63
#define ESSID_MAX	32
#define ESSIDSTR_MAX	64
#define PSKSTR_MAX	126
#define MAC_MAX		6
#define PMKID_MAX	16
#define NONCE_MAX	32
#define MIC_MAX		16
#define LINEBUFFER_MAX	1024
#define UNCHECKED	0b000000000
#define CHECKED		0b000000001
#define REMOVED		0b000000010

/*===========================================================================*/
/*===========================================================================*/
/* struct */
#define PMKLIST_MAX	100000
typedef struct
{
 uint8_t	pmk[PMK_MAX];
 uint8_t	essidlen;
 uint8_t	psklen;
 uint8_t	essid[ESSID_MAX];
 uint8_t	psk[PSK_MAX];
} __attribute__((packed)) pmklist_t;
#define PMKLISTREC_MAX	sizeof(pmklist_t)
/*---------------------------------------------------------------------------*/
typedef struct
{
 uint8_t	pmk[PMK_MAX];
 uint8_t	essidlen;
 uint8_t	psklen;
 uint8_t	essid[ESSID_MAX];
 uint8_t	psk[PSK_MAX];
 uint8_t	status;
} __attribute__((packed)) pmkclist_t;
#define PMKCLISTREC_MAX	sizeof(pmkclist_t)
/*---------------------------------------------------------------------------*/
typedef struct
{
 long		rbtc;
 uint8_t	status;
 uint8_t	essidlen;
 uint8_t	essid[ESSID_MAX];
} __attribute__((packed)) rbth_t;
#define RBTH_MAX	sizeof(rbth_t)

#define RBT_MAX	100000
typedef struct
{
 uint8_t	pmk[PMK_MAX];
 uint8_t	psklen;
 uint8_t	psk[PSK_MAX];
} __attribute__((packed)) rbt_t;
#define RBTREC_MAX	sizeof(rbt_t)

typedef struct
{
 long		rbtc;
 long		rbtm;
 rbt_t		*rbt;
 uint8_t	status;
 uint8_t	essidlen;
 uint8_t	essid[ESSID_MAX];
} __attribute__((packed)) rbtl_t;
#define RBTLREC_MAX	sizeof(rbtl_t)

/*===========================================================================*/
#define PMKIDLIST_MAX	100000
#define PMKID_MAX	16
typedef struct
{
 pmklist_t	*result;
 uint8_t	macap[MAC_MAX];
 uint8_t	macclient[MAC_MAX];
 uint8_t	pmkid[PMKID_MAX];
 uint8_t	essidlen;
 uint8_t	essid[ESSID_MAX];
} __attribute__((packed)) pmkidlist_t;
#define PMKIDLISTREC_MAX	sizeof(pmkidlist_t)

/*---------------------------------------------------------------------------*/
#define EAPOLLIST_MAX	100000
#define EAPOL_MIN	0x5f +4 /* inclusive 4 bytes header */
#define EAPOL_MAX	0xff
typedef struct
{
 pmklist_t	*result;
 uint8_t	macap[MAC_MAX];
 uint8_t	macclient[MAC_MAX];
 uint8_t	kv;
 uint8_t	anonce[NONCE_MAX];
 uint8_t	snonce[NONCE_MAX];
 uint8_t	mic[MIC_MAX];
 uint8_t	mp;
 uint8_t	essidlen;
 uint8_t	essid[ESSID_MAX];
 uint8_t	eapollen;
 uint8_t	eapol[EAPOL_MAX];
} __attribute__((packed)) eapollist_t;
#define EAPOLLISTREC_MAX	sizeof(eapollist_t)
/*===========================================================================*/
typedef struct
{
 pthread_t	thread_id;
 int		thread_num;
 int		cpucount;
 long		errorcount;
 long		falsecount;
 uint8_t	pmk[PMK_MAX];
 uint8_t	essidlen;
 uint8_t	psklen;
 uint8_t	essid[ESSID_MAX];
 uint8_t	psk[PSK_MAX];
} thread_info;
/*---------------------------------------------------------------------------*/
/*===========================================================================*/
/*===========================================================================*/
/* globale variablen */
/*===========================================================================*/
