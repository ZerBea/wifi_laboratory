#define FRAMESIZE	1024
/*===========================================================================*/
#define ADDSEQUENCENR(a,b)	{a[34] = (uint8_t)((b << 4) & 0xff); \
				a[35] = (uint8_t)((b << 4) >> 8); \
				b++;}


#define ADDESSID(a,b,c)		{{a[49] = (uint8_t)b; \
				memcpy(a[49], c, b);}

#define ADDCHANNEL(a,b)		{a[12] = (uint8_t)b;}

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ADDTIMESTAMP		{tx_proberesponse_head[36] = prtimestamp & 0xff; \
				tx_proberesponse_head[37] = (prtimestamp >> 8) & 0xff; \
				tx_proberesponse_head[38] = (prtimestamp >> 16) & 0xff; \
				tx_proberesponse_head[39] = (prtimestamp >> 24) & 0xff; \
				tx_proberesponse_head[40] = (prtimestamp >> 32) & 0xff; \
				tx_proberesponse_head[41] = (prtimestamp >> 40) & 0xff; \
				tx_proberesponse_head[42] = (prtimestamp >> 48) & 0xff; \
				tx_proberesponse_head[43] = (prtimestamp >> 56) & 0xff; \
				prtimestamp += 1;}
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ADDTIMESTAMP		{tx_proberesponse_head[43] = prtimestamp & 0xff; \
				tx_proberesponse_head[42] = (prtimestamp >> 8) & 0xff; \
				tx_proberesponse_head[41] = (prtimestamp >> 16) & 0xff; \
				tx_proberesponse_head[40] = (prtimestamp >> 24) & 0xff; \
				tx_proberesponse_head[39] = (prtimestamp >> 32) & 0xff; \
				tx_proberesponse_head[38] = (prtimestamp >> 40) & 0xff; \
				tx_proberesponse_head[37] = (prtimestamp >> 48) & 0xff; \
				tx_proberesponse_head[36] = (prtimestamp >> 56) & 0xff; \
				prtimestamp += 1;}
#endif

#define APFMCL3(a,b,c)		{memcpy(a[16], b, 6); \
				memcpy(a[22], c, 6); \
				memcpy(a[28], b, 6);}

#define CLFMAP3(a,b,c)		{memcpy(a[16], b, 6); \
				memcpy(a[22], c, 6); \
				memcpy(a[28], c, 6);}

#define ADDSEQUENCENRM1(a,b)	{a[EAPOLM1_OFFSET + 34] = (uint8_t)((b << 4) & 0xff); \
				a[EAPOLM1_OFFSET + 35] = (uint8_t)((b << 4) >> 8); \
				b++;}

#define CLFMAP3M1(a,b,c)	{memcpy(a[EAPOLM1_OFFSET + 16], b, 6); \
				memcpy(a[EAPOLM1_OFFSET + 22], c, 6); \
				memcpy(a[EAPOLM1_OFFSET + 28], c, 6);}

/*===========================================================================*/
static u8 tx_eap_request_id[] =
{
0x00, 0x00,					/* radiotap version and padding */
0x0c, 0x00,					/* radiotap header length */
0x06, 0x80, 0x00, 0x00,				/* bitmap */
0x00,						/* all flags cleared */
0x02,						/* rate */
0x18, 0x00,					/* tx flags */
0x08, 0x02,					/* type subtype data */
0xca, 0x00,					/* duration */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 1 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 2 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 3 */
0x00, 0x00,					/* sequence number */
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,	/* LLC */
0x01, 0x00, 0x00, 0x0a,
0x01, 0x9e, 0x00, 0x0a, 0x01, 0x68, 0x65, 0x6c, 0x6c, 0x6f
};
/*===========================================================================*/
#define EAPOLM1_OFFSET	28
#define EAPOLM1_SIZE	0x91
static u8 tx_eapolm1_wpa1[] =
{
0x06, 0x00, 0x00, 0x00,
0xb4, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x72, 0x44, 0x31, 0x18,
0xaf, 0x85, 0x6b, 0x2a,
0x91, 0x00, 0x00, 0x00,
0x91, 0x00, 0x00, 0x00,
0x00, 0x00,					/* radiotap version and padding */
0x0c, 0x00,					/* radiotap header length */
0x06, 0x80, 0x00, 0x00,				/* bitmap */
0x00,						/* all flags cleared */
0x02,						/* rate */
0x18, 0x00,					/* tx flags */
0x88, 0x02,					/* type subtype qos data */
0x3a, 0x01,					/* duration */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 1 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 2 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 3 */
0x00, 0x00,					/* sequence number */
0x06, 0x00,					/* qos control */
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,	/* LLC */
0x01,
0x03,
0x00, 0x5f,
0xfe,
0x00, 0x89,
0x00, 0x20,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* replay counter */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* nonce */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* nonce */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00,
0x00, 0x00, 0x00,
0xb4, 0x00, 0x00, 0x00
};
/*---------------------------------------------------------------------------*/
static u8 tx_eapolm1_wpa2[] =
{
0x06, 0x00, 0x00, 0x00,
0xb4, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x72, 0x44, 0x31, 0x18,
0xaf, 0x85, 0x6b, 0x2a,
0x91, 0x00, 0x00, 0x00,
0x91, 0x00, 0x00, 0x00,
0x00, 0x00,					/* radiotap version and padding */
0x0c, 0x00,					/* radiotap header length */
0x06, 0x80, 0x00, 0x00,				/* bitmap */
0x00,						/* all flags cleared */
0x02,						/* rate */
0x18, 0x00,					/* tx flags */
0x88, 0x02,					/* type subtype qos data */
0x3a, 0x01,					/* duration */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 1 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 2 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 3 */
0x00, 0x00,					/* sequence number */
0x06, 0x00,					/* qos control */
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,	/* LLC */
0x02,
0x03,
0x00, 0x5f,
0x02,
0x00, 0x8a,
0x00, 0x10,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* replay counter */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* nonce */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* nonce */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00,
0x00, 0x00, 0x00,
0xb4, 0x00, 0x00, 0x00
};
/*---------------------------------------------------------------------------*/
static u8 tx_eapolm1_wpa2v3[] =
{
0x06, 0x00, 0x00, 0x00,
0xb4, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x72, 0x44, 0x31, 0x18,
0xaf, 0x85, 0x6b, 0x2a,
0x91, 0x00, 0x00, 0x00,
0x91, 0x00, 0x00, 0x00,
0x00, 0x00,					/* radiotap version and padding */
0x0c, 0x00,					/* radiotap header length */
0x06, 0x80, 0x00, 0x00,				/* bitmap */
0x00,						/* all flags cleared */
0x02,						/* rate */
0x18, 0x00,					/* tx flags */
0x88, 0x02,					/* type subtype qos data */
0x3a, 0x01,					/* duration */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 1 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 2 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 3 */
0x00, 0x00,					/* sequence number */
0x06, 0x00,					/* qos control */
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,	/* LLC */
0x02,
0x03,
0x00, 0x5f,
0x02,
0x00, 0x8b,
0x00, 0x10,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* replay counter */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* nonce */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* nonce */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00,
0x00, 0x00, 0x00,
0xb4, 0x00, 0x00, 0x00
};
/*===========================================================================*/
static u8 tx_associationresponse[] =
{
0x00, 0x00,					/* radiotap version and padding */
0x0c, 0x00,					/* radiotap header length */
0x06, 0x80, 0x00, 0x00,				/* bitmap */
0x00,						/* all flags cleared */
0x02,						/* rate */
0x18, 0x00,					/* tx flags */
0x10, 0x00,					/* type subtype associationresponse */
0x3a, 0x01,					/* duration */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 1 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 2 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 3 */
0x00, 0x00,					/* sequence number */
0x31, 0x14,					/* capabilities */
0x00, 0x00,					/* status code */
0x10, 0xc0,					/* AID */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x0c, 0x12, 0x96, 0x18, 0x24,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
0x46, 0x05, 0x73, 0xd0, 0x00, 0x00, 0x0c,
0x2d, 0x1a, 0xad, 0x01, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x0b, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x4a, 0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00,
0x7f, 0x08, 0x05, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
0xdd, 0x08, 0x8c, 0xfd, 0xf0, 0x01, 0x01, 0x02, 0x01, 0x00,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x3b, 0x00, 0x01, 0x03, 0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20
};
/*---------------------------------------------------------------------------*/
static u8 tx_authenticationresponse[] =
{
0x00, 0x00,				/* radiotap version and padding */
0x0c, 0x00,				/* radiotap header length */
0x06, 0x80, 0x00, 0x00,			/* bitmap */
0x00,					/* all flags cleared */
0x02,					/* rate */
0x18, 0x00,				/* tx flags */
0xb0, 0x00,				/* type subtype authentication */
0x3a, 0x01,				/* duration */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 1 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 2 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 3 */
0x00, 0x0a,				/* sequence number */
0x00, 0x00,				/* algo open system */
0x02, 0x00,				/* authentication sequence 2*/
0x00, 0x00				/* status */
};
/*===========================================================================*/
static u8 tx_proberesponse_head[FRAMESIZE] =
{
0x00, 0x00,					/* radiotap version and padding */
0x0c, 0x00,					/* radiotap header length */
0x06, 0x80, 0x00, 0x00,				/* bitmap */
0x00,						/* all flags cleared */
0x02,						/* rate */
0x18, 0x00,					/* tx flags */
0x50, 0x00,					/* type subtype proberesponse */
0x3a, 0x01,					/* duration */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 1 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 2 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* mac addr 3 */
0x00, 0x00,					/* sequence number */
0xda, 0x41, 0xf3, 0x31, 0x00, 0x00, 0x00, 0x00,	/* timestamp */
0x64, 0x00,					/* interval */
0x31, 0x14,					/* capabilities */
0x00, 0x00					/* ssid_tag */
};
#define PROBERESPONSEHEAD_SIZE	(ssize_t)50
/* ESSID len 0 <= 32 */
/*---------------------------------------------------------------------------*/
static u8 tx_proberesponse_wpa12_short[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
0x03, 0x01, 0x0b,				/* channel */
0x07, 0x06, 0x44, 0x45, 0x20, 0x01, 0x0d, 0x14,
0x20, 0x01, 0x00,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
0x46, 0x05, 0x32, 0x00, 0x00, 0x00, 0x00,
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02,
};
#define PROBERESPONSE_WAP12_SHORT_SIZE	(ssize_t)sizeof(tx_proberesponse_wpa12_short)
/*===========================================================================*/
static u8 tx_deauthentication6[] =
{
0x00, 0x00,				/* radiotap version and padding */
0x0c, 0x00,				/* radiotap header length */
0x06, 0x80, 0x00, 0x00,			/* bitmap */
0x00,					/* all flags cleared */
0x02,					/* rate */
0x18, 0x00,				/* tx flags */
0xc0, 0x00,				/* type subtype deauthentication */
0x3a, 0x01,				/* duration */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 1 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 2 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 3 */
0x00, 0x00,				/* sequence number */
0x06, 0x00				/* WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA */
};
/*---------------------------------------------------------------------------*/
static u8 tx_disassociation7[] =
{
0x00, 0x00,				/* radiotap version and padding */
0x0c, 0x00,				/* radiotap header length */
0x06, 0x80, 0x00, 0x00,			/* bitmap */
0x00,					/* all flags cleared */
0x02,					/* rate */
0x18, 0x00,				/* tx flags */
0xa0, 0x00,				/* type subtype disassociation */
0x3a, 0x01,				/* duration */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 1 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 2 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 3 */
0x00, 0x00,				/* sequence number */
0x07, 0x00				/* WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA */
};
/*===========================================================================*/
static u8 tx_associationrequest_head[FRAMESIZE] =
{
0x00, 0x00,				/* radiotap version and padding */
0x0c, 0x00,				/* radiotap header length */
0x06, 0x80, 0x00, 0x00,			/* bitmap */
0x00,					/* all flags cleared */
0x02,					/* rate */
0x18, 0x00,				/* tx flags */
0x00, 0x00,				/* type subtype associationrequest */
0x3a, 0x01,				/* duration */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 1 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 2 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 3 */
0x00, 0x00,				/* sequence number */
0x31, 0x14,				/* capabilities */
0x05, 0x00,				/* listen interval */
};
/* 0x00, 0x07, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 ESSID len 0 <= 32 */
/*---------------------------------------------------------------------------*/
static u8 tx_associationrequest_wpa12_2[] =
{
0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
0x21, 0x02, 0x00, 0x14,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x8c, 0x00,
0x2d, 0x1a, 0x6e, 0x19, 0x13, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x96, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x7f, 0x0a, 0x04, 0x00, 0x0a, 0x02, 0x01, 0x40, 0x00, 0x40, 0x00, 0x01,
0x46, 0x05, 0x70, 0x00, 0x00, 0x00, 0x00,
0x3b, 0x16, 0x51, 0x51, 0x53, 0x54, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x00, 0x82, 0x80,
0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00,
};
/*---------------------------------------------------------------------------*/
static u8 tx_associationrequest_wpa2_2[] =
{
0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24, 
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c, 
0x21, 0x02, 0x00, 0x14, 
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x8c, 0x00, 
0x2d, 0x1a, 0x6e, 0x19, 0x13, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x96, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x7f, 0x0a, 0x04, 0x00, 0x0a, 0x02, 0x01, 0x40, 0x00, 0x40, 0x00, 0x01, 
0x46, 0x05, 0x70, 0x00, 0x00, 0x00, 0x00, 
0x3b, 0x16, 0x51, 0x51, 0x53, 0x54, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x00, 0x82, 0x80, 
0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00, 
};
/*---------------------------------------------------------------------------*/
static u8 tx_authenticationrequest[] =
{
0x00, 0x00,				/* radiotap version and padding */
0x0c, 0x00,				/* radiotap header length */
0x06, 0x80, 0x00, 0x00,			/* bitmap */
0x00,					/* all flags cleared */
0x02,					/* rate */
0x18, 0x00,				/* tx flags */
0xb0, 0x00,				/* type subtype authentication */
0x30, 0x01,				/* duration */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 1 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 2 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* mac addr 3 */
0x00, 0x00,				/* sequence number */
0x00, 0x00,				/* algo open system */
0x01, 0x00,				/* authentication sequence 1*/
0x00, 0x00				/* status */
};
/*===========================================================================*/
