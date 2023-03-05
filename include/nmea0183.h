/*===========================================================================*/
#define GPGGA_MAX	60
typedef struct __attribute__((__packed__)) 
{
 u8	mac[6];
 u8	essidlen;
 u8	essid[ESSID_MAX];
 char	gpgga[GPGGA_MAX];
}hcxpos_t;
#define HCXPOS_SIZE (sizeof(hcxpos_t))
/*---------------------------------------------------------------------------*/
