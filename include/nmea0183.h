/*===========================================================================*/
#define NMEA_SIZE		9128
#define NMEA_MSG_MAX		82
#define NMEA_MIN		46
typedef struct __attribute__((__packed__)) 
{
 u8	mac[6];
 u8	essidlen;
 u8	essid[ESSID_MAX];
 char	gprmc[NMEA_MSG_MAX];
 char	gpgga[NMEA_MSG_MAX];
}hcxpos_t;
#define HCXPOS_SIZE (long int)(sizeof(hcxpos_t))
/*---------------------------------------------------------------------------*/
