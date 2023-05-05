#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
/*===========================================================================*/
/*===========================================================================*/
static int sort_pmklist_by_essidlen(const void *a, const void *b)
{
const pmklist_t *ia = (const pmklist_t *)a;
const pmklist_t *ib = (const pmklist_t *)b;

if(ia->essidlen > ib->essidlen) return 1;
else if(ia->essidlen < ib->essidlen) return -1;
if(memcmp(ia->essid, ib->essid, ESSID_MAX) > 0) return 1;
else if(memcmp(ia->essid, ib->essid, ESSID_MAX) < 0) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
static int sort_pmklist_by_pmk(const void *a, const void *b)
{
const pmklist_t *ia = (const pmklist_t *)a;
const pmklist_t *ib = (const pmklist_t *)b;

if(memcmp(ia->pmk, ib->pmk, PMK_MAX) > 0) return 1;
else if(memcmp(ia->pmk, ib->pmk, PMK_MAX) < 0) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static int sort_rbt_by_psk(const void *a, const void *b)
{
const rbt_t *ia = (const rbt_t *)a;
const rbt_t *ib = (const rbt_t *)b;

if(ia->psklen > ib->psklen) return 1;
else if(ia->psklen < ib->psklen) return -1;
if(memcmp(ia->psk, ib->psk, PSK_MAX) > 0) return 1;
else if(memcmp(ia->psk, ib->psk, PSK_MAX) < 0) return -1;
return 0;
}
/*===========================================================================*/
static int sort_pmkidlist_by_essidlen(const void *a, const void *b)
{
const pmkidlist_t *ia = (const pmkidlist_t *)a;
const pmkidlist_t *ib = (const pmkidlist_t *)b;

if(ia->essidlen > ib->essidlen) return 1;
else if(ia->essidlen < ib->essidlen) return -1;
if(memcmp(ia->essid, ib->essid, ESSID_MAX) > 0) return 1;
else if(memcmp(ia->essid, ib->essid, ESSID_MAX) < 0) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
static int sort_pmkidlist_by_pmkid(const void *a, const void *b)
{
const pmkidlist_t *ia = (const pmkidlist_t *)a;
const pmkidlist_t *ib = (const pmkidlist_t *)b;

if(memcmp(ia->pmkid, ib->pmkid, PMKID_MAX) > 0) return 1;
else if(memcmp(ia->pmkid, ib->pmkid, PMKID_MAX) < 0) return -1;
return 0;
}
/*===========================================================================*/
/*===========================================================================*/
static int sort_eapollist_by_essidlen(const void *a, const void *b)
{
const eapollist_t *ia = (const eapollist_t *)a;
const eapollist_t *ib = (const eapollist_t *)b;

if(ia->essidlen > ib->essidlen) return 1;
else if(ia->essidlen < ib->essidlen) return -1;
if(memcmp(ia->essid, ib->essid, ESSID_MAX) > 0) return 1;
else if(memcmp(ia->essid, ib->essid, ESSID_MAX) < 0) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
static int sort_eapollist_by_mic(const void *a, const void *b)
{
const eapollist_t *ia = (const eapollist_t *)a;
const eapollist_t *ib = (const eapollist_t *)b;

if(memcmp(ia->mic, ib->mic, MIC_MAX) > 0) return 1;
else if(memcmp(ia->mic, ib->mic, MIC_MAX) < 0) return -1;
return 0;
}
/*===========================================================================*/
static void putuint8(char *asciibuffer, uint8_t value)
{
static char lookuptable[] = { '0', '1', '2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
size_t p1;

p1 = 0;
asciibuffer[p1++] = lookuptable[(value & 0xf0) >> 4];
asciibuffer[p1++] = lookuptable[value & 0xf];
asciibuffer[p1++] = 0;
return;
}
/*===========================================================================*/
static void putfield(char *asciibuffer, uint8_t *hexbuffer, size_t len)
{
static char lookuptable[] = { '0', '1', '2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
size_t p1;
size_t p2;

p1 = 0;
for (p2 = 0; p2 < len;++p2)
	{
	asciibuffer[p1++] = lookuptable[(hexbuffer[p2] & 0xf0) >> 4];
	asciibuffer[p1++] = lookuptable[hexbuffer[p2] & 0xf];
	}
asciibuffer[p1++] = 0;
return;
}
/*---------------------------------------------------------------------------*/
static int getuint8(const char *str)
{
static uint8_t idx0;
static uint8_t idx1;
static const uint8_t lookuptable[] =
{
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
};
idx0 = ((uint8_t)str[0] & 0x1F) ^ 0x10;
idx1 = ((uint8_t)str[1] & 0x1F) ^ 0x10;
return (uint8_t)(lookuptable[idx0] << 4) | lookuptable[idx1];
}
/*---------------------------------------------------------------------------*/
static int getfield(const char *str, uint8_t *field, size_t flen, uint8_t sep)
{
static size_t pos;
static uint8_t idx0;
static uint8_t idx1;
static const uint8_t lookuptable[] =
{
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
};

pos = 0;
while(str[pos+0] != 0)
	{
	if(str[pos+0] < '0') return 0;
	if(str[pos+0] > 'f') return 0;
	if((str[pos+0] > '9') && (str[pos+0] < 'A')) return 0;
	if((str[pos+0] > 'F') && (str[pos+0] < 'a')) return 0;
	if(str[pos+1] < '0') return 0;
	if(str[pos+1] > 'f') return 0;
	if((str[pos+1] > '9') && (str[pos+1] < 'A')) return 0;
	if((str[pos+1] > 'F') && (str[pos+1] < 'a')) return 0;
	idx0 = ((uint8_t)str[pos+0] & 0x1F) ^ 0x10;
	idx1 = ((uint8_t)str[pos+1] & 0x1F) ^ 0x10;
	field[pos/2] = (uint8_t)(lookuptable[idx0] << 4) | lookuptable[idx1];
	pos += 2;
	if(str[pos+0] == sep) return pos/2;
	if(pos/2 > flen) return 0;
	};
if((pos %2) == 0) return pos /2;
return 0;
}
/*===========================================================================*/
static uint8_t hcx_strlen(char *string)
{
static uint8_t c;

c = 0;
while((string[c] != 0) || (c < 64)) c++;
return c;
}
/*===========================================================================*/
/*===========================================================================*/
#pragma GCC diagnostic pop
