#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "include/hcxdb.h"
#include "include/hcxdb.c"
/*===========================================================================*/
/* define */
/*===========================================================================*/
/*===========================================================================*/
/* global var */
static pmklist_t *pmkl;
static long pmklc;
static long pmklm;
OSSL_LIB_CTX *library_context;
EVP_MD *md;
EVP_MD_CTX *mdctx;
static unsigned int mdlen;
static unsigned char *mdval;
static unsigned char *mdvalfile;
const char *option_properties;
/*===========================================================================*/
static void globalclose()
{
if(pmkl != NULL) free(pmkl);
EVP_MD_CTX_free(mdctx);
OPENSSL_free(mdval);
EVP_MD_free(md);
OSSL_LIB_CTX_free(library_context);
EVP_cleanup();
CRYPTO_cleanup_all_ex_data();
ERR_free_strings();
return;
}
/*===========================================================================*/
/*===========================================================================*/
static int sort_pmklist_by_essid_psk(const void *a, const void *b)
{
const pmklist_t *ia = (const pmklist_t *)a;
const pmklist_t *ib = (const pmklist_t *)b;

if(ia->essidlen > ib->essidlen) return 1;
else if(ia->essidlen < ib->essidlen) return -1;
if(memcmp(ia->essid, ib->essid, ESSID_MAX) > 0) return 1;
else if(memcmp(ia->essid, ib->essid, ESSID_MAX) < 0) return -1;
if(ia->psklen > ib->psklen) return 1;
else if(ia->psklen < ib->psklen) return -1;
if(memcmp(ia->psk, ib->psk, PSK_MAX) > 0) return 1;
else if(memcmp(ia->psk, ib->psk, PSK_MAX) < 0) return -1;
return 0;
}
/*===========================================================================*/
static void printhcxpmkdb()
{
static int lbp;
static long c;
static int p;
static char linebuffer[LINEBUFFER_MAX];

qsort(pmkl, pmklc, PMKLISTREC_MAX, sort_pmklist_by_essid_psk);
for(c = 0; c < pmklc; c++)
	{
	lbp = 0;
	putfield(linebuffer +lbp, (pmkl +c)->pmk, PMK_MAX);
	lbp += (PMK_MAX *2);
	linebuffer[lbp++] = '\t';
	for(p = 0; p < (pmkl +c)->essidlen; p++)
		{
		if((pmkl +c)->essid[p] < 0x20) break;
		if((pmkl +c)->essid[p] == 0x7f) break;
		}
	if(p == (pmkl +c)->essidlen)
		{
		memcpy(linebuffer +lbp, (pmkl +c)->essid, (pmkl +c)->essidlen);
		lbp += (pmkl +c)->essidlen;
		linebuffer[lbp++] = '\t';
		}
	else
		{
		linebuffer[lbp++] = '$';
		linebuffer[lbp++] = 'H';
		linebuffer[lbp++] = 'E';
		linebuffer[lbp++] = 'X';
		linebuffer[lbp++] = '[';
		putfield(linebuffer +lbp, (pmkl +c)->essid, (pmkl +c)->essidlen);
		lbp += ((pmkl +c)->essidlen *2);
		linebuffer[lbp++] = ']';
		linebuffer[lbp++] = '\t';
		}
	for(p = 0; p < (pmkl +c)->psklen; p++)
		{
		if((pmkl +c)->psk[p] < 0x20) break;
		if((pmkl +c)->psk[p] == 0x7f) break;
		}
	if((pmkl +c)->psklen < 8) (pmkl +c)->psklen = 8;
	if(p == (pmkl +c)->psklen)
		{
		memcpy(linebuffer +lbp, (pmkl +c)->psk, (pmkl +c)->psklen);
		lbp += (pmkl +c)->psklen;
		linebuffer[lbp++] = '\n';
		}
	else
		{
		linebuffer[lbp++] = '$';
		linebuffer[lbp++] = 'H';
		linebuffer[lbp++] = 'E';
		linebuffer[lbp++] = 'X';
		linebuffer[lbp++] = '[';
		putfield(linebuffer +lbp, (pmkl +c)->psk, (pmkl +c)->psklen);
		lbp += ((pmkl +c)->psklen *2);
		linebuffer[lbp++] = ']';
		linebuffer[lbp++] = '\n';
		}
	linebuffer[lbp++] = 0;
	fprintf(stdout, "%s", linebuffer);
	}
return;
}
/*===========================================================================*/
static bool readhcxpmkdb(char *hcxpmkdb)
{
static int fh;
static pmklist_t *pmklnew;
if((fh = open(hcxpmkdb, O_RDONLY)) == -1) return true;
if(read(fh, mdvalfile, mdlen) != mdlen)
	{
	fprintf(stderr, "failed to read SHA1 sum\n");
	close(fh);
	return false;
	}
if (EVP_DigestInit(mdctx, md) != 1)
	{
	fprintf(stderr, "EVP_DigestInit failed.\n");
	close(fh);
	return false;
	}
while(1)
	{
	if(read(fh, pmkl +pmklc, PMK_MAX +2) != PMK_MAX +2) break;
	if((pmkl +pmklc)->essidlen > ESSID_MAX) continue;
	if((pmkl +pmklc)->psklen > PSK_MAX) continue;
	if (EVP_DigestUpdate(mdctx, pmkl +pmklc, PMK_MAX +2) != 1)
		{
		fprintf(stderr, "EVP_DigestUpdate(hcxpmkdb) failed.\n");
		break;
		}
	memset((pmkl +pmklc)->essid , 0, ESSID_MAX);
	if(read(fh, (pmkl +pmklc)->essid, (pmkl +pmklc)->essidlen) != (pmkl +pmklc)->essidlen) break;
	if (EVP_DigestUpdate(mdctx, (pmkl +pmklc)->essid, (pmkl +pmklc)->essidlen) != 1)
		{
		fprintf(stderr, "EVP_DigestUpdate(hcxmpkdb) failed.\n");
		break;
		}
	memset((pmkl +pmklc)->psk , 0, PSK_MAX);
	if(read(fh, (pmkl +pmklc)->psk, (pmkl +pmklc)->psklen) != (pmkl +pmklc)->psklen) break;
	if (EVP_DigestUpdate(mdctx, (pmkl +pmklc)->psk, (pmkl +pmklc)->psklen) != 1)
		{
		fprintf(stderr, "EVP_DigestUpdate(hcxmpkdb) failed.\n");
		break;
		}
	pmklc++;
	if(pmklc >= pmklm -1)
		{
		pmklm += PMKLIST_MAX;
		pmklnew = realloc(pmkl, pmklm *PMKCLISTREC_MAX);
		if(pmklnew == NULL)
			{
			fprintf(stderr, "failed to allocate memory for internal list\n");
			close(fh);
			return false;
			}
		pmkl = pmklnew;
		}
	}
if (EVP_DigestFinal(mdctx, mdval, &mdlen) != 1)
	{
	fprintf(stderr, "EVP_DigestFinal(hcxpmkdb) failed.\n");
	close(fh);
	return false;
	}
close(fh);
if(memcmp(mdval, mdvalfile, mdlen) != 0)
	{
	fprintf(stderr, "hcxpmkdb damaged.\n");
	return false;
	}
return true;
}
/*===========================================================================*/
static bool globalinit()
{
ERR_load_crypto_strings();
OpenSSL_add_all_algorithms();
mdlen = 0;
md = NULL;
library_context = NULL;
option_properties = NULL;

library_context = OSSL_LIB_CTX_new();
if(library_context == NULL)
	{
	fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
	return false;
	}
md = EVP_MD_fetch(library_context, "SHA1", option_properties);
if(md == NULL)
	{
	fprintf(stderr, "EVP_MD_fetch could not find SHA1.");
	return false;
	}
mdlen = EVP_MD_get_size(md);
if(mdlen <= 0)
	{
	fprintf(stderr, "EVP_MD_get_size returned invalid size.\n");
	return false;
	}
mdval = OPENSSL_malloc(mdlen);
if(mdval == NULL)
	{
	fprintf(stderr, "No memory.\n");
	return false;
	}
mdvalfile = OPENSSL_malloc(mdlen);
if(mdvalfile == NULL)
	{
	fprintf(stderr, "No memory.\n");
	return false;
	}
mdctx = EVP_MD_CTX_new();
if(mdctx == NULL)
	{
	fprintf(stderr, "EVP_MD_CTX_new failed.\n");
	return false;
	}
pmklc = 0;
pmklm = PMKLIST_MAX;
if((pmkl = (pmklist_t*)calloc(PMKLIST_MAX, PMKLISTREC_MAX)) == NULL) return false;
return true;
}
/*---------------------------------------------------------------------------*/
int main(void)
{
static const char *homedir;
static const char *hcxtoolspath = "/.hcxtools";
static const char *hcxpmkdbname = "/hcxpmk.db";
static char hcxpmkdbdefaultname[PATH_MAX +1];

if(globalinit() == false)
	{
	fprintf(stderr, "could not init lists\n");
	exit(EXIT_FAILURE);
	}
if((homedir = getenv("HOME")) == NULL) homedir = getpwuid(getuid())->pw_dir;
if(homedir == NULL)
	{
	fprintf(stderr, "unable to get HOME directory\n");
	exit(EXIT_FAILURE);
	}
strcpy(hcxpmkdbdefaultname, homedir);
strcat(hcxpmkdbdefaultname, hcxtoolspath);
mkdir(hcxpmkdbdefaultname, 0777);
strcat(hcxpmkdbdefaultname, hcxpmkdbname);
if(readhcxpmkdb(hcxpmkdbdefaultname) == false) fprintf(stderr, "error while reading database\n");
if(pmklc > 0)
	{
	printhcxpmkdb();
	}
globalclose();
return EXIT_SUCCESS;
}
/*===========================================================================*/
