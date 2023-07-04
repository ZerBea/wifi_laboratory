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

#include "include/types.h"
#include "include/hcxdb.h"
#include "include/hcxdb.c"
/*===========================================================================*/
/* define */

/*===========================================================================*/
/*===========================================================================*/
/* global var */
static pmkclist_t *pmkl;
static long pmklc;
static long pmklm;
static bool wantstopflag;
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
/*---------------------------------------------------------------------------*/
static inline void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL)) wantstopflag = true;
return;
}
/*===========================================================================*/
/*===========================================================================*/
static int sort_pmkclist_by_essidlen(const void *a, const void *b)
{
const pmkclist_t *ia = (const pmkclist_t *)a;
const pmkclist_t *ib = (const pmkclist_t *)b;

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
static bool writehcxpmkdb(char *hcxpmkdb)
{
static long c;
static unsigned p;
static int fh;

if((fh = open(hcxpmkdb, O_WRONLY | O_CREAT, 0644)) == -1) return false;
memset(mdvalfile, 0, mdlen);
if(write(fh, mdvalfile, mdlen) != mdlen)
	{
	fprintf(stderr, "saving SHA1 sum failed.\n");
	close(fh);
	return false;
	}
if (EVP_DigestInit(mdctx, md) != 1)
	{
	fprintf(stderr, "EVP_DigestInit failed.\n");
	close(fh);
	return false;
	}
for(c = 0; c < pmklc; c++)
	{
	if((pmkl +c)->status == REMOVED) break;
	if(write(fh, pmkl +c, PMK_MAX +2) != (PMK_MAX +2)) break;
	if((pmkl +c)->essidlen > ESSID_MAX) continue;
	if((pmkl +c)->psklen > PSK_MAX) continue;
	if (EVP_DigestUpdate(mdctx, pmkl +c, PMK_MAX +2) != 1)
		{
		fprintf(stderr, "EVP_DigestUpdate(hcxpmkdb) failed.\n");
		break;
		}
	if(write(fh, (pmkl +c)->essid, (pmkl +c)->essidlen) != (pmkl +c)->essidlen) break;
	if (EVP_DigestUpdate(mdctx, (pmkl +c)->essid, (pmkl +c)->essidlen) != 1)
		{
		fprintf(stderr, "EVP_DigestUpdate(hcxmpkdb) failed.\n");
		break;
		}
	if(write(fh, (pmkl +c)->psk, (pmkl +c)->psklen) != (pmkl +c)->psklen) break;
	if (EVP_DigestUpdate(mdctx, (pmkl +c)->psk, (pmkl +c)->psklen) != 1)
		{
		fprintf(stderr, "EVP_DigestUpdate(hcxmpkdb) failed.\n");
		break;
		}
	}
if (EVP_DigestFinal(mdctx, mdval, &mdlen) != 1)
	{
	fprintf(stderr, "EVP_DigestFinal(hcxpmkdb) failed.\n");
	close(fh);
	return false;
	}
lseek(fh, 0L, SEEK_SET);
if(write(fh, mdval, mdlen) != mdlen)
	{
	fprintf(stderr, "adding signature failed.\n");
	close(fh);
	return false;
	}
close(fh);
fprintf(stdout, "%ld PMK(s) stored to hcxpmkdb...\n", c);
for (p = 0; p < mdlen; p++) fprintf(stdout, "%02x", mdval[p]);
fprintf(stdout, " signature added\n");
return true;
}
/*===========================================================================*/
/*===========================================================================*/
void *calculatepmkthreadcpu(void *arg)
{
long int c;
thread_info *tdata;

tdata = arg;
for(c = tdata->thread_num; c < pmklc; c += tdata->cpucount)
	{
	if(wantstopflag == true) return NULL;
	if(PKCS5_PBKDF2_HMAC_SHA1((const char*)(pmkl +c)->psk, (pmkl +c)->psklen, (pmkl +c)->essid, (pmkl +c)->essidlen, 4096, PMK_MAX, tdata->pmk) == 0) tdata->errorcount += 1;
	if(memcmp(tdata->pmk, (pmkl +c)->pmk, PMK_MAX) != 0)
		{
		memcpy((pmkl +c)->pmk, tdata->pmk, PMK_MAX);
		tdata->falsecount +=1;
		}
	if(wantstopflag == true) return NULL;
	}
return NULL;
}
/*---------------------------------------------------------------------------*/
static int checknewpmks()
{
static int c;
static int cpucount;
static int ret;
static long ec;
static long fc;
static void *res;
static thread_info tinfo[CPU_MAX];
static u8 pmkcalc[PMK_MAX];

ec = 0;
fc = 0;
if(pmklc == 1)
	{
	if(PKCS5_PBKDF2_HMAC_SHA1((const char*)pmkl->psk, pmkl->psklen, pmkl->essid, pmkl->essidlen, 4096, PMK_MAX, pmkcalc) == 0) ec++;
	if(memcmp(pmkl->pmk, pmkcalc, PMK_MAX) != 0)
		{
		memcpy(pmkl->pmk, pmkcalc, PMK_MAX);
		ec++;
		}
	}
else
	{
	cpucount = get_nprocs();
	if(cpucount > CPU_MAX) cpucount = CPU_MAX;
	fprintf(stdout, "%d threads started to check database...\n", cpucount);
	for(c = 0; c < cpucount; c++)
		{
		tinfo[c].thread_num = c;
		tinfo[c].cpucount = cpucount;
		tinfo[c].errorcount = 0;
		tinfo[c].falsecount = 0;
		ret = pthread_create(&tinfo[c].thread_id, NULL, &calculatepmkthreadcpu, &tinfo[c]);
		if(ret != 0)
			{
			fprintf(stderr, "failed to create threads\n");
			return 0;
			}
		}
	for(c = 0; c < cpucount; c++)
		{
		ret = pthread_join(tinfo[c].thread_id, &res);
		ec += tinfo[c].errorcount;
		fc += tinfo[c].falsecount;
		if(ret != 0)
			{
			fprintf(stderr, "failed to join threads\n");
			ec++;
			return ec;
			}
		if(ec != 0)
			{
			fprintf(stderr, "thread error\n");
			return 0;
			}
		}
	}
fprintf(stdout, "%ld PMK(s) corrected...\n", fc);
fprintf(stdout, "%ld ERRORs during calculation...\n", ec);
return ec;
}
/*===========================================================================*/
static bool readhcxpmkdb(char *hcxpmkdb)
{
static unsigned p;
static int fh;
static pmkclist_t *pmklnew;

if((fh = open(hcxpmkdb, O_RDONLY)) == -1) return true;
if(read(fh, mdvalfile, mdlen) != mdlen)
	{
	fprintf(stderr, "failed to read SHA1 sum\n");
	close(fh);
	return false;
	}
for (p = 0; p < mdlen; p++) fprintf(stdout, "%02x", mdvalfile[p]);
fprintf(stdout, " signature from hcxpmkdb\n");
if (EVP_DigestInit(mdctx, md) != 1)
	{
	fprintf(stderr, "EVP_DigestInit failed.\n");
	close(fh);
	return false;
	}
while(1)
	{
	if(read(fh, pmkl +pmklc, PMK_MAX +2) != PMK_MAX +2) break;
	if (EVP_DigestUpdate(mdctx, pmkl +pmklc, PMK_MAX +2) != 1)
		{
		fprintf(stderr, "EVP_DigestUpdate(hcxpmkdb) failed.\n");
		break;
		}
	memset((pmkl +pmklc)->essid , 0, ESSID_MAX);
	if(read(fh, (pmkl +pmklc)->essid, (pmkl +pmklc)->essidlen) != (pmkl +pmklc)->essidlen) break;
	if(EVP_DigestUpdate(mdctx, (pmkl +pmklc)->essid, (pmkl +pmklc)->essidlen) != 1)
		{
		fprintf(stderr, "EVP_DigestUpdate(hcxmpkdb) failed.\n");
		break;
		}
	memset((pmkl +pmklc)->psk , 0, PSK_MAX);
	if(read(fh, (pmkl +pmklc)->psk, (pmkl +pmklc)->psklen) != (pmkl +pmklc)->psklen) break;
	if(EVP_DigestUpdate(mdctx, (pmkl +pmklc)->psk, (pmkl +pmklc)->psklen) != 1)
		{
		fprintf(stderr, "EVP_DigestUpdate(hcxmpkdb) failed.\n");
		break;
		}
	(pmkl +pmklc)->status = CHECKED;
	pmklc++;
	if(pmklc >= pmklm)
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
fprintf(stdout, "%ld PMK(s) loaded from database\n", pmklc);
for (p = 0; p < mdlen; p++) fprintf(stdout, "%02x", mdval[p]);
if(memcmp(mdval, mdvalfile, mdlen) == 0) fprintf(stdout, " signature verified\n");
else fprintf(stdout, " signature error\n");
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
if((pmkl = (pmkclist_t*)calloc(PMKLIST_MAX, PMKCLISTREC_MAX)) == NULL) return false;
wantstopflag = false;
signal(SIGINT, programmende);
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
if(pmklc == 0)
	{
	globalclose();
	return EXIT_SUCCESS;
	}
if(pmklc > 1)
	{
	qsort(pmkl, pmklc, PMKCLISTREC_MAX, sort_pmkclist_by_essidlen);
	}

globalclose();
return EXIT_SUCCESS;
}
/*===========================================================================*/
