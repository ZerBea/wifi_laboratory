#define _GNU_SOURCE
#include <ctype.h>
#include <stdbool.h>
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <getopt.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#include "include/types.h"
#include "include/hcxpostool.h"
#include "include/nmea0183.h"

/*===========================================================================*/
/* global var */

static int fd_gpwpl = 0;

static hcxpos_t *hcxposlist = NULL;
static hcxpos_t hcxpos = { 0 };
/*===========================================================================*/
static void do_gpwpl(hcxpos_t *rec)
{
static ssize_t c;

c = 0;
while(c < (NMEA_MSG_MAX -2))
	{
	if(rec->gpgga[c] == '*')
		{
		if(c > 22)
			{
			rec->gpgga[c + 3] = 0x0d;
			rec->gpgga[c + 4] = 0x0a;
			if((write(fd_gpwpl, rec->gpgga, c + 4)) != c +4) return;
			return;
			}
		}
	c++;
	}
return;
}
/*---------------------------------------------------------------------------*/
static void process_record(hcxpos_t *rec)
{
static const char *gpgga = "$GPGGA,";

if(memcmp(gpgga, rec->gpgga, 7) != 0) return;
if(fd_gpwpl > 0) do_gpwpl(rec);
return;
}
/*---------------------------------------------------------------------------*/
static void close_outputfiles()
{
if(fd_gpwpl > 0) close(fd_gpwpl);

return;
}
/*---------------------------------------------------------------------------*/
static bool open_outputfiles(char *gpwplname)
{
if(gpwplname != NULL)
	{
	if((fd_gpwpl = open(gpwplname, O_WRONLY | O_CREAT, 0777)) < 0)
		{
		fprintf(stderr, "failed to open NMEA 0183 GPWPL file\n");
		}
	}
return true;
}
/*---------------------------------------------------------------------------*/
static void process_hcxpos(char *hcxposname)
{
static off_t i;
static int fd_hcxpos = 0;
static struct stat stinfo;

if(stat(hcxposname, &stinfo) == -1) return;
if((fd_hcxpos = open(hcxposname, O_RDONLY)) == -1) return;
if((hcxposlist = (hcxpos_t*)calloc(1,stinfo.st_size)) != NULL)
	{
	if(read(fd_hcxpos, hcxposlist, stinfo.st_size) == stinfo.st_size)
		{
		for(i = 0; i < (stinfo.st_size / HCXPOS_SIZE); i++) process_record(hcxposlist + i);
		}
	}
else
	{
	while(1)
		{
		if(read(fd_hcxpos, &hcxpos, HCXPOS_SIZE) != HCXPOS_SIZE) break;
		process_record(&hcxpos);
		}
	}
if(hcxposlist != NULL) free(hcxposlist);
if(fd_hcxpos != 0) close(fd_hcxpos);
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n", eigenname, VERSIONTAG, VERSIONYEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
fprintf(stdout, "%s %s  (C) %s ZeroBeat\n"
	"usage  : %s <options>\n"
	"\n"
	"short options:\n"
	"-i <file>      : input hcxpos file\n"
	"-h             : show this help\n"
	"-v             : show version\n"
	"\n",
	eigenname, VERSIONTAG, VERSIONYEAR, eigenname);
fprintf(stdout, "long options:\n"
	"--gpwpl=<file>    : output waypoint (NMEA 0183 GPWPL)\n"
	"                    only MAC AP is used because NMEA 0183 messages\n"
	"                    have a maximum length of 82 characters\n"
	"--help            : show this help\n"
	"--version         : show version\n"
	"\n");
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSIONTAG, VERSIONYEAR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl = -1;
static int index = 0;
static char *hcxposname = 0;
static char *gpwplname = NULL;
static const char *short_options = "i:hv";
static const struct option long_options[] =
{
	{"gpwpl",			required_argument,	NULL,	HCX_GPWPL},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};
optind = 1;
optopt = 0;
while((auswahl = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_POSNAME:
		hcxposname = optarg;
		break;

		case HCX_GPWPL:
		gpwplname = optarg;
		break;

		case HCX_HELP:
		usage(basename(argv[0]));
		break;

		case HCX_VERSION:
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;

		default:
		usageerror(basename(argv[0]));
		}
	}
setbuf(stdout, NULL);
open_outputfiles(gpwplname);
if(hcxposname != NULL) process_hcxpos(hcxposname);
close_outputfiles();
fprintf(stdout, "\nbye-bye\n");
return EXIT_SUCCESS;
}
/*===========================================================================*/
