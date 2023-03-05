#define _GNU_SOURCE
#include <ctype.h>
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

static hcxpos_t hcxpos = { 0 };

/*===========================================================================*/
static void process_pos(char *hcxposname)
{
static int fd_hcxpos = 0;

if((fd_hcxpos = open(hcxposname, O_RDONLY)) == -1) return;
while(1)
	{
	if(read(fd_hcxpos, &hcxpos, HCXPOS_SIZE) != HCXPOS_SIZE) break;

	printf("%.*s\n", hcxpos.essidlen, hcxpos.essid);

	}
close(fd_hcxpos);
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
	"--help                         : show this help\n"
	"--version                      : show version\n"
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
static const char *short_options = "i:hv";
static const struct option long_options[] =
{
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
if(hcxposname != NULL) process_pos(hcxposname);
fprintf(stdout, "\nbye-bye\n");
return EXIT_SUCCESS;
}
/*===========================================================================*/
