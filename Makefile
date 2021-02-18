INSTALLDIR	= /usr/local/bin

CC	= gcc
CFLAGS	= -O3 -Wall -Wextra 

all: build

build:
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxlabdeauth hcxlabtool.c -DDEAUTHENTICATION

install: build
	install -D -m 0755 hcxdump $(INSTALLDIR)/hcxlabtool

	rm -f hcxlabtool
	rm -f *.o *~

clean:
	rm -fhcxlabtool
	rm -f *.o *~

uninstall:
	rm -f $(INSTALLDIR)/hcxlabtool
