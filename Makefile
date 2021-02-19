INSTALLDIR	= /usr/local/bin

CC	= gcc
CFLAGS	= -O3 -Wall -Wextra 

all: build

build:
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxlabdeauth hcxlabtool.c -DDEAUTHENTICATION
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxlabdumpall hcxlabtool.c -DDUMPALL

install: build
	install -D -m 0755 hcxlabdeauth $(INSTALLDIR)/hcxlabdeauth
	install -D -m 0755 hcxlabdumpall $(INSTALLDIR)/hcxlabdumpall

	rm -f hcxlabdeauth
	rm -f hcxlabdumpall
	rm -f *.o *~

clean:
	rm -f hcxlabdeauth
	rm -f hcxlabdumpall
	rm -f *.o *~

uninstall:
	rm -f $(INSTALLDIR)/hcxlabdeauth
	rm -f $(INSTALLDIR)/hcxlabdumpall
