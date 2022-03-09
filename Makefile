INSTALLDIR	= /usr/local/bin

CC	?= gcc
#CFLAGS	= -O3 -Wall -Wextra -ggdb -fsanitize=address
CFLAGS	= -O3 -Wall -Wextra

all: build

build:
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxlabgetm1 hcxlabtool.c -DGETM1 -DSTATUSOUT
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxlabgetm2 hcxlabtool.c -DGETM2 -DSTATUSOUT
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxlabgetm2wc hcxlabtool.c -DGETM2 -DBEACONUNSET -DSTATUSOUT
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxlabgetm1234 hcxlabtool.c -DGETM1234 -DSTATUSOUT
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxlabgetmall hcxlabtool.c  -DGETM1 -DGETM2 -DGETM1234 -DSTATUSOUT
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxlabdumpall hcxlabtool.c -DDUMPIPV4 -DDUMPIPV6 -DDUMPWEP -DDUMPWPA

install: build
	install -D -m 0755 hcxlabgetm1 $(INSTALLDIR)/hcxlabgetm1
	install -D -m 0755 hcxlabgetm2 $(INSTALLDIR)/hcxlabgetm2
	install -D -m 0755 hcxlabgetm2wc $(INSTALLDIR)/hcxlabgetm2wc
	install -D -m 0755 hcxlabgetm1234 $(INSTALLDIR)/hcxlabgetm1234
	install -D -m 0755 hcxlabgetmall $(INSTALLDIR)/hcxlabgetmall
	install -D -m 0755 hcxlabdumpall $(INSTALLDIR)/hcxlabdumpall

	rm -f hcxlabgetm1
	rm -f hcxlabgetm2
	rm -f hcxlabgetm2wc
	rm -f hcxlabgetm1234
	rm -f hcxlabgetmall
	rm -f hcxlabdumpall
	rm -f *.o *~

clean:
	rm -f hcxlabgetm1
	rm -f hcxlabgetm2
	rm -f hcxlabgetm2wc
	rm -f hcxlabgetm1234
	rm -f hcxlabgetmall
	rm -f hcxlabdumpall
	rm -f *.o *~

uninstall:
	rm -f $(INSTALLDIR)/hcxlabgetm1
	rm -f $(INSTALLDIR)/hcxlabgetm2
	rm -f $(INSTALLDIR)/hcxlabgetm2wc
	rm -f $(INSTALLDIR)/hcxlabgetm1234
	rm -f $(INSTALLDIR)/hcxlabgetmall
	rm -f $(INSTALLDIR)/hcxlabdumpall
