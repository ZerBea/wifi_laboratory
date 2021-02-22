INSTALLDIR	= /usr/local/bin

CC	= gcc
CFLAGS	= -O3 -Wall -Wextra -ggdb

all: build

build:
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxlabgetm1 hcxlabtool.c -DGETM1
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxlabgetm1234 hcxlabtool.c -DGETM1234
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxlabdumpall hcxlabtool.c -DDUMPALL

install: build
	install -D -m 0755 hcxlabgetm1 $(INSTALLDIR)/hcxlabgetm1
	install -D -m 0755 hcxlabgetm1234 $(INSTALLDIR)/hcxlabgetm1234
	install -D -m 0755 hcxlabdumpall $(INSTALLDIR)/hcxlabdumpall

	rm -f hcxlabgetm1
	rm -f hcxlabgetm1234
	rm -f hcxlabdumpall
	rm -f *.o *~

clean:
	rm -f hcxlabgetm1
	rm -f hcxlabgetm1234
	rm -f hcxlabdumpall
	rm -f *.o *~

uninstall:
	rm -f $(INSTALLDIR)/hcxlabgetm1
	rm -f $(INSTALLDIR)/hcxlabgetm1234
	rm -f $(INSTALLDIR)/hcxlabdumpall
