INSTALLDIR	= /usr/local/bin

CC	= gcc
CFLAGS	= -O3 -Wall -Wextra
CFLAGS	+= -ggdb -fsanitize=address

all: build

build:
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxpot2pmkdb hcxpot2pmkdb.c -lcrypto
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxcheckpmkdb hcxcheckpmkdb.c -lcrypto
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxprintpmkdb hcxprintpmkdb.c -lcrypto

install: build
	install -D -m 0755 hcxpot2pmkdb $(INSTALLDIR)/hcxpot2pmkdb
	install -D -m 0755 hcxcheckpmkdb $(INSTALLDIR)/hcxcheckpmkdb
	install -D -m 0755 hcxprintpmkdb $(INSTALLDIR)/hcxprintpmkdb

	rm -f hcxpot2pmkdb
	rm -f hcxcheckpmkdb
	rm -f hcxprintpmkdb
	rm -f *.o *~

clean:
	rm -f hcxpot2pmkdb
	rm -f hcxcheckpmkdb
	rm -f hcxprintpmkdb
	rm -f *.o *~

uninstall:
	rm -f $(INSTALLDIR)/hcxpot2pmkdb
	rm -f $(INSTALLDIR)/hcxcheckpmkdb
	rm -f $(INSTALLDIR)/hcxprintpmkdb
