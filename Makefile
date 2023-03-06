INSTALLDIR	= /usr/local/bin

CC	?= gcc
#CFLAGS	= -O3 -Wall -Wextra
CFLAGS	= -O3 -Wall -Wextra -ggdb -fsanitize=address

all: build

build:
	$(CC) $(CFLAGS) $(CFLAGS1) -o hcxlabtool hcxlabtool.c -DSTATUSOUT -DNMEAOUT

install: build
	install -D -m 0755 hcxlabtool $(INSTALLDIR)/hcxlabtool

	rm -f hcxlabtool
	rm -f *.o *~

clean:
	rm -f hcxlabtool
	rm -f *.o *~

uninstall:
	rm -f $(INSTALLDIR)/hcxlabtool
