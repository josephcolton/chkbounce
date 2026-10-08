PROGS   = chkbounce
OBJS    = global.o packets.o receive.o report.o server.o client.o
HEADERS = global.h protocol.h packets.h receive.h report.h server.h client.h
VERSION := $(shell git describe --always --dirty 2>/dev/null || echo unknown)
CFLAGS  = -Wall -Wextra -O2 -DCHKBOUNCE_VERSION='"$(VERSION)"'

PREFIX  = /usr
SBINDIR = $(PREFIX)/sbin
MAN8DIR = $(PREFIX)/share/man/man8

all: $(PROGS)

global.o: global.c global.h protocol.h
	gcc $(CFLAGS) -c global.c

packets.o: packets.c packets.h global.h protocol.h
	gcc $(CFLAGS) -c packets.c

receive.o: receive.c receive.h global.h protocol.h
	gcc $(CFLAGS) -c receive.c

report.o: report.c report.h global.h protocol.h client.h
	gcc $(CFLAGS) -c report.c

server.o: server.c server.h global.h protocol.h packets.h receive.h
	gcc $(CFLAGS) -c server.c

client.o: client.c client.h global.h protocol.h packets.h receive.h report.h
	gcc $(CFLAGS) -c client.c

chkbounce: chkbounce.c $(OBJS) $(HEADERS)
	gcc $(CFLAGS) chkbounce.c -o chkbounce $(OBJS)

install: $(PROGS)
	install -d $(DESTDIR)$(SBINDIR)
	install -d $(DESTDIR)$(MAN8DIR)
	install -m 0755 chkbounce $(DESTDIR)$(SBINDIR)/chkbounce
	install -m 0644 chkbounce.8 $(DESTDIR)$(MAN8DIR)/chkbounce.8
	gzip -f $(DESTDIR)$(MAN8DIR)/chkbounce.8

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/chkbounce
	rm -f $(DESTDIR)$(MAN8DIR)/chkbounce.8.gz

clean:
	rm -f $(PROGS) $(OBJS)

.PHONY: all install uninstall clean
