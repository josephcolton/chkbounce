PROGS   = chkbounce
OBJS    = global.o packets.o receive.o report.o server.o client.o
HEADERS = global.h protocol.h packets.h receive.h report.h server.h client.h
VERSION := $(shell git describe --always --dirty 2>/dev/null || echo unknown)
CFLAGS  = -Wall -Wextra -O2 -DCHKBOUNCE_VERSION='"$(VERSION)"'

PREFIX  = /usr
SBINDIR = $(PREFIX)/sbin
MAN8DIR = $(PREFIX)/share/man/man8

# The installed binary is NOT setuid (a setuid chkbounce would write -o/--csv/
# --json files as root for any user).  Instead it gets only the capabilities
# it needs: raw sockets for ICMP, and binding probe ports below 1024.
# Packagers who apply capabilities at package-install time can pass SETCAP=
# to skip this step.
CAPS    = cap_net_raw,cap_net_bind_service+ep
SETCAP ?= setcap

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
	@if [ -z "$(SETCAP)" ]; then \
		echo "SETCAP is empty: no capabilities set on $(DESTDIR)$(SBINDIR)/chkbounce;"; \
		echo "run it as root, or later: setcap $(CAPS) $(SBINDIR)/chkbounce"; \
	elif ! command -v $(SETCAP) >/dev/null 2>&1; then \
		echo "error: $(SETCAP) not found (install libcap2-bin or libcap)," \
		     "or rerun with SETCAP= to skip capabilities" >&2; \
		exit 1; \
	elif $(SETCAP) $(CAPS) $(DESTDIR)$(SBINDIR)/chkbounce; then \
		echo "Set capabilities $(CAPS) on $(DESTDIR)$(SBINDIR)/chkbounce"; \
	else \
		echo "error: could not set capabilities (needs root, and a filesystem" \
		     "with extended attributes); rerun with sudo, or with SETCAP= to skip" >&2; \
		exit 1; \
	fi
	install -m 0644 chkbounce.8 $(DESTDIR)$(MAN8DIR)/chkbounce.8
	gzip -f $(DESTDIR)$(MAN8DIR)/chkbounce.8

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/chkbounce
	rm -f $(DESTDIR)$(MAN8DIR)/chkbounce.8.gz

clean:
	rm -f $(PROGS) $(OBJS)

.PHONY: all install uninstall clean
