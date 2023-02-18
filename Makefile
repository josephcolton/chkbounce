

PROGS=chkbounce
OBJS=global.o packets.o
INCLUDES=global.h packets.h

all: $(PROGS)

global.o: global.c global.h
	gcc global.c -c

packets.o: packets.c packets.h global.h
	gcc packets.c -c

chkbounce: chkbounce.c $(OBJS) $(INCLUDES)
	gcc chkbounce.c -o chkbounce $(OBJS)

clean:
	rm $(PROGS) $(OBJS)

