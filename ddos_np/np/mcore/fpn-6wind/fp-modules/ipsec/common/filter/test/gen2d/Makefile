CC=gcc
LD=ld
AR=ar
RANLIB=ranlib

CFLAGS+= -Wextra -Wall -Werror
#CFLAGS+= -O0 -g
CFLAGS+= -O2

CFLAGS+= -I.

COMPILE= $(CC) $(CFLAGS) -MMD -o $@ -c $<

PROGS= gen2d
all: $(PROGS)

.PHONY: $(PROGS)

gen2d.o: gen2d.c
	$(COMPILE)

gen2d: gen2d.c
	$(CC) $(LDFLAG) -o $@ $^

clean:
	rm -f *.o $(PROGS) *.a *.d

-include *.d

