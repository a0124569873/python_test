#CC= mips64-octeon-linux-gnu-gcc
#CFLAGS+= -mabi=n32
#LDFLAGS+= -static

CC = gcc

CFLAGS+= -O2 -g -Wextra -Wall -Werror
CFLAGS+= -I. -I.. -I../..
CFLAGS+= -I../../../common
# phase 3 or 4
CFLAGS+= -DRFC_PHASE=4
#CFLAGS+= -DRFC_PHASE=3

# for PRINT_STAT
#CFLAGS+= -DPRINT_STAT 
#LDFLAGS+= -lm

#CFLAGS+= -DDEBUG 

#LDFLAGS+= ElectricFence/libefence.a

rfc: main.c ../rfc.c ../dheap.c  ../dheap.h ../rfc.h Makefile
	${CC} ${CFLAGS} -o rfc main.c ../rfc.c ../dheap.c  ${LDFLAGS}
#-lm

all: rfc 

clean:
	rm -f rfc

.PHONY: acl fw1 r1
acl: rfc
	./rfc -r acl1_1K -t acl1_1K_trace

acl10: rfc
	./rfc -r acl1_10K -t acl1_10K_trace

fw1: rfc
	./rfc -r fw1 -t fw1_trace

fw10: rfc
	./rfc -r fw1_10K -t fw1_10K_trace

r1: 
	./rfc -r r1 -t t1

