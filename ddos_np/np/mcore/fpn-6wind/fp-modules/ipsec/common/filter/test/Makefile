CC=gcc
# Copyright(c) 2007 6WIND

OBJS= egt-pc.o pool.o test_file.o classifier.o binary_tree.o main.o rfc.o dheap.o

CFLAGS+= -Wextra -Wall -Wunused -Werror
CFLAGS+= -O2 -g
#CFLAGS+= -O0 -g
CFLAGS+= -I..
CFLAGS+= -I.
CFLAGS+= -I../../common
CFLAGS+= -I../../../../fpn-sdk

CFLAGS+= -DFPN_MAX_CORES=1
CFLAGS+= -DRFC_PHASE=4

trie: $(OBJS) ../egt-pc/egt-pc.h ../filter.h ../pool.h ../rfc/dheap.c ../rfc/dheap.h 
	$(CC) $(CFLAGS) $(OBJS) -o trie

egt-pc.o: ../egt-pc/egt-pc.c ../egt-pc/egt-pc.h ../filter.h ../pool.h
	$(CC) $(CFLAGS) -o egt-pc.o -c ../egt-pc/egt-pc.c

classifier.o:  ../classif/classifier_error.h ../classif/classifier.h ../pool.h
	$(CC) $(CFLAGS)  -o classifier.o -c ../classif/classifier.c

binary_tree.o:  ../classif/binary_tree.h
	$(CC) $(CFLAGS) -o binary_tree.o -c ../classif/binary_tree.c

main.o: main.c ../filter.h ../trie.h ../egt-pc/egt-pc.h
	$(CC) $(CFLAGS) -c main.c

pool.o: ../pool.c ../pool.h
	$(CC) $(CFLAGS) -o pool.o -c ../pool.c

test_file.o: test_file.c ../filter.h test_file.h
	$(CC) $(CFLAGS) -c test_file.c

rfc.o: ../filter.h ../rfc/rfc.h ../rfc/dheap.h ../rfc/rfc.c
	$(CC) $(CFLAGS) -c ../rfc/rfc.c

dheap.o: ../filter.h ../rfc/dheap.h
	$(CC) $(CFLAGS) -c ../rfc/dheap.c

clean:
	rm -f *.o trie
