OPTS = -O0 -g -Wall -D_LINUX_S390_
LIBS = -L../../.libs
INCLUDE = -I. -I./include -I../../../include
SOURCES = libica_sha_test.c queue_t.c sha_tests.c read_rsp.c
CC = gcc
FILES = libica_sha_test.c~ \
	libica_sha_test.o	\
	queue_t.c~	\
	queue_t.o	\
	include/queue_t.h~ \
	sha_tests.c~ \
	sha_tests.o	\
	include/sha_tests.h~ \
	read_rsp.c~ \
	include/read_rsp.h~ \
	include/critical_error.h~

all:
	$(CC) $(OPTS) $(LIBS) $(INCLUDE) -lica -lcrypto -o libica_sha_test $(SOURCES)

clean:
	rm -f libica_sha_test

distclean:
	rm -f Makefile
	rm -f $(FILES)
