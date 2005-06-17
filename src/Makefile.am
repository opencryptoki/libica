include ../Makefile.macros
bin_PROGRAMS=libica.so
bindir=$(INSROOT)/usr/lib

libica_so_LDFLAGS = -shared $(LIBCRYPTO)

CFLAGS = $(S390_FLAG) $(PERFFLAG) -shared -fPIC -D_REENTRANT -I../include

INCLUDES = -I ./inc -I ../include

libica_so_SOURCES = ansipran.c genprime.c icalinux.c init.c mp_hw.c mp_modul.c \
                    mp_util.c mpsubadd.c prand.c rsa.c rsakygen.c sha1.c sieve.c\
                    x931prim.c

install-data-local:
	cp ../include/ica_api.h $(INSROOT)/usr/include

