SUBDIRS=. tests

lib_LTLIBRARIES=libica.la

libica_la_LDFLAGS="-shared"
libica_la_CFLAGS="-shared -fPIC -D_REENTRANT -I../include"
libica_la_SOURCES=ansipran.c genprime.c icalinux.c init.c mp_hw.c mp_modul.c \
                  mp_util.c mpsubadd.c prand.c rsa.c rsakygen.c sha1.c sieve.c \
                  x931prim.c

install-data-local:
	cp ../include/ica_api.h $(INSROOT)/usr/include

