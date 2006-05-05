bin_PROGRAMS=libica.so
bindir=$(INSROOT)$(libdir)

INCLUDES = -I ./inc -I ../include

libica_so_LDFLAGS = -shared 

libica_so_CFLAGS = -shared -fPIC -D_REENTRANT -I../include


libica_so_SOURCES = ansipran.c genprime.c icalinux.c init.c mp_hw.c mp_modul.c \
                    mp_util.c mpsubadd.c prand.c rsa.c rsakygen.c sha1.c sieve.c\
                    x931prim.c

