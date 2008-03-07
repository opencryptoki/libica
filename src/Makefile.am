INCLUDES = -I ./inc -I ../include

lib_LTLIBRARIES = libica.la

libica_la_LDFLAGS = -release $(PACKAGE_VERSION)

libica_la_SOURCES = ansipran.c genprime.c icalinux.c init.c mp_hw.c mp_modul.c \
                    mp_util.c mpsubadd.c prand.c rsa.c rsakygen.c sha1.c sieve.c\
                    x931prim.c sha256.c sha512.c

bin_PROGRAMS = icainfo

icainfo_SOURCES = icainfo.c
