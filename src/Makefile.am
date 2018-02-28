INCLUDES = -I ./include -I ../include

lib_LTLIBRARIES = libica.la

libica_la_LDFLAGS = -version-number 3:2:0 $(PACKAGE_VERSION) -lrt -lcrypto
libica_la_SOURCES = ica_api.c init.c icastats_shared.c \
		    s390_rsa.c s390_crypto.c \
		    s390_prng.c s390_sha.c s390_drbg.c s390_drbg_sha512.c \
		    test_vec.c fips.c

bin_PROGRAMS = icainfo icastats

icainfo_LDADD = libica.la
icainfo_SOURCES = icainfo.c

icastats_CFLAGS = $(AM_CFLAGS)
icastats_LDFLAGS = -lrt
icastats_SOURCES = icastats.c icastats_shared.c
