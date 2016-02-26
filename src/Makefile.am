INCLUDES = -I ./include -I ../include

lib_LTLIBRARIES = libica.la

libica_la_LDFLAGS = -version-number 2:6:1 $(PACKAGE_VERSION) -lrt -lcrypto
libica_la_SOURCES = icalinux.c ica_api.c init.c icastats_shared.c \
		    s390_rsa.c s390_crypto.c s390_common.c \
		    s390_prng.c s390_sha.c opencryptoki_api.c \
		    s390_drbg.c s390_drbg_sha512.c s390_drbg_test_vec.c

bin_PROGRAMS = icainfo icastats

icainfo_LDADD = libica.la
icainfo_SOURCES = icainfo.c

icastats_CFLAGS = $(AM_CFLAGS)
icastats_LDFLAGS = -lrt
icastats_SOURCES = icastats.c icastats_shared.c
