INCLUDES = -I ./include -I ../include

lib_LTLIBRARIES = libica.la

libica_la_LDFLAGS = -release $(PACKAGE_VERSION) -lrt -lcrypto

libica_la_SOURCES = icalinux.c ica_api.c init.c icastats_shared.c \
		    s390_rsa.c s390_crypto.c s390_common.c s390_des.c \
		    s390_aes.c s390_prng.c s390_sha.c opencryptoki_api.c \
		    s390_cmac.c s390_ctr.c s390_cbccs.c s390_ccm.c s390_gcm.c

bin_PROGRAMS = icainfo icastats

icainfo_LDADD = libica.la

icainfo_SOURCES = icainfo.c

icastats_LDADD = libica.la

icastats_SOURCES = icastats.c

