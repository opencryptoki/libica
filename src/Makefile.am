VERSION = 3:3:1

AM_CFLAGS = @FLAGS@

# lib

lib_LTLIBRARIES = libica.la

libica_la_CFLAGS = ${AM_CFLAGS} -I${srcdir}/include -I${srcdir}/../include \
		   -fvisibility=hidden
libica_la_CCASFLAGS = ${AM_CFLAGS}
libica_la_LIBADD = @LIBS@ -lrt -lcrypto
libica_la_LDFLAGS = -Wl,--version-script=${srcdir}/../libica.map \
		    -version-number ${VERSION}
libica_la_SOURCES = ica_api.c init.c icastats_shared.c s390_rsa.c \
		    s390_crypto.c s390_ecc.c s390_prng.c s390_sha.c \
		    s390_drbg.c s390_drbg_sha512.c test_vec.c fips.c \
		    mp.S	\
		    include/fips.h include/icastats.h include/init.h \
		    include/s390_aes.h include/s390_cbccs.h \
		    include/s390_ccm.h include/s390_cmac.h \
		    include/s390_common.h include/s390_crypto.h \
		    include/s390_ctr.h include/s390_des.h \
		    include/s390_drbg.h include/s390_drbg_sha512.h \
		    include/s390_ecc.h include/s390_gcm.h include/s390_prng.h \
		    include/s390_rsa.h include/s390_sha.h include/test_vec.h

EXTRA_DIST = mp.pl
mp.S	: mp.pl
	./mp.pl mp.S

# bin

bin_PROGRAMS = icainfo icastats

icainfo_CFLAGS = ${AM_CFLAGS} -I${srcdir}/include -I${srcdir}/../include
icainfo_LDADD = @LIBS@ libica.la
icainfo_SOURCES = icainfo.c include/fips.h include/s390_crypto.h \
		  ../include/ica_api.h

icastats_CFLAGS = ${AM_CFLAGS} -I${srcdir}/include
icastats_LDADD = @LIBS@ -lrt
icastats_SOURCES = icastats.c icastats_shared.c include/icastats.h
