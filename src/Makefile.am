VERSION = 4:2:3

AM_CFLAGS = @FLAGS@
MAJOR := `echo $(VERSION) | cut -d: -f1`
MINOR := `echo $(VERSION) | cut -d: -f2`
PATCH := `echo $(VERSION) | cut -d: -f3`
VERSION1 := $(MAJOR).$(MINOR).$(PATCH)

DEFAULT_BUILD_VERSION := "UNSPECIFIED"
BUILD_VERSION := $(DEFAULT_BUILD_VERSION)

# lib

lib_LTLIBRARIES = libica.la libica-cex.la

CFLAGS_common = ${AM_CFLAGS} -DNO_SW_FALLBACKS -I${srcdir}/include -I${srcdir}/../include \
		   -DLIBICA_CONFDIR=\"${sysconfdir}\" \
		   -DBUILD_VERSION="\"$(BUILD_VERSION)\"" \
		   -fvisibility=hidden -pthread
LIBS_common = @LIBS@ -lrt -lcrypto -ldl
LDFLAGS_common = -Wl,--version-script=${srcdir}/../libica.map \
		    -version-number ${VERSION}
SOURCES_common = ica_api.c init.c icastats_shared.c s390_rsa.c \
		    s390_crypto.c s390_ecc.c s390_prng.c s390_sha.c \
		    s390_drbg.c s390_drbg_sha512.c test_vec.c fips.c \
		    mp.S rng.c \
		    include/fips.h include/icastats.h include/init.h \
		    include/s390_aes.h include/s390_cbccs.h \
		    include/s390_ccm.h include/s390_cmac.h \
		    include/s390_common.h include/s390_crypto.h \
		    include/s390_ctr.h include/s390_des.h \
		    include/s390_drbg.h include/s390_drbg_sha512.h \
		    include/s390_ecc.h include/s390_gcm.h include/s390_prng.h \
		    include/s390_rsa.h include/s390_sha.h include/test_vec.h \
		    include/rng.h

libica_la_CFLAGS = ${CFLAGS_common} -DLIBNAME=\"libica\"
libica_la_CCASFLAGS = ${AM_CFLAGS}
libica_la_LIBADD = ${LIBS_common}
libica_la_LDFLAGS = ${LDFLAGS_common}
libica_la_SOURCES = ${SOURCES_common}

libica_cex_la_CFLAGS = ${CFLAGS_common} -DNO_CPACF -DLIBNAME=\"libica-cex\"
libica_cex_la_CCASFLAGS = ${AM_CFLAGS}
libica_cex_la_LIBADD = ${LIBS_common}
libica_cex_la_LDFLAGS = ${LDFLAGS_common}
libica_cex_la_SOURCES = ${SOURCES_common}

EXTRA_DIST = mp.pl perlasm/s390x.pm
mp.S	: mp.pl
	./mp.pl mp.S

if ICA_FIPS
fipsinstall:
	$(AM_V_GEN) openssl dgst -sha256 -mac hmac -macopt hexkey:00000000 $(DESTDIR)$(libdir)/libica.so.$(VERSION1) | sed -e 's/^.* //' > $(DESTDIR)$(libdir)/.libica.so.$(VERSION1).hmac
	$(AM_V_GEN) cd $(DESTDIR)$(libdir) && ln -sf .libica.so.$(VERSION1).hmac .libica.so.$(MAJOR).hmac
	$(AM_V_GEN) openssl dgst -sha256 -mac hmac -macopt hexkey:00000000 $(DESTDIR)$(libdir)/libica-cex.so.$(VERSION1) | sed -e 's/^.* //' > $(DESTDIR)$(libdir)/.libica-cex.so.$(VERSION1).hmac
	$(AM_V_GEN) cd $(DESTDIR)$(libdir) && ln -sf .libica-cex.so.$(VERSION1).hmac .libica-cex.so.$(MAJOR).hmac

hmac-file-lnk: hmac-file
	$(AM_V_GEN) cd ${top_builddir}/src/.libs && ln -sf .libica.so.$(VERSION1).hmac .libica.so.$(MAJOR).hmac
	$(AM_V_GEN) cd ${top_builddir}/src/.libs && ln -sf .libica-cex.so.$(VERSION1).hmac .libica-cex.so.$(MAJOR).hmac

hmac-file: libica.la libica-cex.la
	$(AM_V_GEN) openssl dgst -sha256 -mac hmac -macopt hexkey:00000000 ${top_builddir}/src/.libs/libica.so.$(VERSION1) | sed -e 's/^.* //' > ${top_builddir}/src/.libs/.libica.so.$(VERSION1).hmac
	$(AM_V_GEN) openssl dgst -sha256 -mac hmac -macopt hexkey:00000000 ${top_builddir}/src/.libs/libica-cex.so.$(VERSION1) | sed -e 's/^.* //' > ${top_builddir}/src/.libs/.libica-cex.so.$(VERSION1).hmac

hmac_files = hmac-file hmac-file-lnk

all-local: $(hmac_files)
endif

# bin

bin_PROGRAMS = icainfo icastats icainfo-cex

icainfo_CFLAGS_COMMON = ${AM_CFLAGS} -DNO_SW_FALLBACKS -I${srcdir}/include -I${srcdir}/../include \
					   -DDEFAULT_BUILD_VERSION="\"$(DEFAULT_BUILD_VERSION)\"" \
					   -DBUILD_VERSION="\"$(BUILD_VERSION)\""
icainfo_LDADD_COMMON = @LIBS@ -lcrypto
icainfo_SOURCES_COMMON = icainfo.c include/fips.h include/s390_crypto.h \
		  ../include/ica_api.h

icainfo_CFLAGS = ${icainfo_CFLAGS_COMMON}
icainfo_LDADD = ${icainfo_LDADD_COMMON} libica.la
icainfo_SOURCES = ${icainfo_SOURCES_COMMON}

icainfo_cex_CFLAGS = ${icainfo_CFLAGS_COMMON} -DNO_CPACF
icainfo_cex_LDADD = ${icainfo_LDADD_COMMON} libica-cex.la
icainfo_cex_SOURCES = ${icainfo_SOURCES_COMMON}

icastats_CFLAGS = ${AM_CFLAGS} -I${srcdir}/include -I${srcdir}/../include -DICASTATS
icastats_LDADD = @LIBS@ -lrt
icastats_SOURCES = icastats.c icastats_shared.c include/icastats.h

# internal tests

if ICA_INTERNAL_TESTS
noinst_PROGRAMS = internal_tests/ec_internal_test

internal_tests_ec_internal_test_CFLAGS = ${AM_CFLAGS} -I${srcdir}/include \
					 -I${srcdir}/../include	\
					 -DICA_INTERNAL_TEST \
					 -DICA_INTERNAL_TEST_EC \
					 -DLIBNAME=\"libica\" \
					 -DLIBICA_CONFDIR=\"${sysconfdir}\" \
					 -DBUILD_VERSION="\"$(BUILD_VERSION)\""
internal_tests_ec_internal_test_CCASFLAGS = ${AM_CFLAGS}
internal_tests_ec_internal_test_LDADD = @LIBS@ -lrt -lcrypto -lpthread -ldl
internal_tests_ec_internal_test_SOURCES = \
		    ica_api.c init.c icastats_shared.c s390_rsa.c \
		    s390_crypto.c s390_ecc.c s390_prng.c s390_sha.c \
		    s390_drbg.c s390_drbg_sha512.c test_vec.c fips.c \
		    mp.S rng.c \
		    include/fips.h include/icastats.h include/init.h \
		    include/s390_aes.h include/s390_cbccs.h \
		    include/s390_ccm.h include/s390_cmac.h \
		    include/s390_common.h include/s390_crypto.h \
		    include/s390_ctr.h include/s390_des.h \
		    include/s390_drbg.h include/s390_drbg_sha512.h \
		    include/s390_ecc.h include/s390_gcm.h include/s390_prng.h \
		    include/s390_rsa.h include/s390_sha.h include/test_vec.h \
		    include/rng.h ../test/testcase.h
endif

.PHONY: hmac-file hmac-file-lnk fipsinstall

CLEANFILES = mp.S
MAINTAINERCLEANFILES = Makefile.in
