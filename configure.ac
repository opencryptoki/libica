AC_INIT([libica], [4.3.0], [https://github.com/opencryptoki/libica/issues],, [https://github.com/opencryptoki/libica])

# save cmdline flags
cmdline_CFLAGS="$CFLAGS"

AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_SRCDIR([src/ica_api.c])
AC_CONFIG_MACRO_DIRS([m4])

AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL

AC_CHECK_HEADERS([fcntl.h memory.h stddef.h stdint.h stdlib.h string.h strings.h sys/file.h sys/ioctl.h sys/time.h syslog.h unistd.h])

AC_CHECK_HEADER([openssl/evp.h], [], [
	AC_MSG_ERROR([OpenSSL 1.1.1 or later is required but OpenSSL headers couldn't be found])
])

AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([bzero ftruncate gettimeofday memchr memset munmap strcasecmp strerror strstr strtol setenv strtoull])

AC_CHECK_LIB([crypto], [EVP_sha3_256], [], [
	AC_MSG_ERROR([OpenSSL 1.1.1 or later is required but OpenSSL libraries version 1.1.1 or later couldn't be found])
])

AM_PROG_AS
LT_INIT
AM_INIT_AUTOMAKE([-Wall -Wno-portability foreign])

FLAGS="-Wall -Wextra -mzarch"

dnl --- check for perl
AC_PATH_PROG(PERL, perl)
if test -z "$PERL" ; then
	AC_MSG_ERROR([Please install perl])
fi

dnl --- check for perl-FindBin module
AC_MSG_CHECKING([if perl module 'FindBin' is installed])
(echo "use FindBin;" ; echo "exit(0);") | $PERL > /dev/null 2>&1
if test $? != 0 ; then
	AC_MSG_RESULT(no)
	AC_MSG_ERROR([Please install perl-FindBin])
fi
AC_MSG_RESULT(yes)

dnl --- enable_debug
AC_ARG_ENABLE(debug,
              [  --enable-debug          turn on debugging flags],
              [],[enable_debug="no"])
AM_CONDITIONAL(DEBUG, test x$enable_debug = xyes)

if test "x$enable_debug" = xyes; then
	FLAGS="$FLAGS -g -O0"
	AC_MSG_RESULT([*** Enabling debugging at user request ***])
fi

dnl --- enable_coverage
AC_ARG_ENABLE(coverage,
              [  --enable-coverage       turn on coverage testing],
              [],[enable_coverage="no"])
AM_CONDITIONAL(COVERAGE, test x$enable_coverage = xyes)

if test "x$enable_coverage" = xyes; then
	FLAGS="$FLAGS -g -O0 -fprofile-arcs -ftest-coverage"
	AC_MSG_RESULT([*** Enabling coverage testing at user request ***])
fi

dnl --- enable_fips
AC_ARG_ENABLE(fips,
              [  --enable-fips           built with FIPS mode support],
              [],[enable_fips="no"])
AM_CONDITIONAL(ICA_FIPS, test x$enable_fips = xyes)

AC_CHECK_LIB([crypto], [OSSL_PROVIDER_load], [openssl3=yes], [])
AM_CONDITIONAL(ICA_OPENSSL3, test x$openssl3 = xyes)

if test "x$enable_fips" = xyes; then
	FLAGS="$FLAGS -DICA_FIPS"
	AC_MSG_RESULT([*** Building libica-fips at user request ***])
    AC_CHECK_PROG([openssl_var],[openssl],[yes],[no])
    if test "x$openssl_var" != xyes; then
        AC_MSG_ERROR([Missing openssl binary application required for FIPS build])
    fi
    if test "x$openssl3" = "xyes"; then
        FIPSDIR=`openssl version -d | cut -f 2- -d ' ' | tr -d \"`
        AC_SUBST(FIPSDIR)
        AC_CONFIG_FILES([src/openssl3-fips.cnf])
    fi
fi

dnl --- enable_sanitizer
AC_ARG_ENABLE(sanitizer,
              [  --enable-sanitizer      turn on sanitizer (may not work on all systems)],
              [],[enable_sanitizer="no"])
AM_CONDITIONAL(SANITIZER, test x$enable_sanitizer = xyes)

if test "x$enable_sanitizer" = xyes; then
	FLAGS="$FLAGS -O3 -g -fstack-protector-all -fsanitize=address,signed-integer-overflow,undefined -Wformat-security -Werror=format-security -Warray-bounds -Werror=array-bounds -D_FORTIFY_SOURCE=2"
	LIBS="-lubsan -lasan"
	AC_MSG_RESULT([*** Enabling sanitizer at user request ***])
fi

dnl --- enable_internal tests
AC_ARG_ENABLE(internal_tests,
              [  --enable-internal-tests built internal tests],
              [],[enable_internal_tests="no"])
AM_CONDITIONAL(ICA_INTERNAL_TESTS, test x$enable_internal_tests = xyes)

if test "x$enable_internal_tests" = xyes; then
	AC_MSG_RESULT([*** Building internal tests at user request ***])
fi



if test "x$enable_coverage" = xno && test "x$enable_debug" = xno && test "x$enable_sanitizer" = xno; then
	FLAGS="$FLAGS -O3 -D_FORTIFY_SOURCE=2"
fi

# restore cmdline flags (ignore PROG_AS/PROG_CC defaults)
CFLAGS="$cmdline_CFLAGS"
CCASFLAGS="$cmdline_CFLAGS"

AC_SUBST([FLAGS], $FLAGS)
AC_SUBST([LIBS], $LIBS)
AC_CONFIG_FILES([Makefile doc/Makefile include/Makefile src/Makefile test/Makefile])
AC_OUTPUT

echo "FLAGS=$FLAGS $CFLAGS"
echo "LIBS=$LIBS"

echo "Enabled features:"
echo "  FIPS build:      $enable_fips"
echo "  Debug build:     $enable_debug"
echo "  Sanitizer build: $enable_sanitizer"
echo "  Coverage build:  $enable_coverage"
echo "  Internal tests:  $enable_internal_tests"
