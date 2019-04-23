AC_INIT([libica], [3.5.0], [steuer@linux.vnet.ibm.com],, [https://github.com/opencryptoki/libica])

# save cmdline flags
cmdline_CFLAGS="$CFLAGS"

AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_SRCDIR([src/ica_api.c])

AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL

AC_CHECK_HEADERS([fcntl.h memory.h stddef.h stdint.h stdlib.h string.h strings.h sys/file.h sys/ioctl.h sys/time.h syslog.h unistd.h])

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

AM_PROG_AS
LT_INIT
AM_INIT_AUTOMAKE([-Wall -Wno-portability foreign])

FLAGS="-Wall -Wextra -mzarch"

dnl --- enable_debug
AC_ARG_ENABLE(debug,
              [  --enable-debug          turn on debugging flags],
              [enable_debug="yes"],[enable_debug="no"])
AM_CONDITIONAL(DEBUG, test x$enable_debug = xyes)

if test "x$enable_debug" = xyes; then
	FLAGS="$FLAGS -g -O0"
	AC_MSG_RESULT([*** Enabling debugging at user request ***])
fi

dnl --- enable_coverage
AC_ARG_ENABLE(coverage,
              [  --enable-coverage       turn on coverage testing],
              [enable_coverage="yes"],[enable_coverage="no"])
AM_CONDITIONAL(COVERAGE, test x$enable_coverage = xyes)

if test "x$enable_coverage" = xyes; then
	FLAGS="$FLAGS -g -O0 -fprofile-arcs -ftest-coverage"
	AC_MSG_RESULT([*** Enabling coverage testing at user request ***])
fi

dnl --- enable_fips
AC_ARG_ENABLE(fips,
              [  --enable-fips           built with FIPS mode support],
              [enable_fips="yes"],[enable_fips="no"])
AM_CONDITIONAL(ICA_FIPS, test x$enable_fips = xyes)

if test "x$enable_fips" = xyes; then
	FLAGS="$FLAGS -DICA_FIPS"
	AC_MSG_RESULT([*** Building libica-fips at user request ***])
fi

dnl --- enable_sanitizer
AC_ARG_ENABLE(sanitizer,
              [  --enable-sanitizer      turn on sanitizer (may not work on all systems)],
              [enable_sanitizer="yes"],[enable_sanitizer="no"])
AM_CONDITIONAL(SANITIZER, test x$enable_sanitizer = xyes)

if test "x$enable_sanitizer" = xyes; then
	FLAGS="$FLAGS -O3 -g -fstack-protector-all -fsanitize=address,signed-integer-overflow,undefined -Wformat-security -Werror=format-security -Warray-bounds -Werror=array-bounds -D_FORTIFY_SOURCE=2"
	LIBS="-lubsan -lasan"
	AC_MSG_RESULT([*** Enabling sanitizer at user request ***])
fi

dnl --- enable_internal tests
AC_ARG_ENABLE(internal_tests,
              [  --enable-internal-tests built internal tests],
              [enable_internal_tests="yes"],[enable_internal_tests="no"])
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
