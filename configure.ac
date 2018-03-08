AC_PREREQ([2.69])
AC_INIT([libica], [3.3.0], [steuer@linux.vnet.ibm.com],, [https://github.com/opencryptoki/libica])
AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_SRCDIR([src/ica_api.c])
AC_CONFIG_MACRO_DIRS([m4])

AC_PROG_CC
AC_PROG_INSTALL

AC_CHECK_HEADERS([fcntl.h memory.h stddef.h stdint.h stdlib.h string.h strings.h sys/file.h sys/ioctl.h sys/time.h syslog.h unistd.h])

AC_CHECK_HEADER_STDBOOL
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
AC_CHECK_FUNCS([bzero ftruncate gettimeofday memchr memset munmap strcasecmp strerror strstr strtol])

AM_PROG_AR

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
LT_INIT

CFLAGS="-Wall -Wextra"

dnl --- enable_debug
AC_ARG_ENABLE(debug,
              [--enable-debug          turn on debugging flags],
              [enable_debug="yes"],[enable_debug="no"])
AM_CONDITIONAL(DEBUG, test x$enable_debug = xyes)

if test "x$enable_debug" = xyes; then
	CFLAGS="$CFLAGS -g -O0"
	AC_MSG_RESULT([*** Enabling debugging at user request ***])
else
	CFLAGS="$CFLAGS -O3"
fi

dnl --- enable_fips
AC_ARG_ENABLE(fips,
              [--enable-fips          built with FIPS mode support],
              [enable_fips="yes"],[enable_fips="no"])
AM_CONDITIONAL(ICA_FIPS, test x$enable_fips = xyes)

if test "x$enable_fips" = xyes; then
	CFLAGS="$CFLAGS -DICA_FIPS"
	AC_MSG_RESULT([*** Building libica-fips at user request ***])
fi

dnl --- enable_sanitizer
AC_ARG_ENABLE(sanitizer,
              [--enable-sanitizer    turn on sanitizer (may not work with all compiler versions)],
              [enable_sanitizer="yes"],[enable_sanitizer="no"])
AM_CONDITIONAL(SANITIZER, test x$enable_sanitizer = xyes)

if test "x$enable_sanitizer" = xyes; then
	CFLAGS="$CFLAGS -g -fstack-protector-all -fsanitize=address,signed-integer-overflow,undefined -Wformat-security -Werror=format-security -Warray-bounds -Werror=array-bounds -D_FORTIFY_SOURCE=2"
	LDLIBS="-lubsan -lasan"
	AC_MSG_RESULT([*** Enabling sanitizer at user request ***])
else
	CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=1"
fi

AC_CONFIG_FILES([Makefile doc/Makefile include/Makefile src/Makefile test/Makefile])
AC_OUTPUT

echo "CFLAGS=$CFLAGS"

echo "Enabled features:"
echo "  FIPS build:      $enable_fips"
echo "  Debug build:     $enable_debug"
echo "  Sanitizer build: $enable_sanitizer"
