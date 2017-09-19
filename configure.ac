#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT(libica, 3.2.0, steuer@linux.vnet.ibm.com)

cmdline_CFLAGS="$CFLAGS"

# Compute $target
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE(1.9.5)

# Use extensions
AC_GNU_SOURCE

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h memory.h stdlib.h string.h strings.h sys/ioctl.h unistd.h \
		  errno.h stdio.h semaphore.h linux/types.h sys/ioctl.h])
case "$target" in
     *s390*)
          AC_CHECK_HEADERS([openssl/bn.h openssl/rsa.h openssl/rand.h \
				openssl/sha.h openssl/aes.h openssl/des.h],,
				AC_MSG_ERROR(openssl-devel package required))
          ;;
     *)
          AC_CHECK_HEADER(linux/icaioctl.h, ,
                          AC_MSG_ERROR([*** Unable to find linux/icaioctl.h]))
          ;;
esac



# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_C_VOLATILE

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_STAT
AC_CHECK_FUNCS([bzero memset])

CFLAGS="$cmdline_CFLAGS"
AX_PTHREAD
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

case $target in
     *s390x*)
          CFLAGS="$CFLAGS -D_LINUX_S390X_ -D_LINUX_S390_ -Wall -fvisibility=hidden -Wl,--version-script=../libica.map"
          ;;
     *s390*)
          CFLAGS="$CFLAGS -D_LINUX_S390_ -m31 -Wall -fvisibility=hidden -Wl,--version-script=../libica.map"
          ;;
esac

dnl --- enable_debug
AC_ARG_ENABLE(debug,
              [--enable-debug          turn on debugging flags],
              [enable_debug="yes"],[enable_debug="no"])
AM_CONDITIONAL(DEBUG, test x$enable_debug = xyes)

if test "x$enable_debug" = xyes; then
	CFLAGS="$CFLAGS -g -O0 -fstack-protector-all -DICA_DEBUG"
	AC_MSG_RESULT([*** Enabling debugging at user request ***])
else
	CFLAGS="$CFLAGS -O2"
fi

dnl --- enable_testcases
AC_ARG_ENABLE([testcases],
	AS_HELP_STRING([--enable-testcases],[build the test cases @<:@default=no@:>@]),
	[enable_testcases=yes],
	[enable_testcases=no])

if test "$enable_testcases" = yes; then
	MAYBE_OPT="src/tests src/tests/libica_sha_test/"
else
	MAYBE_OPT=
fi
AC_SUBST(MAYBE_OPT)

dnl --- enable_fips
AC_ARG_ENABLE(fips,
              [--enable-fips          built with FIPS mode support],
              [enable_fips="yes"],[enable_fips="no"])
AM_CONDITIONAL(ICA_FIPS, test x$enable_fips = xyes)

if test "x$enable_fips" = xyes; then
	CFLAGS="$CFLAGS -DICA_FIPS"
	AC_MSG_RESULT([*** Building libica-fips at user request ***])
fi

AC_CONFIG_FILES([src/tests/Makefile src/tests/libica_sha_test/Makefile])
AC_OUTPUT([Makefile src/Makefile include/Makefile doc/Makefile])

echo "CFLAGS=$CFLAGS"

echo "Enabled features:"
echo "  FIPS build:     $enable_fips"
echo "  Debug build:    $enable_debug"
echo "  Testcases:      $enable_testcases"
