#! /bin/sh

set -x
if [ -f Makefile ] ; then
        make -k clean
fi
rm mkinstalldirs
rm aclocal.m4
rm -rf autom4te.cache
rm compile
rm config.*
rm configure
rm depcomp
rm install-sh
rm ltmain.sh
rm missing
rm libtool
find . -name Makefile -exec rm {} \;
find . -name Makefile.in -exec rm {} \;
find . -depth -name .deps -exec  rm -rf {} \;

