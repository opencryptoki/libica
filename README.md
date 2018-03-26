# libica

Linux on z Systems crypto library


## configure options

`--enable-fips` : enable FIPS build

`--enable-debug` : enable debug build

`--enable-sanitizer` : enable sanitizer build (libasan and libubsan required)

`--enable-coverage` : enable coverage testing build (gcov required)

See `configure -help`.


## make targets

`make` : build the library and the tools

`make check` : build and run the test-suite

`make (un)install` : (un)install the library and the tools

`make coverage` : build and run the test-suite plus coverage tests (`--enable-coverage` required)

See the INSTALL file.
