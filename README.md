# libica

Linux on z Systems crypto library


## configure options

`--enable-fips` : enable FIPS build

`--enable-debug` : enable debug build

`--enable-sanitizer` : enable sanitizer build (libasan and libubsan required)

`--enable-coverage` : enable coverage testing build (gcov required)

`--enable-internal-tests` : build internal tests

See `configure -help`.


## make targets

`make` : build the library and the tools

`make check` : build and run the test-suite

`make (un)install` : (un)install the library and the tools

`make coverage` : build and run the test-suite plus coverage tests (`--enable-coverage` required)

See the INSTALL file.


## requirements

ECC via shared CEX4C adapter under z/VM 6.4 requires APAR VM65942


## documentation

[libica Programmer's Reference](https://www.ibm.com/support/knowledgecenter/en/linuxonibm/com.ibm.linux.z.lxci/lxci_linuxonz.html)
