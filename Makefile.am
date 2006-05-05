SUBDIRS = src include

rpm: 
	rm -rf /usr/src/libica
	mkdir -p /usr/src/libica/RPMS/$(shell uname -m)
	mkdir -p /usr/src/libica/SRPMS
	mkdir -p /usr/src/libica/SPEC
	mkdir -p /usr/src/libica/SOURCES
	mkdir -p /usr/src/libica/BUILD
	tar zcf /usr/src/libica/SOURCES/libica.tar.gz ./*
	rpmbuild -bb libica.spec

.PHONY: rpm
