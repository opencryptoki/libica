SUBDIRS = src

rpm: 
	mkdir -p /usr/src/libica/RPMS
	mkdir -p /usr/src/libica/SRPMS
	mkdir -p /usr/src/libica/SOURCES
	mkdir -p /usr/src/libica/BUILD
	tar -cvf /usr/src/libica/SOURCES/libica.tar ./*
	rpmbuild -bb libica-1.1-4.spec || rpm -bb libica-1.1-4.spec
