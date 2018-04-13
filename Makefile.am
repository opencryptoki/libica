ACLOCAL_AMFLAGS = -I m4

SUBDIRS = doc include src test

dist_doc_DATA = AUTHORS ChangeLog INSTALL LICENSE README.md
EXTRA_DIST = libica.map libica.spec

coverage: check
	@echo -e "\n-----------------";
	@echo -e "icastats coverage";
	@echo -e "-----------------\n";
	cd ${top_builddir}/src && gcov *.gcda
	@echo -e "\n---------------";
	@echo -e "libica coverage";
	@echo -e "---------------\n";
	cd ${top_builddir}/src && gcov .libs/*.gcda
