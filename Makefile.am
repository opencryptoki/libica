ACLOCAL_AMFLAGS = -I m4

SUBDIRS = doc include src test

dist_doc_DATA = AUTHORS ChangeLog INSTALL LICENSE README.md
EXTRA_DIST = libica.map libica.spec
MAJOR := `echo $(VERSION) | cut -d. -f1`

coverage: check
	@echo -e "\n-----------------";
	@echo -e "icastats coverage";
	@echo -e "-----------------\n";
	cd ${top_builddir}/src && gcov *.gcda
	@echo -e "\n---------------";
	@echo -e "libica coverage";
	@echo -e "---------------\n";
	cd ${top_builddir}/src && gcov .libs/*.gcda

if ICA_FIPS
install-data-hook:
	$(INSTALL) -m 0444 ${top_builddir}/src/.libs/.libica.so.$(VERSION).hmac $(DESTDIR)$(libdir)
	cd $(DESTDIR)$(libdir) && ln -sf .libica.so.$(VERSION).hmac .libica.so.$(MAJOR).hmac
	$(INSTALL) -m 0444 ${top_builddir}/src/.libs/.libica-cex.so.$(VERSION).hmac $(DESTDIR)$(libdir)
	cd $(DESTDIR)$(libdir) && ln -sf .libica-cex.so.$(VERSION).hmac .libica-cex.so.$(MAJOR).hmac
if ICA_OPENSSL3
	test -f $(DESTDIR)$(sysconfdir)/libica || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/libica
	test -f $(DESTDIR)$(sysconfdir)/libica/openssl3-fips.cnf || $(INSTALL) -m 644 ${top_builddir}/src/openssl3-fips.cnf $(DESTDIR)$(sysconfdir)/libica/openssl3-fips.cnf || true
endif

uninstall-hook:
	rm -f $(DESTDIR)$(libdir)/.libica.so.$(MAJOR).hmac
	rm -f $(DESTDIR)$(libdir)/.libica.so.$(VERSION).hmac
	rm -f $(DESTDIR)$(libdir)/.libica-cex.so.$(MAJOR).hmac
	rm -f $(DESTDIR)$(libdir)/.libica-cex.so.$(VERSION).hmac
if ICA_OPENSSL3
	rm -f $(sysconfdir)/libica/openssl3-fips.cnf
	if [ -d $(sysconfdir)/libica ]; then rm -rf $(sysconfdir)/libica; fi
endif
endif

