Name:          libica
Version:       3.5.0
Release:       1%{?dist}
Summary:       Interface library to the ICA device driver

Group:         Libraries/Crypto
License:       CPL
URL:           https://github.com/opencryptoki/libica
Source0:       %{name}-%{version}.tar.gz
BuildRoot:     %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf automake libtool openssl-devel

%description
Interface library on Linux for IBM System z to utilize CPACF
functions and cryptographic processors.


%package devel
Summary:       Interface library to the ICA device driver
Group:         Libraries/Crypto
Requires:      libica = %{version}-%{release}, glibc-devel

%description devel
Interface library on Linux for IBM System z to utilize CPACF
functions and cryptographic processors.


%prep
%setup -q -n %{name}-%{version}


%build
autoreconf --force --install
%configure --disable-static
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
rm -f $RPM_BUILD_ROOT/%{_libdir}/*.la


%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%doc LICENSE INSTALL AUTHORS README.md ChangeLog
%{_mandir}/man*/*
%{_bindir}/*
%attr(755,root,root) %{_libdir}/*

%files devel
%doc LICENSE
%defattr(-,root,root,-)
%{_includedir}/ica_api.h

%changelog
* Tue Apr 23 2019 Patrick Steuer <steuer@linux.vnet.ibm.com>
- Version v3.5.0
* Fri Nov 08 2018 Patrick Steuer <steuer@linux.vnet.ibm.com>
- Version v3.4.0
* Fri Jun 08 2018 Patrick Steuer <steuer@linux.vnet.ibm.com>
- Version v3.3.3
* Tue Apr 17 2018 Patrick Steuer <steuer@linux.vnet.ibm.com>
- Version v3.3.2
* Mon Apr 16 2018 Patrick Steuer <steuer@linux.vnet.ibm.com>
- Version v3.3.1
* Fri Apr 13 2018 Patrick Steuer <steuer@linux.vnet.ibm.com>
- Version v3.3.0
* Wed Feb 28 2018 Patrick Steuer <steuer@linux.vnet.ibm.com>
- Version v3.2.1
* Tue Sep 19 2017 Patrick Steuer <steuer@linux.vnet.ibm.com>
- Version v3.2.0
* Fri Sep 08 2017 Patrick Steuer <steuer@linux.vnet.ibm.com>
- Version v3.1.1
* Wed Jun 28 2017 Patrick Steuer <steuer@linux.vnet.ibm.com>
- Version v3.1.0
* Tue Jan 17 2017 Patrick Steuer <steuer@linux.vnet.ibm.com>
- Version v3.0.2
* Wed Nov 23 2016 Patrick Steuer <steuer@linux.vnet.ibm.com>
- Version v3.0.1
* Tue Oct 25 2016 Patrick Steuer <steuer@linux.vnet.ibm.com>
- Version v3.0.0
* Tue Mar 22 2016 Ingo Tuchscherer <ingo.tuchscherer@linux.vnet.ibm.com>
- Version v2.6.2
* Fri Feb 26 2016 Ingo Tuchscherer <ingo.tuchscherer@linux.vnet.ibm.com>
- Version v2.6.1
* Thu Feb 18 2016 Ingo Tuchscherer <ingo.tuchscherer@linux.vnet.ibm.com>
- Version v2.6.0
* Wed Nov 11 2015 Ingo Tuchscherer <ingo.tuchscherer@linux.vnet.ibm.com>
- Version v2.5.0
* Tue Jun 17 2014 Ingo Tuchscherer <ingo.tuchscherer@linux.vnet.ibm.com>
- Version v2.4.0
* Wed Mar 20 2013 Ingo Tuchscherer <ingo.tuchscherer@linux.vnet.ibm.com>
- Version v2.3.0
* Mon Feb 13 2012 Holger Dengler <hd@linux.vnet.ibm.com>
- Version v2.2.0
* Mon Sep 12 2011 Holger Dengler <hd@linux.vnet.ibm.com>
- Bugfix version v2.1.1
* Mon May 09 2011 Holger Dengler <hd@linux.vnet.ibm.com>
- Version v2.1.0
* Sat Mar 05 2011 Holger Dengler <hd@linux.vnet.ibm.com>
- Bugfix version 2.0.6
* Sat Mar 05 2011 Holger Dengler <hd@linux.vnet.ibm.com>
- Bugfix version 2.0.5
* Thu Sep 30 2010 Rainer Wolafka <rwolafka@de.ibm.com>
- Bugfix version 2.0.4
* Thu Apr 15 2010 Ruben Straus <rstraus@de.ibm.com>
- Bugfixes version 2.0.3
* Wed Aug 12 2009 Felix Beck <felix.beck@de.ibm.com>
- Bugfixes version 2.0.2
* Wed Feb 4 2009 Felix Beck <felix.beck@de.ibm.com
- version 2.0
* Fri Aug 4 2006 Daniel H Jones <danjones@us.ibm.com>
- initial file created
