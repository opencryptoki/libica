Name:          libica 
Version:       2.0
Release:       5%{?dist}
Summary:       Interface library to the ICA device driver 

Group:         Libraries/Crypto 
License:       CPL 
URL:           http://sourceforge.net/projects/opencryptoki 
Source0:       %{name}-%{version}.tar.bz2 
BuildRoot:     %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf automake libtool

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


%files
%defattr(-,root,root,-)
%doc LICENSE INSTALL
%{_bindir}/*
%attr(755,root,root) %{_libdir}/*

%files devel
%doc LICENSE
%defattr(-,root,root,-)
%{_includedir}/ica_api.h

%changelog
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
