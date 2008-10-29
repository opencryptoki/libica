Name:          libica 
Version:       1.3.9.1
Release:       1%{?dist}
Summary:       Interface library to the ICA device driver 

Group:         Libraries/Crypto 
License:       CPL 
URL:           http://sourceforge.net/projects/opencryptoki 
Source0:       %{name}-%{version}.tar.bz2 
BuildRoot:     %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf automake libtool

%description
Interface library routines used by IBM modules to interface to the IBM
eServer Cryptographic Accelerator (ICA).


%package devel
Summary:       Interface library to the ICA device driver
Group:         Libraries/Crypto 
Requires:      libica = %{version}-%{release}, glibc-devel

%description devel
Interface library routines used by IBM modules to interface to the IBM
eServer Cryptographic Accelerator (ICA).


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
%doc LICENSE README INSTALL
%{_bindir}/*
%attr(755,root,root) %{_libdir}/*

%files devel
%doc LICENSE
%defattr(-,root,root,-)
%{_includedir}/ica_api.h

%changelog
* Fri Aug 4 2006 Daniel H Jones <danjones@us.ibm.com>
- initial file created

