#
# Specfile for libica from IBM
#
Summary:  Interface library to the ICA device driver
Name: libica
Version: 1.3.5
Release: 3
Copyright: International Business Machines (2001)
Group: Libraries/Crypto
Source: libica.tar
URL:  http://oss.software.ibm.com/developerworks/opensource/libica
Distribution: DeveloperWorks
Vendor: IBM
Packager:  LTC Network Security Team
Buildroot:  /tmp/libica.build

# The following 64bit arches are supported
%define libica_64bit_arch s390x ppc64
%define _topdir /usr/src/libica

%description
Interface library routines used by IBM modules to interface to the IBM
eServer Cryptographic Accelerator (ICA).

%prep
%setup -c libica-1.3.5

%build
if [[ $RPM_BUILD_ROOT  ]] ;
then
        mkdir -p $RPM_BUILD_ROOT
        export INSROOT=$RPM_BUILD_ROOT
fi
#./configure
make -f Makefile
mkdir -p $RPM_BUILD_ROOT/usr/include
cd ./include
cp ica_api.h $RPM_BUILD_ROOT/usr/include
%ifos Linux
%ifarch %libica_64bit_arch
mkdir -p $RPM_BUILD_ROOT/opt/libica/lib31
mkdir -p $RPM_BUILD_ROOT/opt/libica/lib64
# To build the 64 bit RPM, you need to have the 31 bit libica already
# installed on the system.  The 64 bit RPM contains both the 31 bit and 64
# bit shared objects
cp /opt/libica/libica.so $RPM_BUILD_ROOT/opt/libica/lib31
chmod 755 $RPM_BUILD_ROOT/opt/libica/lib31
%else
mkdir -p $RPM_BUILD_ROOT/opt/libica
%endif
%endif


%install
if [[ $RPM_BUILD_ROOT  ]] ;
then
        export INSROOT=$RPM_BUILD_ROOT
fi
make -f Makefile install
%ifos Linux
%ifarch %libica_64bit_arch 
cp $RPM_BUILD_ROOT/usr/lib/libica.so $RPM_BUILD_ROOT/opt/libica/lib64
cp $RPM_BUILD_ROOT/opt/libica/lib31/libica.so $RPM_BUILD_ROOT/usr/lib/libica.so
%else
cp $RPM_BUILD_ROOT/usr/lib/libica.so $RPM_BUILD_ROOT/opt/libica
%endif
%endif
#
# Added to counter rpmbuild 4.1's new behavior - KEY
# See http://www.rpm.org/hintskinks/unpackaged-files/
#
rm -f $RPM_BUILD_ROOT/usr/lib/libica.so



%files
/usr/include/ica_api.h
%ifos Linux
%ifarch %libica_64bit_arch 
  /opt/libica/lib64/libica.so
  /opt/libica/lib31/libica.so
%else
  /opt/libica/libica.so
%endif
%endif


#pre install we need to remove any vestiges
#of libica... particularly from previous installs
#before we used ldconfig
%pre
%ifos Linux
if [[ ! -L /usr/lib/libica.so ]];
then
     if [[ -f /usr/lib/libica.so ]];  # does the file exist
     then
          /bin/rm /usr/lib/libica.so
     fi
fi
%endif

# Post installation processing
%post
%ifos Linux
%ifarch %libica_64bit_arch
if [ `grep -c \/opt\/libica\/lib64 /etc/ld.so.conf` = '0' ]
  then echo /opt/libica/lib64 >>/etc/ld.so.conf
fi
if [ `grep -c \/opt\/libica\/lib31 /etc/ld.so.conf` = '0' ]
  then echo /opt/libica/lib31 >>/etc/ld.so.conf
fi
ln -sf /opt/libica/lib64/libica.so /usr/lib64/libica.so
ln -sf /opt/libica/lib31/libica.so /usr/lib/libica.so
%else
if [ `grep -c \/opt\/libica /etc/ld.so.conf` = '0' ]
  then echo /opt/libica >>/etc/ld.so.conf
fi
ln -sf /opt/libica/libica.so /usr/lib/libica.so
%endif
/sbin/ldconfig
%endif


# Processing to be performed after uninstalling the RPM
%postun
%ifos Linux
rm -f /usr/lib/libica.so
%ifarch %libica_64bit_arch
rm -f /usr/lib64/libica.so
%endif
if [ `grep -c libica /etc/ld.so.conf` != '0' ]
  then
    sed '/libica/d' /etc/ld.so.conf >/tmp/libica.tmp
    mv /tmp/libica.tmp /etc/ld.so.conf
    /sbin/ldconfig
    cd /opt
    rm -rf libica
    cd -
fi
%endif
