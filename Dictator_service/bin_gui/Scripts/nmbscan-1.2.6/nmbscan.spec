Name: nmbscan
Summary: a NMB/SMB network scanner
Version: 1.2.6
Release: 1
License: GPL
Packager : Gregoire Barbier (devel at g76r dot eu)
Group: Applications/System 
URL: http://nmbscan.g76r.eu/
#Source: http://nmbscan.g76r.eu/down.php?file=nmbscan-%{version}.tar.gz
Source: %{name}-%{version}.tar.gz
Buildroot: /var/tmp/%{name}-root
Prefix: /usr
Buildarch: noarch
Requires: samba-client, iputils

%description
Scans a SMB shares network, using NMB and SMB protocols. Useful to acquire
information on local aera network (security audit, etc.)

Matches informations such as NMB/SMB/Windows hostname, IP address, IP
hostname, ethernet MAC address, Windows username, NMB/SMB/Windows domain name
and master browser.

Can discover all NMB/SMB/Windows hosts on a local aera network thanks to hosts
lists maintained by master browsers.


%prep
%setup -q -c %{name}-%{version}

%build

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/sbin
install nmbscan $RPM_BUILD_ROOT/usr/sbin

%clean
rm -rf $RPM_BUILD_ROOT

%files
/usr/sbin/nmbscan

%changelog
* Sat Aug 8 2010 Gregoire Barbier
- upgrading from 1.2.5 to 1.2.6 (public shares listing support, some
  mac address listing improvements, minor improvements)

* Sat Dec 22 2007 Gregoire Barbier
- upgrading from 1.2.4 to 1.2.5 (minor enhancement and bugfixes)

* Fri Feb 4 2005 Gregoire Barbier
- upgrading from 1.2.3 to 1.2.4 (speed improvement, adding mac address over
  netbios)

* Sun Jun 20 2004 Gregoire Barbier
- upgrading from 1.2.2 to 1.2.3 (support for *BSD, including OSX)

* Sat Jun 5 2004 Gregoire Barbier
- upgrading from 1.2.1 to 1.2.2 (support for Samba 3)

* Sat Feb 9 2002 Gregoire Barbier
- upgrading from 1.2.0 to 1.2.1

* Sun Jan 26 2002 Gregoire Barbier
- first release

