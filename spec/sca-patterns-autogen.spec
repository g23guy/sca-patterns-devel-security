# spec file for package sca-patterns-autogen
#
# Copyright (c) 2022 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

%define autogenbase patdevel
%define autogenconfdir %{_sysconfdir}/opt/%{autogenbase}
%define autogenbasedir %{_localstatedir}/opt/%{autogenbase}
%define autogendir %{autogenbasedir}/autogen

Name:         sca-patterns-autogen
Version:      1.2.3
Release:      0
Summary:      SCA Security Pattern Generator
License:      GPL-2.0-only
URL:          https://github.com/g23guy/sca-patterns-autogen
Group:        System/Monitoring
Source:       %{name}-%{version}.tar.gz
Requires:     /usr/bin/python3
Requires:     sca-patterns-devel
BuildArch:    noarch

%description
Tools to generate Security announcement patterns for the SCA Tool

%prep
%setup -q

%build

%install
pwd;ls -la
mkdir -p %{buildroot}/usr/local/bin
mkdir -p %{buildroot}%{autogenconfdir}
mkdir -p %{buildroot}%{autogendir}/patterns
mkdir -p %{buildroot}%{autogendir}/logs
mkdir -p %{buildroot}%{autogendir}/errors
mkdir -p %{buildroot}%{autogendir}/duplicates
install -m 555 bin/* %{buildroot}/usr/local/bin
install -m 644 conf/* %{buildroot}%{autogenconfdir}

%files
%defattr(-,root,root,-)
/usr/local/bin/*
%dir %{autogenconfdir}
%dir %{autogenbasedir}
%dir %attr(775,root,users) %{autogendir}
%dir %attr(775,root,users) %{autogendir}/patterns
%dir %attr(775,root,users) %{autogendir}/logs
%dir %attr(775,root,users) %{autogendir}/errors
%dir %attr(775,root,users) %{autogendir}/duplicates
%{autogenconfdir}/*
%config %attr(664,root,users) %{autogenconfdir}/*

%post

%postun

%changelog

