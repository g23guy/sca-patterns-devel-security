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

%define autogenbase autogen
%define autogenconfdir %{_sysconfdir}/opt/%{autogenbase}

Name:         sca-patterns-autogen
Version:      1.2.1
Release:      0
Summary:      SCA Security Pattern Generator
License:      GPL-2.0-only
URL:          https://github.com/g23guy/sca-patterns-autogen
Group:        System/Monitoring
Source:       %{name}-%{version}.tar.gz
Requires:     /usr/bin/python3
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
install -m 555 bin/* %{buildroot}/usr/local/bin
install -m 644 conf/* %{buildroot}%{autogenconfdir}

%files
%defattr(-,root,root,-)
/usr/local/bin/*
%dir %{autogenconfdir}
%{autogenconfdir}/*
%config %attr(664,root,users) %{autogenconfdir}/*

%post

%postun

%changelog

