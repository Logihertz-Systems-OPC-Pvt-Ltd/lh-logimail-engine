Name:           lh-logimail-engine
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-mail - RFC 6376 Canonicalization & RSA-SHA256 DKIM Signature
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-logimail-engine
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      noarch

%description
Zero-dependency PHP 8.2+ transactional mail dispatch engine with RFC 6376 relaxed/relaxed DKIM RSA-2048 signing, RFC 5322 MIME CRLF injection protection, STARTTLS socket pooling, and 10-rule mail posture auditor.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-mail ]; then
    install -m 0755 bin/lh-mail %{buildroot}%{_bindir}/lh-mail
elif [ -f lh-mail ]; then
    install -m 0755 lh-mail %{buildroot}%{_bindir}/lh-mail
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for Logihertz Systems Ecosystem and STRUCT OS.
