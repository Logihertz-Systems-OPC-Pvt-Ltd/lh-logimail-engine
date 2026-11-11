# Security Policy

## Overview

`lh-logimail-engine` is an enterprise-grade mail infrastructure security engine, RFC 6376 DKIM signer,
and mail gateway posture auditor developed by **Logihertz Systems (OPC) Private Limited**.
Engineered with a strict clean-room design and zero external runtime dependencies, `lh-logimail-engine`
operates with complete cryptographic determinism and auditability.

---

## Supported Versions

Only the latest active release of `lh-logimail-engine` receives security updates and vulnerability patches.

| Version | Supported          |
|:-------:|:------------------:|
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability, cryptographic bypass, CRLF injection vector,
or denial-of-service issue in `lh-logimail-engine`, please report it responsibly through
our coordinated security response channel.
**Do not create a public GitHub issue for security vulnerabilities.**

### Vulnerability Reporting Process

1. **Email Details**: Send an advisory email to:
   - **security@logihertz.com**
   - **ops@logihertz.com**
2. **Include Key Information**:
   - Affected component (`DkimSigner`, `MimeBuilder`, `SmtpMultiplexer`, `MailAuditor`, CLI)
   - Specific version of `lh-logimail-engine`
   - Detailed description of the vulnerability and attack vector
   - Minimal reproduction snippet, malformed payload, or configuration manifest
3. **Response Timeline**:
   - **Acknowledgment**: Within **48 hours** of receiving your report.
   - **Triage & Status**: Within **3 business days** with preliminary assessment and reproduction verification.
   - **Remediation & Patch**: We aim to release a verified patch within **5 business days** for high or critical severity issues.

---

## Security Engineering Standards

`lh-logimail-engine` enforces rigorous internal engineering controls:
- **Zero Third-Party Runtime Dependencies**: Zero `vendor/` supply chain footprint in production.
- **Strict CRLF Injection Protection**: Sanitization and rejection of Carriage Return (`\r`) and Line Feed (`\n`) headers in all MIME header fields.
- **Deterministic Cryptographic Enforcement**: Enforces >= 2048-bit RSA keys and SHA-256 for DKIM signatures, strictly disallowing deprecated 1024-bit keys or SHA-1 hashes.
- **TLS 1.2+ Enforcement**: Mandates TLS v1.2 / TLS v1.3 with peer verification for all production SMTP connections.
