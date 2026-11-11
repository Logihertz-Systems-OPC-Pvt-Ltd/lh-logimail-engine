# Changelog

All notable changes to **lh-logimail-engine** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-11

Initial clean-room release of **lh-logimail-engine**, an enterprise-grade, zero-dependency PHP 8.2+ mail infrastructure security engine, RFC 6376 DKIM canonicalizer & signer, CRLF-sanitized MIME builder, persistent SMTP socket multiplexer, and 10-rule mail gateway posture auditor developed by **Logihertz Systems (OPC) Private Limited**.

### Added

- **Zero-Dependency PSR-4 Autoloader** (`Logihertz\LogiMail\Autoloader`):
  - Lightweight, deterministic autoloader for the `Logihertz\LogiMail\` namespace without external Composer runtime dependencies.

- **RFC 6376 Relaxed/Relaxed DKIM Signer** (`Logihertz\LogiMail\DkimSigner`):
  - Strict RFC 6376 Section 3.4.2 relaxed header canonicalization (case folding, WSP compression, whitespace trimming, continuation unfolding).
  - Strict RFC 6376 Section 3.4.4 relaxed body canonicalization (CRLF normalization, trailing line space removal, trailing empty line collapse, empty body handling).
  - Base64-encoded SHA-256 body hash computation (`bh=`).
  - RSA-SHA256 signature generation (`a=rsa-sha256`) and verification via native `ext-openssl`.
  - RSA private key modulus bit-length inspection (`inspectPrivateKey`) enforcing $\ge 2048$-bit key sizes and detecting deprecated 1024-bit keys.

- **CRLF-Protected MIME Builder** (`Logihertz\LogiMail\MimeBuilder`):
  - Strict header injection sanitization against literal `\r`, `\n`, and URL-encoded `%0a` / `%0d` sequences in `From`, `To`, `Cc`, `Reply-To`, and `Subject`.
  - RFC 5322 & RFC 2045 `multipart/alternative` structure assembly with cryptographically random boundaries (`random_bytes(16)`).
  - RFC 8058 one-click list unsubscribe support via `List-Unsubscribe` and `List-Unsubscribe-Post: List-Unsubscribe=One-Click`.
  - Quoted-printable body encoding with standardized CRLF line terminations.

- **Persistent SMTP Socket Multiplexer** (`Logihertz\LogiMail\SmtpMultiplexer`):
  - Persistent connection pooling over `stream_socket_client` with mandatory TLSv1.2 / TLSv1.3 cryptographic handshakes and peer certificate validation.
  - Multi-message batch delivery using `RSET` state resets without disconnecting.
  - Configurable connection lifecycle recycling via `max_messages_per_connection` (default: 100).
  - Dot-stuffing compliance per RFC 5321 Section 4.5.2.
  - Offline `DryRunTransport` mode capturing comprehensive wire transcripts without external network access.

- **10-Rule Mail Posture Auditor** (`Logihertz\LogiMail\MailAuditor`):
  - Deterministic evaluation of mail gateway JSON configurations and raw `.eml` messages across 10 security rules:
    - `LH-MAIL-001` (CRITICAL, CWE-319): Plaintext SMTP transport or disabled TLS peer verification.
    - `LH-MAIL-002` (CRITICAL, CWE-345): DKIM signing disabled or missing domain/selector configuration.
    - `LH-MAIL-003` (HIGH, CWE-326): Sub-2048-bit RSA key modulus or deprecated SHA-1 digest.
    - `LH-MAIL-004` (HIGH, CWE-347): Undersigned DKIM headers missing mandatory From, Date, Subject, or Message-ID.
    - `LH-MAIL-005` (HIGH, CWE-290): Permissive SPF policy (`+all`, `?all`), missing hard/soft fail, or >10 DNS mechanisms.
    - `LH-MAIL-006` (HIGH, CWE-358): Missing or monitor-only DMARC policy (`p=none`) without aggregate reporting (`rua=`).
    - `LH-MAIL-007` (MEDIUM, CWE-93): Disabled CRLF header injection defenses or unvalidated envelope addresses.
    - `LH-MAIL-008` (MEDIUM, CWE-400): Unbounded multiplexing limits, timeouts (>60s), or message sizes (>25MB).
    - `LH-MAIL-009` (CRITICAL, CWE-798): Hardcoded plaintext SMTP credentials in configuration files.
    - `LH-MAIL-010` (LOW, CWE-755): Missing bounce alignment or RFC 8058 one-click unsubscribe compliance.
  - Mathematical Logihertz Security Posture Score ($S_{\text{posture}} \in [0, 100]$):
    $$S_{\text{posture}} = \max\left(0, 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

- **Multi-Format Enterprise Exporters** (`Logihertz\LogiMail\Exporters`):
  - Formatted ANSI terminal summary table with score colorization (`--format table`).
  - Canonical JSON report exporter (`--format json`).
  - OASIS SARIF v2.1.0 schema exporter (`--format sarif`) with driver rule definitions and MITRE CWE references.

- **Standalone CLI Executable** (`bin/lh-mail`):
  - Commands: `scan`, `sign`, `send-test`, `--version`, and `--help`.
  - Deterministic UNIX process exit codes:
    - `0`: Success / Audit clean (`total_findings === 0`).
    - `1`: Policy violations discovered (`total_findings > 0`).
    - `2`: CLI usage errors, unreadable files, or malformed inputs.

- **Deterministic Verification Test Suite** (`tests/run_tests.php`):
  - 80 zero-dependency assertions covering autoloader, canonicalization, cryptographic signing, MIME generation, SMTP multiplexing, posture scoring, exporter schemas, and CLI subprocess execution.
  - Tested and verified across PHP 8.2, 8.3, and 8.4 in GitHub Actions CI.

- **Governance & Legal Documentation**:
  - Full Apache License 2.0 (`LICENSE`).
  - Enterprise attribution and legal reservation notice (`NOTICE`).
  - Coordinated vulnerability disclosure policy (`SECURITY.md`).
  - Developer contribution guidelines (`CONTRIBUTING.md`).
  - Contributor Covenant v2.1 code of conduct (`CODE_OF_CONDUCT.md`).
  - Package manifest (`composer.json`).
  - Enterprise documentation with mathematical specifications and detection tables (`README.md`).

[0.1.0]: https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-logimail-engine/releases/tag/v0.1.0
