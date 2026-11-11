# lh-logimail-engine

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-logimail-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-logimail-engine/actions/workflows/ci.yml)
[![PHP 8.2+](https://img.shields.io/badge/php-8.2+-8892BF.svg)](https://www.php.net/)
[![Dependencies: Zero](https://img.shields.io/badge/dependencies-0-success.svg)](composer.json)
[![OASIS SARIF v2.1.0](https://img.shields.io/badge/OASIS%20SARIF-v2.1.0-blue.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise-grade, zero-dependency PHP 8.2+ mail infrastructure security engine, RFC 6376 DKIM canonicalizer & signer, CRLF-sanitized MIME builder, persistent SMTP socket multiplexer, and 10-rule mail gateway posture auditor developed by **Logihertz Systems (OPC) Private Limited**.

---

## Architectural Highlights

- **100% Zero External Runtime Dependencies**: Operates exclusively with native PHP 8.2+ core functionality (`ext-openssl`, `ext-json`, `ext-spl`, and PHP Streams). Zero third-party `vendor/` supply chain attack surface.
- **RFC 6376 Relaxed/Relaxed DKIM Signer**: Clean-room implementation of header and body relaxed canonicalization with cryptographic RSA-SHA256 signature generation and validation via `ext-openssl`.
- **CRLF Injection Guard & RFC 5322 MIME Builder**: Strict sanitization of Carriage Return (`\r`), Line Feed (`\n`), and URL-encoded sequences (`%0a`, `%0d`) in headers; builds clean multipart/alternative structures with RFC 8058 one-click unsubscribe support.
- **Persistent SMTP Socket Multiplexer**: Persistent connection pooling with mandatory TLSv1.2 / TLSv1.3 negotiation, RSET envelope resets, and an offline `DryRunTransport` mode capturing complete wire transcripts.
- **10-Rule Deterministic Posture Engine**: Inspects mail gateway JSON configurations and EML messages against security rules `LH-MAIL-001` through `LH-MAIL-010`.
- **Multi-Format Enterprise Reporting**: Outputs rich colored ANSI terminal tables, canonical JSON, and OASIS SARIF v2.1.0 schemas.

---

## Core Detection Rules

| Rule ID | Severity | CWE | Weight | Description |
|:---|:---:|:---:|:---:|:---|
| `LH-MAIL-001` | `CRITICAL` | `CWE-319` | 25 | Plaintext SMTP transport permitted (`tls_mode: "none"`) or peer certificate verification disabled (`verify_peer: false`) |
| `LH-MAIL-002` | `CRITICAL` | `CWE-345` | 25 | DKIM signing disabled (`dkim_enabled: false`) or missing selector/domain parameters |
| `LH-MAIL-003` | `HIGH` | `CWE-326` | 10 | Weak DKIM RSA key modulus (`dkim_key_bits < 2048`, e.g., 1024-bit RSA) or deprecated hash algorithm (`rsa-sha1`) |
| `LH-MAIL-004` | `HIGH` | `CWE-347` | 10 | Undersigned DKIM headers (omits mandatory `From`, `Date`, `Subject`, or `Message-ID` in `signed_headers`) |
| `LH-MAIL-005` | `HIGH` | `CWE-290` | 10 | Missing, permissive SPF policy (`+all` or `?all` instead of `-all` / `~all`), or exceeding 10 DNS lookup mechanisms |
| `LH-MAIL-006` | `HIGH` | `CWE-358` | 10 | Missing, monitor-only DMARC policy (`p=none` without quarantine/reject), or missing aggregate reporting URI (`rua=`) |
| `LH-MAIL-007` | `MEDIUM` | `CWE-93` | 4 | CRLF Header Injection protection disabled (`strict_header_sanitization: false`) or unvalidated envelope addresses |
| `LH-MAIL-008` | `MEDIUM` | `CWE-400` | 4 | Unbounded SMTP socket multiplexing (`max_messages > 500`, `timeout > 60s`, or `max_size > 25MB`) |
| `LH-MAIL-009` | `CRITICAL` | `CWE-798` | 25 | Hardcoded plaintext SMTP credentials in configuration rather than environment variable or secret vault references |
| `LH-MAIL-010` | `LOW` | `CWE-755` | 1 | Missing bounce / Return-Path envelope alignment or missing RFC 8058 one-click unsubscribe compliance |

---

## Mathematical Formulations

### 1. Logihertz Security Posture Score ($S_{\text{posture}}$)

The objective security posture score evaluates mail gateway configurations on a normalized scale $[0, 100]$:

$$S_{\text{posture}} = \max\left(0, 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

Where $c_i$ represents the count of detected findings at severity tier $i$. A fully hardened gateway produces $S_{\text{posture}} = 100$, while multiple severe misconfigurations reduce the score to 0.

### 2. RFC 6376 Relaxed Header Canonicalization

Given a header field with name $N$ and value $V$:

$$\text{canon}_{\text{header}}(N, V) = \text{lowercase}(N) \mathbin{:} \text{trim}\left(\text{compressWSP}\left(\text{unfold}(V)\right)\right)$$

Where $\text{unfold}$ replaces any CRLF or line ending followed by whitespace with a single space character, and $\text{compressWSP}$ replaces any run of spaces or tabs with a single space.

### 3. RFC 6376 Relaxed Body Canonicalization & Hash ($bh$)

The body lines are stripped of trailing line whitespace and normalized to `\r\n`. All sequences of WSP within each line are compressed to a single space. Multiple trailing empty lines are collapsed to a single `\r\n`. If the body is empty or consists only of whitespace, the canonical body is $\epsilon$ (empty string).

The body hash $bh$ is calculated over the canonicalized body:

$$bh = \text{Base64}\left(\text{SHA-256}\left(\text{canon}_{\text{body}}(B)\right)\right)$$

---

## Installation

### Prerequisites

- **PHP 8.2 or higher**
- Required standard extensions: `ext-openssl`, `ext-json`, `ext-spl`

### Direct Execution

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-logimail-engine.git
cd lh-logimail-engine

# Verify permissions
chmod +x bin/lh-mail

# Verify version
./bin/lh-mail --version
```

### Composer Integration

```bash
composer require logihertzsystems/lh-logimail-engine
```

---

## CLI Usage

### 1. Auditing Mail Gateway Configuration or EML

```bash
# Scan mail gateway configuration with ANSI terminal table
./bin/lh-mail scan fixtures/hardened_mail_config.json

# Export scan results to OASIS SARIF v2.1.0
./bin/lh-mail scan fixtures/hardened_mail_config.json --format sarif --output report.sarif

# Export scan results to canonical JSON
./bin/lh-mail scan fixtures/vulnerable_mail_config.json --format json
```

### 2. Signing an RFC 5322 EML Message with DKIM

```bash
# Sign using an existing RSA private key
./bin/lh-mail sign fixtures/sample_unsigned.eml \
  --domain logihertz.com \
  --selector sig2026 \
  --key /path/to/dkim.pem \
  --output signed_message.eml

# Sign using auto-generated ephemeral 2048-bit RSA key (for testing)
./bin/lh-mail sign fixtures/sample_unsigned.eml \
  --domain logihertz.com \
  --selector sig2026
```

### 3. SMTP Socket Multiplexer Dry-Run Test

```bash
# Execute offline wire transcript simulation
./bin/lh-mail send-test fixtures/hardened_mail_config.json --dry-run
```

---

## Exit Code Semantics

The CLI enforces deterministic UNIX process exit codes:

| Exit Code | Meaning | Condition |
|:---:|:---|:---|
| `0` | **Success / Clean** | Audit passed with zero findings (`total_findings === 0`) or operation succeeded |
| `1` | **Policy Findings Detected** | Audit detected one or more security findings (`total_findings > 0`) |
| `2` | **Usage / System Error** | Invalid CLI arguments, missing target, unreadable file, or malformed input |

---

## Running Tests

Execute the zero-dependency test suite (80 assertions across 10 test groups):

```bash
php tests/run_tests.php
```

To run syntax linting across all repository files:

```bash
find src bin tests -type f -exec php -l {} +
```

---

## Enterprise Governance & Notice

`lh-logimail-engine` is an open-source product developed by:

- **Organization**: Logihertz Systems (OPC) Private Limited (`logihertzsystems`)
- **Website**: [https://logihertz.com/](https://logihertz.com/)
- **Contact & Support**: [ops@logihertz.com](mailto:ops@logihertz.com)
- **Creator, Founder, Director & Sole Developer**: **Sameer Tawade** (`ops@logihertz.com`)
- **License**: Apache License 2.0 (SPDX-License-Identifier: `Apache-2.0`). See [LICENSE](LICENSE) and [NOTICE](NOTICE) for complete legal terms.
