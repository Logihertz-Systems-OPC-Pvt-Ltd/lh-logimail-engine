# Contributing to lh-logimail-engine

Thank you for your interest in contributing to **lh-logimail-engine**, an enterprise-grade, zero-dependency mail infrastructure security engine developed by **Logihertz Systems (OPC) Private Limited**.

We welcome contributions that improve cryptographic determinism, RFC compliance, mail posture auditing, performance, and documentation.

---

## 1. Architectural Mandates & Standards

### Zero External Runtime Dependencies
`lh-logimail-engine` operates under a strict **Zero Runtime Dependencies** policy:
- All source code in `src/` must exclusively utilize native PHP 8.2+ core language features and standard system extensions:
  - `ext-openssl`: Cryptographic signing, hash computation, and TLS v1.2/v1.3 stream handshakes.
  - `ext-json`: Canonical JSON parsing and serialization.
  - `ext-spl`: Autoloading, standard data structures, and exception hierarchy.
  - **PHP Streams**: Native socket connections via `stream_socket_client` and `stream_socket_enable_crypto`.
- **No Third-Party Runtime Packages**: `composer.json` must not declare any external production runtime dependencies in `require`.
- **Namespace Consistency**: All classes must reside under the `Logihertz\LogiMail\` namespace and comply with PSR-4 autoloading via `src/Autoloader.php`.
- **Strict Typing**: Every PHP file must begin with `declare(strict_types=1);`.
- **PHP 8.2 Compatibility**: Do not use features introduced in PHP 8.3+ (e.g., typed class constants like `const string FOO = 'bar'`, which causes syntax errors in PHP 8.2). Use untyped constants `const FOO = 'bar'`.

---

## 2. Local Development & Verification Workflow

Before submitting any code change or pull request, you must execute the full local verification pipeline:

### Step 1: Syntax Validation
Verify that every PHP file passes the PHP built-in syntax linter with zero errors:

```bash
find src bin tests -type f -exec php -l {} +
```

### Step 2: Zero-Dependency Test Suite
Run the deterministic test suite containing 80+ assertions covering canonicalization, signing, MIME building, socket multiplexing, posture evaluation, and CLI execution:

```bash
php tests/run_tests.php
```
Ensure all assertions pass with a 100% success rate.

### Step 3: CLI Subprocess Smoke Testing
Verify that `bin/lh-mail` executes cleanly across its primary subcommands and formats:

```bash
# 1. Audit hardened configuration (expected exit code 0)
php bin/lh-mail scan fixtures/hardened_mail_config.json --format table

# 2. Audit vulnerable configuration with SARIF v2.1.0 export (expected exit code 1)
php bin/lh-mail scan fixtures/vulnerable_mail_config.json --format sarif

# 3. Canonicalize and sign a sample RFC 5322 EML message (expected exit code 0)
php bin/lh-mail sign fixtures/sample_unsigned.eml --domain logihertz.com --selector mail2026

# 4. Dry-run persistent SMTP socket multiplexer probe (expected exit code 0)
php bin/lh-mail send-test fixtures/hardened_mail_config.json --dry-run
```

---

## 3. RFC Compliance Guidelines

All mail handling logic must adhere strictly to established IETF standards:

1. **RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures**:
   - Canonicalization algorithm must strictly implement `relaxed/relaxed` header and body canonicalization per RFC 6376 Sections 3.4.2 and 3.4.4.
   - Body hash (`bh=`) must be computed over the relaxed canonical body using base64-encoded SHA-256.
   - Private key inspection must enforce RSA modulus lengths $\ge 2048$ bits; sub-2048-bit keys (e.g., 1024-bit) must be flagged or rejected.
   - Deprecated hash digests (`sha1`, `rsa-sha1`, `md5`) are strictly prohibited for signature generation.

2. **RFC 5322 & RFC 2045 - Internet Message Format & MIME**:
   - Enforce strict Carriage Return Line Feed (`\r\n`) header injection protection. All header values must be stripped or rejected if literal `\r`, `\n`, or URL-encoded `%0a` / `%0d` sequences are detected.
   - Boundaries for `multipart/alternative` must use cryptographically secure randomness via `random_bytes(16)`.

3. **RFC 8058 - One-Click Unsubscribe Functionality**:
   - Support `List-Unsubscribe: <url>` and mandatory `List-Unsubscribe-Post: List-Unsubscribe=One-Click` headers for transactional and bulk mail streams.

4. **Transport Security (TLS v1.2 / TLS v1.3)**:
   - SMTP client connections must enforce `STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT` and peer certificate verification by default. Plaintext transport must never be the default.

---

## 4. Guidelines for Adding or Modifying Mail Posture Rules (`LH-MAIL-001`..`010`)

When proposing a new audit rule or modifying existing detection logic in `src/MailAuditor.php`:

1. **Deterministic Severity & Weighting**:
   Assign an objective severity, CWE mapping, and weight according to the Logihertz Posture Model:
   - `CRITICAL` (Weight: 25, e.g., Plaintext SMTP, Missing DKIM, Plaintext Credentials)
   - `HIGH` (Weight: 10, e.g., Sub-2048 bit RSA, Missing Mandatory Signed Headers, Permissive SPF, Monitor-only DMARC)
   - `MEDIUM` (Weight: 4, e.g., Disabled CRLF protection, Unbounded multiplexing limits)
   - `LOW` (Weight: 1, e.g., Missing RFC 8058 one-click headers, alignment inconsistencies)

2. **Mathematical Posture Score Invariant**:
   The posture score calculation must remain strictly deterministic:
   $$S_{\text{posture}} = \max\left(0, 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

3. **Update Exporters & SARIF v2.1.0 Schemas**:
   Add the rule metadata to `MailAuditor::RULE_METADATA` and verify that `Exporters::exportSarif()` correctly maps the rule ID, CWE tags, precision, and level (`error`, `warning`, `note`).

4. **Update Fixtures and Test Suite**:
   - Ensure `fixtures/hardened_mail_config.json` passes the new rule cleanly (0 findings, score 100).
   - Ensure `fixtures/vulnerable_mail_config.json` triggers the rule under policy violation conditions.
   - Add dedicated positive and negative assertions in `tests/run_tests.php`.

---

## 5. Pull Request & Commit Standards

- **Commit Message Format**: Follow Conventional Commits:
  - `feat: add support for Ed25519 DKIM signatures`
  - `fix: resolve WSP trailing compression edge case in DkimSigner`
  - `docs: update RFC 8058 implementation examples in README`
  - `test: add unit assertions for DMARC pct tag evaluation`
- **Code Style & Formatting**:
  - 4 spaces indentation (no tabs in PHP source files).
  - Include the standard Logihertz Systems header comment banner at the top of every new PHP file:
    ```php
    <?php

    declare(strict_types=1);

    // ==============================================================================
    // Product:       lh-logimail-engine (bin/lh-mail)
    // Module:        Logihertz\LogiMail\...
    // Role:          ...
    // Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
    // Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
    // Contact:       ops@logihertz.com | https://logihertz.com/
    // License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
    // ==============================================================================
    ```
- **Attribution & Licensing**:
  All contributions are licensed under the **Apache License 2.0**. By submitting a pull request, you agree that your contribution is provided under the terms of the Apache License, Version 2.0, with copyright and attribution assigned to **Logihertz Systems (OPC) Private Limited**.

---

## 6. Communication & Questions

For architecture discussions, bug disclosures, or security inquiries:
- **Operations & Technical**: [ops@logihertz.com](mailto:ops@logihertz.com)
- **Security Vulnerabilities**: [security@logihertz.com](mailto:security@logihertz.com)
- **Executive Director**: Sameer Tawade (Creator, Founder, Director & Sole Developer)
