# Engineering & Technical Architecture Specification

**Specification ID**: `LH-SPEC-2026-031`  
**Repository**: `lh-logimail-engine`  
**CLI Executable**: `lh-mail`  
**Standard Release Version**: `0.1.0`  
**Standard License**: `Apache-2.0`  
**Classification**: `Industrial Sovereign Cybersecurity & Critical Infrastructure Telemetry`

---

## Section 1: Document Control & Specification Metadata

| Metadata Attribute | Value |
| :--- | :--- |
| **Document Identification** | `LH-SPEC-2026-031` |
| **System Name** | `Logihertz Systems Sovereign Ecosystem` |
| **Target Component** | `lh-logimail-engine` (`lh-mail`) |
| **Target Language / Platform** | `PHP` |
| **Legal Entity** | Logihertz Systems (OPC) Private Limited |
| **Corporate Identity (CIN)** | `U72100MH2025OPC463857` |
| **GSTIN Registration** | `27AAGCL6394P1ZL` |
| **Principal Architect** | Sameer Tawade (`ops@logihertz.com` / `security@logihertz.com`) |
| **Headquarters & Registered Office** | Mumbai, Maharashtra, Republic of India |
| **Official Portal** | [https://www.logihertz.com](https://www.logihertz.com) |
| **Repository URL** | [https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-logimail-engine](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-logimail-engine) |
| **Document Status** | `APPROVED FOR PRODUCTION & INDUSTRIAL CERTIFICATION` |
| **Effective Release Date** | `2026-11-16` |

---

## Section 2: Normative RFC 2119 Requirements & System Invariants

This technical architecture specification enforces strict deterministic execution invariants in accordance with **RFC 2119** (`MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `RECOMMENDED`, `MAY`).

1. **Zero-Daemon Execution Invariant**:
   - The CLI binary `lh-mail` `MUST` execute as a clean, self-contained, stateless, zero-daemon process.
   - It `MUST NOT` spawn background daemons, fork unmonitored worker processes, or establish persistent Unix domain socket listeners unless explicitly invoked in daemon mode.
   - All state transitions `MUST` be deterministic, ephemeral, and strictly bounded by the execution lifecycle.

2. **Zero External Runtime Dependency Mandate**:
   - The software `MUST NOT` load, link, or depend upon third-party runtime package registries (e.g. PyPI, npm, Packagist, crates.io, Maven) at runtime.
   - For `PHP`, all cryptographic, mathematical, serialization, and networking primitives `MUST` be implemented exclusively via language standard libraries or clean-room internal zero-dependency modules.

3. **Deterministic Air-Gapped Operation**:
   - The system `MUST` function with 100% feature parity in air-gapped, isolated, and offline enclaves.
   - The software `MUST NOT` initiate unsolicited network calls, telemetry telemetry pings, phone-home beacons, or external CDN queries.
   - All verification baselines, heuristics, and schemas `MUST` be packaged locally within the distribution.

4. **Constant-Time Cryptographic Comparison**:
   - All cryptographic comparison routines (hashes, HMAC tags, signatures, secret tokens, and commitments) `MUST` execute in constant time (`subtle.ConstantTimeCompare`, `CRYPTO_memcmp`, or equivalent).
   - The implementation `MUST NOT` short-circuit string comparisons when evaluating sensitive keys, thereby mitigating timing side-channel attacks.

5. **Memory Safety & Explicit Zeroization**:
   - All transient buffers containing sensitive key material, decrypted plaintexts, seeds, and cryptographic nonces `MUST` be explicitly overwritten with zeroes immediately following completion of the cryptographic operation.
   - For C/C++ implementations, bounds checks and safe buffer wrappers `MUST` prevent stack/heap overflows. For Rust implementations, `#![forbid(unsafe_code)]` `MUST` be enforced.

6. **Standardized Telemetry Interoperability**:
   - All security assessment outputs `MUST` support machine-readable ingestion via OASIS SARIF v2.1.0 JSON and Canonical Indented JSON schemas, alongside ANSI console tables.

---

## Section 3: Core Mathematical & Algorithmic Specification

### 3.1 Domain Engine Mathematical Foundation: RFC 6376 Canonicalization & RSA-SHA256 DKIM Signature

The underlying computational core of `lh-logimail-engine` is formally governed by the following mathematical and algorithmic formulations:

$$\sigma_{\text{DKIM}} = \text{RSA-SHA256}_{K_{\text{priv}}}\left(C_{\text{relaxed}}(H) \parallel C_{\text{relaxed}}(B)\right)$$

### 3.2 Standardized Logihertz Security Posture Score Formulation

To achieve absolute cross-tool normalization across all 60 repositories in the Logihertz Systems Ecosystem, the security posture score $S_{\text{posture}}$ is evaluated on a standardized continuous integer scale $[0, 100]$:

$$S_{\text{posture}} = \max\left(0, \; 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

Where:
- $c_{\text{CRITICAL}}$ represents the total count of triggered Critical-severity normative rules (deduction: $-25$ per finding).
- $c_{\text{HIGH}}$ represents the total count of triggered High-severity normative rules (deduction: $-10$ per finding).
- $c_{\text{MEDIUM}}$ represents the total count of triggered Medium-severity normative rules (deduction: $-4$ per finding).
- $c_{\text{LOW}}$ represents the total count of triggered Low-severity normative rules (deduction: $-1$ per finding).

The final compliance verdict is strictly bifurcated:
$$\text{Verdict} = \begin{cases} \text{PASS} & \text{if } S_{\text{posture}} = 100 \land \sum c_i = 0 \\ \text{FAIL} & \text{otherwise} \end{cases}$$

---

## Section 4: Normative 10-Rule Detection Matrix

The detection engine evaluates configurations, manifests, firmware, protocols, and streams against the following 10 deterministic security rules:

| Rule ID | Severity | Weight | CWE ID | Trigger Predicate / Condition | Remediation Guideline |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `LH-MAIL-001` | `CRITICAL` | `25` | `CWE-319` | 25 | Plaintext SMTP transport permitted (tls_mode: "none") or peer certificate verification disabled (verify_peer: false) |
| `LH-MAIL-002` | `CRITICAL` | `25` | `CWE-345` | 25 | DKIM signing disabled (dkim_enabled: false) or missing selector/domain parameters |
| `LH-MAIL-003` | `HIGH` | `10` | `CWE-326` | 10 | Weak DKIM RSA key modulus (dkim_key_bits < 2048, e.g., 1024-bit RSA) or deprecated hash algorithm (rsa-sha1) |
| `LH-MAIL-004` | `HIGH` | `10` | `CWE-347` | 10 | Undersigned DKIM headers (omits mandatory From, Date, Subject, or Message-ID in signed_headers) |
| `LH-MAIL-005` | `HIGH` | `10` | `CWE-290` | 10 | Missing, permissive SPF policy (+all or ?all instead of -all / ~all), or exceeding 10 DNS lookup mechanisms |
| `LH-MAIL-006` | `HIGH` | `10` | `CWE-358` | 10 | Missing, monitor-only DMARC policy (p=none without quarantine/reject), or missing aggregate reporting URI (rua=) |
| `LH-MAIL-007` | `MEDIUM` | `4` | `CWE-93` | 4 | CRLF Header Injection protection disabled (strict_header_sanitization: false) or unvalidated envelope addresses |
| `LH-MAIL-008` | `MEDIUM` | `4` | `CWE-400` | 4 | Unbounded SMTP socket multiplexing (max_messages > 500, timeout > 60s, or max_size > 25MB) |
| `LH-MAIL-009` | `CRITICAL` | `25` | `CWE-798` | 25 | Hardcoded plaintext SMTP credentials in configuration rather than environment variable or secret vault references |
| `LH-MAIL-010` | `LOW` | `1` | `CWE-755` | 1 | Missing bounce / Return-Path envelope alignment or missing RFC 8058 one-click unsubscribe compliance |

---

## Section 5: CLI Contract, Exit Codes & OASIS SARIF v2.1.0 Specification

### 5.1 Command-Line Interface Syntax

The primary entrypoint `lh-mail` conforms to standard POSIX argument conventions:

```text
USAGE:
  lh-mail <command> [flags] [arguments]

CORE COMMANDS:
  scan <target> [--format table|json|sarif] [--output <file>]
      Execute deterministic security evaluation against target manifest or telemetry stream.
  verify <target>
      Validate operational parameters, cryptographic checksums, and structural invariants.
  --version, version
      Output release version, architecture, and legal attribution.
  --help, help
      Display comprehensive operational usage and command reference.
```

### 5.2 Deterministic Exit Code Protocol

| Exit Code | Classification | Operational Semantics |
| :---: | :--- | :--- |
| `0` | **SUCCESS / PASS** | Target passed all checks; zero Critical/High violations detected; $S_{\text{posture}} = 100$. |
| `1` | **FINDINGS / FAIL** | Target triggered one or more security rule violations; policy threshold breached. |
| `2` | **ERROR / USAGE** | Invalid CLI invocation, syntax error, missing input file, or fatal I/O failure. |

### 5.3 OASIS SARIF v2.1.0 Schema Compliance

Exported SARIF documents validate against the official OASIS schema (`sarif-schema-2.1.0.json`). Each result object maps:
- `ruleId`: Standardized identifier (`LH-MAIL-001` .. `LH-MAIL-010`).
- `level`: SARIF severity levels (`error` for Critical/High, `warning` for Medium, `note` for Low).
- `message.text`: Comprehensive explanation, CWE mapping, and actionable remediation steps.
- `locations[].physicalLocation.artifactLocation.uri`: Absolute or normalized relative path of target artifact.

---

## 6. Standalone Future Development Roadmap (`v0.2.0` — `v0.5.0`)

`lh-logimail-engine` is developed as an independent, standalone open-source project. The following roadmap defines the planned architectural, algorithmic, and protocol enhancements for upcoming point releases of `lh-logimail-engine`:

| Target Release | Milestone Focus | Planned Technical Deliverables for `lh-logimail-engine` |
|---|---|---|
| **`v0.2.0`** | Parser & Protocol Expansion | Add RFC 8463 Ed25519-SHA256 dual DKIM signing alongside RSA-2048/4096 and Authenticated Received Chain (ARC, RFC 8617) header sealing. |
| **`v0.3.0`** | Deep Algorithmic & Stateful Analysis | Implement RFC 3461/3464 Delivery Status Notification (DSN) bounce parsing and adaptive per-domain SMTP rate throttling. |
| **`v0.4.0`** | Remediation, Synthesis & Format Interop | Add MX priority failover queues with persistent disk-backed transactional spooling and automatic retry backoff. |
| **`v0.5.0`** | High-Throughput Performance & Formal Verification | Implement native S/MIME (CMS) and OpenPGP/MIME body encryption alongside DANE / MTA-STS outbound TLS verification. |

### 6.1 `v0.2.0` — Parser & Protocol Expansion
- **Format & Protocol Ingestion**: Add RFC 8463 Ed25519-SHA256 dual DKIM signing alongside RSA-2048/4096 and Authenticated Received Chain (ARC, RFC 8617) header sealing.
- **Zero-Dependency Architecture**: Pure standard library implementation with deterministic parsing guarantees and strict error handling.
- **Verification & Telemetry**: Regression test suites verifying schema edge-cases, malformed payload rejections, and SARIF v2.1.0 output fidelity.

### 6.2 `v0.3.0` — Deep Algorithmic & Stateful Analysis
- **Algorithmic Core**: Implement RFC 3461/3464 Delivery Status Notification (DSN) bounce parsing and adaptive per-domain SMTP rate throttling.
- **State Machine & Analysis Engine**: High-fidelity state tracking, cycle detection, and invariant checking with minimal computational overhead.
- **Differential & Regression Verification**: Comprehensive test harnesses covering stateful transitions, edge conditions, and mathematical boundary constraints.

### 6.3 `v0.4.0` — Remediation, Synthesis & Format Interoperability
- **Synthesis & Interoperability**: Add MX priority failover queues with persistent disk-backed transactional spooling and automatic retry backoff.
- **Automated Remediation Workflows**: Idempotent generation of verified configuration patches, policy rules, and standardized cross-format exports.
- **Contract & Artifact Validation**: Cryptographic baseline verification and end-to-end integration testing for synthesized deliverables.

### 6.4 `v0.5.0` — High-Throughput Performance & Formal Verification
- **High-Throughput Optimization**: Implement native S/MIME (CMS) and OpenPGP/MIME body encryption alongside DANE / MTA-STS outbound TLS verification.
- **Hardware & Kernel Acceleration**: Vectorized SIMD/eBPF/sub-millisecond streaming execution with bounded memory allocation.
- **Formal Verification & Assurance**: Mathematical proof of invariant preservation, false-positive calibration, and high-assurance certification baselines.

---

## Section 7: Verification, Quality Assurance & Legal Attribution

### 7.1 Automated Verification Protocol

Prior to distribution, all builds must execute the standardized Logihertz test suite:
- Unit and mathematical property tests verifying all equations and edge cases.
- Static analysis with zero warnings under standard strict linters.
- Subprocess CLI verification covering exit codes `0`, `1`, and `2`.

### 7.2 Copyright & Governance Notice

```text
Copyright 2025-2026 Logihertz Systems (OPC) Private Limited.
Creator, Founder, Director & Sole Developer: Sameer Tawade <ops@logihertz.com> / <security@logihertz.com>
Official Corporate Portal: https://www.logihertz.com
```

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this software except in compliance with the License. You may obtain a copy of the License at `http://www.apache.org/licenses/LICENSE-2.0`.
