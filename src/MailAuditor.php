<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-logimail-engine (bin/lh-mail)
// Module:        Logihertz\LogiMail\MailAuditor
// Role:          10-Rule Deterministic Mail & DKIM Posture Security Engine
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

namespace Logihertz\LogiMail;

use InvalidArgumentException;
use JsonException;

/**
 * Finding model representing an evaluated rule violation.
 */
class AuditFinding
{
    public function __construct(
        public readonly string $ruleId,
        public readonly string $severity,
        public readonly string $cwe,
        public readonly string $title,
        public readonly string $description,
        public readonly string $recommendation,
        public readonly ?string $evidence = null,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'rule_id' => $this->ruleId,
            'severity' => $this->severity,
            'cwe' => $this->cwe,
            'title' => $this->title,
            'description' => $this->description,
            'recommendation' => $this->recommendation,
            'evidence' => $this->evidence,
        ];
    }
}

/**
 * Comprehensive audit result containing findings, summary metrics, and posture score.
 */
class AuditResult
{
    /**
     * @param string $target File path or identifier evaluated.
     * @param string $targetType "configuration" or "eml".
     * @param string $timestamp ISO 8601 scan timestamp.
     * @param int $postureScore Normalized posture score (0-100).
     * @param array<AuditFinding> $findings List of detected rule findings.
     * @param array{total_findings: int, critical: int, high: int, medium: int, low: int} $summary
     */
    public function __construct(
        public readonly string $target,
        public readonly string $targetType,
        public readonly string $timestamp,
        public readonly int $postureScore,
        public readonly array $findings,
        public readonly array $summary,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'target' => $this->target,
            'target_type' => $this->targetType,
            'timestamp' => $this->timestamp,
            'posture_score' => $this->postureScore,
            'summary' => $this->summary,
            'findings' => array_map(static fn(AuditFinding $f): array => $f->toArray(), $this->findings),
        ];
    }
}

/**
 * Deterministic mail infrastructure security auditor evaluating gateway configurations
 * and raw email messages against rules LH-MAIL-001 through LH-MAIL-010.
 */
class MailAuditor
{
    /** @var array<string, array{severity: string, cwe: string, title: string, weight: int}> */
    public const RULE_METADATA = [
        'LH-MAIL-001' => [
            'severity' => 'CRITICAL',
            'cwe' => 'CWE-319',
            'title' => 'Plaintext SMTP transport permitted or peer verification disabled',
            'weight' => 25,
        ],
        'LH-MAIL-002' => [
            'severity' => 'CRITICAL',
            'cwe' => 'CWE-345',
            'title' => 'DKIM signing disabled or missing domain/selector configuration',
            'weight' => 25,
        ],
        'LH-MAIL-003' => [
            'severity' => 'HIGH',
            'cwe' => 'CWE-326',
            'title' => 'Weak DKIM RSA key modulus (< 2048 bits) or deprecated hash algorithm',
            'weight' => 10,
        ],
        'LH-MAIL-004' => [
            'severity' => 'HIGH',
            'cwe' => 'CWE-347',
            'title' => 'Undersigned or improperly specified DKIM headers',
            'weight' => 10,
        ],
        'LH-MAIL-005' => [
            'severity' => 'HIGH',
            'cwe' => 'CWE-290',
            'title' => 'Missing, permissive, or DNS-excessive SPF policy',
            'weight' => 10,
        ],
        'LH-MAIL-006' => [
            'severity' => 'HIGH',
            'cwe' => 'CWE-358',
            'title' => 'Missing, monitor-only (p=none), or non-reporting DMARC policy',
            'weight' => 10,
        ],
        'LH-MAIL-007' => [
            'severity' => 'MEDIUM',
            'cwe' => 'CWE-93',
            'title' => 'CRLF header injection sanitization disabled or address unvalidated',
            'weight' => 4,
        ],
        'LH-MAIL-008' => [
            'severity' => 'MEDIUM',
            'cwe' => 'CWE-400',
            'title' => 'Unbounded SMTP socket multiplexing, timeout, or message payload limits',
            'weight' => 4,
        ],
        'LH-MAIL-009' => [
            'severity' => 'CRITICAL',
            'cwe' => 'CWE-798',
            'title' => 'Hardcoded plaintext SMTP credentials in configuration',
            'weight' => 25,
        ],
        'LH-MAIL-010' => [
            'severity' => 'LOW',
            'cwe' => 'CWE-755',
            'title' => 'Missing bounce alignment or RFC 8058 one-click unsubscribe compliance',
            'weight' => 1,
        ],
    ];

    /**
     * Audit a file (either JSON mail gateway configuration or .eml message).
     *
     * @param string $filePath Absolute or relative path to file.
     * @return AuditResult
     * @throws InvalidArgumentException
     */
    public function auditFile(string $filePath): AuditResult
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            throw new InvalidArgumentException("Target path is not a readable file: {$filePath}");
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            throw new InvalidArgumentException("Unable to read target file: {$filePath}");
        }

        // Determine if target is JSON or EML
        $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        if ($ext === 'json') {
            try {
                $decoded = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
                if (!is_array($decoded)) {
                    throw new InvalidArgumentException('JSON configuration must be an object/associative array.');
                }
                return $this->auditConfiguration($decoded, $filePath);
            } catch (JsonException $e) {
                throw new InvalidArgumentException("Malformed JSON configuration in {$filePath}: " . $e->getMessage(), 0, $e);
            }
        }

        if ($ext === 'eml') {
            return $this->auditEml($content, $filePath);
        }

        // Attempt JSON decode fallback
        $json = @json_decode($content, true);
        if (is_array($json)) {
            return $this->auditConfiguration($json, $filePath);
        }

        // Otherwise treat as EML
        return $this->auditEml($content, $filePath);
    }

    /**
     * Audit a parsed JSON mail gateway configuration against all 10 rules.
     *
     * @param array<string, mixed> $config Gateway settings.
     * @param string $target Name/path for reporting.
     * @return AuditResult
     */
    public function auditConfiguration(array $config, string $target = 'mail_config.json'): AuditResult
    {
        $findings = [];

        // LH-MAIL-001 (CRITICAL, 25, CWE-319): Plaintext SMTP transport
        $tlsMode = strtolower((string) ($config['tls_mode'] ?? 'starttls'));
        $allowPlaintext = (bool) ($config['allow_plaintext'] ?? false);
        $verifyPeer = (bool) ($config['verify_peer'] ?? true);

        if ($tlsMode === 'none' || $tlsMode === 'plain' || $allowPlaintext || !$verifyPeer) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-MAIL-001',
                severity: 'CRITICAL',
                cwe: 'CWE-319',
                title: self::RULE_METADATA['LH-MAIL-001']['title'],
                description: 'SMTP gateway permits unencrypted plaintext transport or disables TLS peer certificate verification.',
                recommendation: 'Enforce tls_mode: "starttls" or "implicit", set allow_plaintext: false, and verify_peer: true.',
                evidence: sprintf('tls_mode=%s, allow_plaintext=%s, verify_peer=%s', $tlsMode, $allowPlaintext ? 'true' : 'false', $verifyPeer ? 'true' : 'false')
            );
        }

        // LH-MAIL-002 (CRITICAL, 25, CWE-345): DKIM signing disabled or missing selector/domain
        $dkimEnabled = (bool) ($config['dkim_enabled'] ?? false);
        $dkimSelector = trim((string) ($config['dkim_selector'] ?? ''));
        $dkimDomain = trim((string) ($config['dkim_domain'] ?? ''));

        if (!$dkimEnabled || $dkimSelector === '' || $dkimDomain === '') {
            $findings[] = new AuditFinding(
                ruleId: 'LH-MAIL-002',
                severity: 'CRITICAL',
                cwe: 'CWE-345',
                title: self::RULE_METADATA['LH-MAIL-002']['title'],
                description: 'DKIM signing is either disabled or missing required domain/selector configuration parameters.',
                recommendation: 'Enable dkim_enabled: true and configure active dkim_selector and dkim_domain values.',
                evidence: sprintf('dkim_enabled=%s, dkim_selector="%s", dkim_domain="%s"', $dkimEnabled ? 'true' : 'false', $dkimSelector, $dkimDomain)
            );
        }

        // LH-MAIL-003 (HIGH, 10, CWE-326): Weak DKIM RSA key size (<2048) or deprecated hash algorithm
        $keyBits = (int) ($config['dkim_key_bits'] ?? 2048);
        $hashAlgo = strtolower((string) ($config['dkim_hash_algorithm'] ?? 'rsa-sha256'));

        if ($keyBits < 2048 || in_array($hashAlgo, ['sha1', 'rsa-sha1', 'md5'], true)) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-MAIL-003',
                severity: 'HIGH',
                cwe: 'CWE-326',
                title: self::RULE_METADATA['LH-MAIL-003']['title'],
                description: 'DKIM cryptographic configuration specifies a sub-2048-bit RSA key or deprecated SHA-1 digest.',
                recommendation: 'Deploy >= 2048-bit RSA keys and configure dkim_hash_algorithm: "rsa-sha256".',
                evidence: sprintf('dkim_key_bits=%d, dkim_hash_algorithm="%s"', $keyBits, $hashAlgo)
            );
        }

        // LH-MAIL-004 (HIGH, 10, CWE-347): Undersigned/missing mandatory DKIM headers
        $signedHeaders = (array) ($config['signed_headers'] ?? []);
        $normalizedSigned = array_map('strtolower', array_map('strval', $signedHeaders));
        $mandatory = ['from', 'date', 'subject', 'message-id'];
        $missing = array_diff($mandatory, $normalizedSigned);

        if (!empty($missing)) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-MAIL-004',
                severity: 'HIGH',
                cwe: 'CWE-347',
                title: self::RULE_METADATA['LH-MAIL-004']['title'],
                description: 'DKIM header signature policy omits one or more mandatory headers (From, Date, Subject, Message-ID).',
                recommendation: 'Ensure signed_headers includes "from", "date", "subject", and "message-id".',
                evidence: 'Missing mandatory headers: ' . implode(', ', $missing)
            );
        }

        // LH-MAIL-005 (HIGH, 10, CWE-290): Permissive, missing, or >10 DNS mechanisms SPF policy
        $spfRecord = trim((string) ($config['spf_record'] ?? ''));
        if ($spfRecord === '' || str_contains($spfRecord, '+all') || str_contains($spfRecord, '?all') || (!str_contains($spfRecord, '-all') && !str_contains($spfRecord, '~all'))) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-MAIL-005',
                severity: 'HIGH',
                cwe: 'CWE-290',
                title: self::RULE_METADATA['LH-MAIL-005']['title'],
                description: 'Sender Policy Framework (SPF) record is missing, permissive (+all/?all), or fails to specify hard/soft fail (-all/~all).',
                recommendation: 'Publish a strict SPF record ending in "-all" or "~all" without excessive mechanisms.',
                evidence: $spfRecord === '' ? 'No spf_record specified in configuration' : "spf_record: {$spfRecord}"
            );
        } else {
            // Count DNS mechanisms: include:, a, mx, ptr, exists, redirect
            preg_match_all('/\b(include:|a\b|mx\b|ptr\b|exists:|redirect=)/i', $spfRecord, $mechMatches);
            if (count($mechMatches[0]) > 10) {
                $findings[] = new AuditFinding(
                    ruleId: 'LH-MAIL-005',
                    severity: 'HIGH',
                    cwe: 'CWE-290',
                    title: self::RULE_METADATA['LH-MAIL-005']['title'],
                    description: 'SPF policy contains more than 10 DNS lookup mechanisms, risking SPF PermError failures.',
                    recommendation: 'Flatten SPF records to reduce DNS query mechanisms to 10 or fewer per RFC 7208.',
                    evidence: sprintf('Mechanism count: %d (> 10)', count($mechMatches[0]))
                );
            }
        }

        // LH-MAIL-006 (HIGH, 10, CWE-358): Missing or monitor-only DMARC policy
        $dmarcRecord = trim((string) ($config['dmarc_record'] ?? ''));
        if ($dmarcRecord === '' || preg_match('/\bp\s*=\s*none\b/i', $dmarcRecord) === 1 || !str_contains(strtolower($dmarcRecord), 'rua=')) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-MAIL-006',
                severity: 'HIGH',
                cwe: 'CWE-358',
                title: self::RULE_METADATA['LH-MAIL-006']['title'],
                description: 'DMARC record is missing, set to inactive monitoring (p=none), or lacks aggregate reporting (rua=).',
                recommendation: 'Enforce p=reject or p=quarantine and configure an aggregate feedback URI (rua=mailto:...).',
                evidence: $dmarcRecord === '' ? 'No dmarc_record specified in configuration' : "dmarc_record: {$dmarcRecord}"
            );
        }

        // LH-MAIL-007 (MEDIUM, 4, CWE-93): CRLF Header Injection protection disabled
        $strictSanitization = (bool) ($config['strict_header_sanitization'] ?? true);
        $validateReplyTo = (bool) ($config['validate_reply_to'] ?? true);
        $validateReturnPath = (bool) ($config['validate_return_path'] ?? true);

        if (!$strictSanitization || !$validateReplyTo || !$validateReturnPath) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-MAIL-007',
                severity: 'MEDIUM',
                cwe: 'CWE-93',
                title: self::RULE_METADATA['LH-MAIL-007']['title'],
                description: 'MIME header CRLF injection defense or envelope address validation is disabled.',
                recommendation: 'Set strict_header_sanitization: true, validate_reply_to: true, and validate_return_path: true.',
                evidence: sprintf(
                    'strict_header_sanitization=%s, validate_reply_to=%s, validate_return_path=%s',
                    $strictSanitization ? 'true' : 'false',
                    $validateReplyTo ? 'true' : 'false',
                    $validateReturnPath ? 'true' : 'false'
                )
            );
        }

        // LH-MAIL-008 (MEDIUM, 4, CWE-400): Unbounded SMTP socket multiplexing or timeouts
        $maxMsgs = (int) ($config['max_messages_per_connection'] ?? 100);
        $timeoutSec = (int) ($config['socket_timeout_seconds'] ?? 30);
        $maxSize = (int) ($config['max_message_size_bytes'] ?? 10485760);

        if ($maxMsgs > 500 || $timeoutSec > 60 || $maxSize > 26214400) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-MAIL-008',
                severity: 'MEDIUM',
                cwe: 'CWE-400',
                title: self::RULE_METADATA['LH-MAIL-008']['title'],
                description: 'SMTP connection multiplexing limits, timeouts, or maximum message size parameters exceed safe bounds.',
                recommendation: 'Keep max_messages_per_connection <= 500, socket_timeout_seconds <= 60, and max_message_size_bytes <= 26214400 (25MB).',
                evidence: sprintf('max_messages=%d, timeout_sec=%d, max_size_bytes=%d', $maxMsgs, $timeoutSec, $maxSize)
            );
        }

        // LH-MAIL-009 (CRITICAL, 25, CWE-798): Hardcoded plaintext SMTP password
        $password = (string) ($config['password'] ?? $config['smtp_password'] ?? '');
        if ($password !== '' && !str_starts_with($password, 'env:') && !str_starts_with($password, 'vault:') && !str_starts_with($password, '${')) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-MAIL-009',
                severity: 'CRITICAL',
                cwe: 'CWE-798',
                title: self::RULE_METADATA['LH-MAIL-009']['title'],
                description: 'Plaintext SMTP credential detected directly inside the configuration file.',
                recommendation: 'Reference secrets dynamically using environment variables ("env:SMTP_PASSWORD") or a secure vault.',
                evidence: 'Hardcoded password string detected (masked: ' . substr($password, 0, 2) . '****)'
            );
        }

        // LH-MAIL-010 (LOW, 1, CWE-755): Missing bounce alignment or RFC 8058 one-click unsubscribe
        $bounceAlignment = (bool) ($config['bounce_alignment'] ?? $config['envelope_alignment'] ?? true);
        $oneClickUnsub = (bool) ($config['require_one_click_unsubscribe'] ?? $config['list_unsubscribe_post'] ?? true);

        if (!$bounceAlignment || !$oneClickUnsub) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-MAIL-010',
                severity: 'LOW',
                cwe: 'CWE-755',
                title: self::RULE_METADATA['LH-MAIL-010']['title'],
                description: 'Return-Path envelope alignment or RFC 8058 one-click unsubscribe header is not enforced.',
                recommendation: 'Enable bounce_alignment: true and require_one_click_unsubscribe: true for bulk/transactional mail.',
                evidence: sprintf('bounce_alignment=%s, require_one_click_unsubscribe=%s', $bounceAlignment ? 'true' : 'false', $oneClickUnsub ? 'true' : 'false')
            );
        }

        return $this->buildResult($target, 'configuration', $findings);
    }

    /**
     * Audit an EML message file.
     *
     * @param string $emlContent Raw EML message.
     * @param string $target Target file name/path.
     * @return AuditResult
     */
    public function auditEml(string $emlContent, string $target = 'message.eml'): AuditResult
    {
        $findings = [];
        $parts = preg_split("/\r\n\r\n|\n\n/", $emlContent, 2);
        $headerSection = $parts[0] ?? '';

        $signer = new DkimSigner();
        $headers = $signer->parseHeaders($headerSection);
        $headerMap = [];
        foreach ($headers as $h) {
            $headerMap[strtolower($h['name'])] = $h['value'];
        }

        // Check for DKIM-Signature
        if (!isset($headerMap['dkim-signature'])) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-MAIL-002',
                severity: 'CRITICAL',
                cwe: 'CWE-345',
                title: self::RULE_METADATA['LH-MAIL-002']['title'],
                description: 'Raw email message lacks a DKIM-Signature header.',
                recommendation: 'Sign outgoing messages using DkimSigner before dispatch.',
                evidence: 'DKIM-Signature header absent'
            );
        } else {
            // Check DKIM tags
            $dkimVal = $headerMap['dkim-signature'];
            if (str_contains(strtolower($dkimVal), 'a=rsa-sha1') || str_contains(strtolower($dkimVal), 'a=sha1')) {
                $findings[] = new AuditFinding(
                    ruleId: 'LH-MAIL-003',
                    severity: 'HIGH',
                    cwe: 'CWE-326',
                    title: self::RULE_METADATA['LH-MAIL-003']['title'],
                    description: 'DKIM-Signature uses deprecated SHA-1 algorithm.',
                    recommendation: 'Upgrade to a=rsa-sha256.',
                    evidence: 'a=rsa-sha1 in signature'
                );
            }

            if (preg_match('/h=([^;]+)/', $dkimVal, $hMatch)) {
                $signedH = array_map('trim', explode(':', strtolower($hMatch[1])));
                $missing = array_diff(['from', 'subject', 'date', 'message-id'], $signedH);
                if (!empty($missing)) {
                    $findings[] = new AuditFinding(
                        ruleId: 'LH-MAIL-004',
                        severity: 'HIGH',
                        cwe: 'CWE-347',
                        title: self::RULE_METADATA['LH-MAIL-004']['title'],
                        description: 'DKIM-Signature omits mandatory headers in h= tag.',
                        recommendation: 'Include from, date, subject, and message-id in DKIM h= tag.',
                        evidence: 'Missing signed headers: ' . implode(', ', $missing)
                    );
                }
            }
        }

        // Check for List-Unsubscribe-Post if List-Unsubscribe is present
        if (isset($headerMap['list-unsubscribe']) && !isset($headerMap['list-unsubscribe-post'])) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-MAIL-010',
                severity: 'LOW',
                cwe: 'CWE-755',
                title: self::RULE_METADATA['LH-MAIL-010']['title'],
                description: 'Email contains List-Unsubscribe but lacks RFC 8058 List-Unsubscribe-Post header.',
                recommendation: 'Add List-Unsubscribe-Post: List-Unsubscribe=One-Click for one-click unsubscribe support.',
                evidence: 'List-Unsubscribe present without List-Unsubscribe-Post'
            );
        }

        return $this->buildResult($target, 'eml', $findings);
    }

    /**
     * Compute summary metrics and calculate S_posture score.
     *
     * @param string $target Target path.
     * @param string $type Target type.
     * @param array<AuditFinding> $findings Detected findings.
     * @return AuditResult
     */
    private function buildResult(string $target, string $type, array $findings): AuditResult
    {
        $critical = 0;
        $high = 0;
        $medium = 0;
        $low = 0;

        foreach ($findings as $f) {
            match ($f->severity) {
                'CRITICAL' => $critical++,
                'HIGH' => $high++,
                'MEDIUM' => $medium++,
                'LOW' => $low++,
                default => null,
            };
        }

        // S_posture = max(0, 100 - (25 * c_CRITICAL + 10 * c_HIGH + 4 * c_MEDIUM + 1 * c_LOW))
        $deduction = (25 * $critical) + (10 * $high) + (4 * $medium) + (1 * $low);
        $postureScore = max(0, 100 - $deduction);

        $summary = [
            'total_findings' => count($findings),
            'critical' => $critical,
            'high' => $high,
            'medium' => $medium,
            'low' => $low,
        ];

        return new AuditResult(
            target: $target,
            targetType: $type,
            timestamp: gmdate('Y-m-d\TH:i:s\Z'),
            postureScore: $postureScore,
            findings: $findings,
            summary: $summary,
        );
    }
}
