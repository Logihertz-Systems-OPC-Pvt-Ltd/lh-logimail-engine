<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-logimail-engine (bin/lh-mail)
// Module:        tests/run_tests.php
// Role:          Zero-Dependency Deterministic Test Suite
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

require_once __DIR__ . '/../src/Autoloader.php';

use Logihertz\LogiMail\Autoloader;
use Logihertz\LogiMail\DkimSigner;
use Logihertz\LogiMail\MimeBuilder;
use Logihertz\LogiMail\SmtpMultiplexer;
use Logihertz\LogiMail\MailAuditor;
use Logihertz\LogiMail\Exporters;
use Logihertz\LogiMail\CliApplication;

Autoloader::register();

class TestRunner
{
    private int $totalAssertions = 0;
    private int $passedAssertions = 0;
    /** @var array<string> */
    private array $failures = [];

    public function assert(bool $condition, string $description): void
    {
        $this->totalAssertions++;
        if ($condition) {
            $this->passedAssertions++;
            echo "  \033[32m✓\033[0m {$description}\n";
        } else {
            $this->failures[] = $description;
            echo "  \033[31m✗ FAIL:\033[0m {$description}\n";
        }
    }

    public function summary(): int
    {
        echo "\n" . str_repeat('=', 80) . "\n";
        if (empty($this->failures)) {
            echo sprintf(
                "\033[32;1mTEST SUITE PASSED:\033[0m %d/%d assertions passing (100%% success rate)\n",
                $this->passedAssertions,
                $this->totalAssertions
            );
            echo str_repeat('=', 80) . "\n\n";
            return 0;
        }

        echo sprintf(
            "\033[31;1mTEST SUITE FAILED:\033[0m %d/%d assertions failed:\n",
            count($this->failures),
            $this->totalAssertions
        );
        foreach ($this->failures as $f) {
            echo " - {$f}\n";
        }
        echo str_repeat('=', 80) . "\n\n";
        return 1;
    }
}

$t = new TestRunner();

echo "\n================================================================================\n";
echo "  lh-logimail-engine: Zero-Dependency Verification Test Suite\n";
echo "================================================================================\n\n";

// -----------------------------------------------------------------------------
// Group 1: Autoloader Verification
// -----------------------------------------------------------------------------
echo "[Group 1: Autoloader Verification]\n";
$t->assert(class_exists(DkimSigner::class), 'Autoloader resolves DkimSigner class');
$t->assert(!Autoloader::loadClass('Vendor\\ForeignClass'), 'Autoloader ignores foreign namespace');
$t->assert(!Autoloader::loadClass('Logihertz\\LogiMail\\NonexistentClassXYZ'), 'Autoloader handles missing class gracefully');

// -----------------------------------------------------------------------------
// Group 2: RFC 6376 Relaxed Header Canonicalization
// -----------------------------------------------------------------------------
echo "\n[Group 2: RFC 6376 Relaxed Header Canonicalization]\n";
$signer = new DkimSigner();

$h1 = $signer->canonicalizeHeaderRelaxed('Subject', 'Hello World');
$t->assert($h1 === 'subject:Hello World', 'Header field name converted to lowercase');

$h2 = $signer->canonicalizeHeaderRelaxed('FROM  ', '   ops@logihertz.com   ');
$t->assert($h2 === 'from:ops@logihertz.com', 'Leading and trailing whitespace stripped');

$h3 = $signer->canonicalizeHeaderRelaxed('X-Custom', "Line1 \t  Value \t  More");
$t->assert($h3 === 'x-custom:Line1 Value More', 'Internal WSP sequences compressed to single space');

$h4 = $signer->canonicalizeHeaderRelaxed('Received', "from server.example.com\r\n\tby mail.example.com");
$t->assert($h4 === 'received:from server.example.com by mail.example.com', 'Header continuation unfolded');

$h5 = $signer->canonicalizeHeaderRelaxed('To', "  Recipient <user@example.com> \r\n  with details  ");
$t->assert($h5 === 'to:Recipient <user@example.com> with details', 'Multi-line continuation unfolded and compressed');

$h6 = $signer->canonicalizeHeaderRelaxed('Date', ' Wed, 11 Nov 2026 10:00:00 +0000 ');
$t->assert($h6 === 'date:Wed, 11 Nov 2026 10:00:00 +0000', 'Colon immediately follows lowercase name without spaces');

// -----------------------------------------------------------------------------
// Group 3: RFC 6376 Relaxed Body Canonicalization
// -----------------------------------------------------------------------------
echo "\n[Group 3: RFC 6376 Relaxed Body Canonicalization]\n";

$b1 = $signer->canonicalizeBodyRelaxed('');
$t->assert($b1 === '', 'Empty body canonicalizes to empty string');

$b2 = $signer->canonicalizeBodyRelaxed("   \r\n   \r\n   ");
$t->assert($b2 === '', 'Whitespace-only body canonicalizes to empty string');

$b3 = $signer->canonicalizeBodyRelaxed("Hello World\nLine 2\n");
$t->assert($b3 === "Hello World\r\nLine 2\r\n", 'Normalizes bare LF to CRLF');

$b4 = $signer->canonicalizeBodyRelaxed("Line 1  \t  \r\nLine 2\t\r\n");
$t->assert($b4 === "Line 1\r\nLine 2\r\n", 'Strips trailing WSP at the end of each line before CRLF');

$b5 = $signer->canonicalizeBodyRelaxed("Word1    Word2\t\tWord3\r\n");
$t->assert($b5 === "Word1 Word2 Word3\r\n", 'Compresses internal sequences of WSP on a line to single space');

$b6 = $signer->canonicalizeBodyRelaxed("Content\r\n\r\n\r\n\r\n");
$t->assert($b6 === "Content\r\n", 'Compresses multiple trailing empty lines to a single CRLF');

$b7 = $signer->canonicalizeBodyRelaxed("No trailing newline");
$t->assert($b7 === "No trailing newline\r\n", 'Appends CRLF to non-empty body missing terminating newline');

// -----------------------------------------------------------------------------
// Group 4: RFC 6376 Body Hash & RSA Key Inspection
// -----------------------------------------------------------------------------
echo "\n[Group 4: Body Hash & RSA Key Inspection]\n";

// RFC 6376 Section 3.4.4: SHA-256 hash of empty canonical body ("")
$emptyHash = $signer->computeBodyHash('');
$t->assert($emptyHash === '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=', 'SHA-256 body hash of empty body matches RFC 6376 standard');

// Ephemeral 2048-bit RSA key generation
$res2048 = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$t->assert($res2048 !== false, 'Successfully generated ephemeral 2048-bit RSA key');
openssl_pkey_export($res2048, $pem2048);

$insp2048 = $signer->inspectPrivateKey($pem2048);
$t->assert($insp2048['valid'] === true && $insp2048['bits'] === 2048 && $insp2048['type'] === 'RSA', 'Key inspection validates 2048-bit RSA key');

// Ephemeral 1024-bit RSA key inspection
$res1024 = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
openssl_pkey_export($res1024, $pem1024);
$insp1024 = $signer->inspectPrivateKey($pem1024);
$t->assert($insp1024['valid'] === true && $insp1024['bits'] === 1024, 'Key inspection detects 1024-bit RSA key');

// Corrupted PEM inspection
$inspInvalid = $signer->inspectPrivateKey('-----BEGIN RSA PRIVATE KEY----- invalid content');
$t->assert($inspInvalid['valid'] === false, 'Key inspection rejects invalid PEM format');

// -----------------------------------------------------------------------------
// Group 5: DKIM Signature Generation & Cryptographic Verification
// -----------------------------------------------------------------------------
echo "\n[Group 5: DKIM Signature Generation & Cryptographic Verification]\n";

$rawEml = "From: sender@logihertz.com\r\nTo: recipient@logihertz.com\r\nSubject: Security Notice\r\nDate: Wed, 11 Nov 2026 10:00:00 +0000\r\nMessage-ID: <test001@logihertz.com>\r\n\r\nHello World Body Content";
$signed = $signer->sign($rawEml, 'logihertz.com', 'mail2026', $pem2048);

$t->assert(str_starts_with($signed, 'DKIM-Signature:'), 'Signed message has prepended DKIM-Signature header');
$t->assert(str_contains($signed, 'a=rsa-sha256'), 'DKIM header specifies a=rsa-sha256 algorithm');
$t->assert(str_contains($signed, 'c=relaxed/relaxed'), 'DKIM header specifies c=relaxed/relaxed canonicalization');
$t->assert(str_contains($signed, 'd=logihertz.com'), 'DKIM header contains d=logihertz.com tag');
$t->assert(str_contains($signed, 's=mail2026'), 'DKIM header contains s=mail2026 tag');

// Cryptographic verification against public key
$details2048 = openssl_pkey_get_details($res2048);
$pubKeyPem = $details2048['key'];

$verified = $signer->verify($signed, $pubKeyPem);
$t->assert($verified === true, 'Cryptographic verification via openssl_verify succeeds on authentic message');

// Tamper verification
$tampered = str_replace('Hello World', 'Tampered Content', $signed);
$tamperedVerified = $signer->verify($tampered, $pubKeyPem);
$t->assert($tamperedVerified === false, 'Cryptographic verification fails when message body is tampered');

// -----------------------------------------------------------------------------
// Group 6: MimeBuilder & CRLF Injection Sanitization
// -----------------------------------------------------------------------------
echo "\n[Group 6: MimeBuilder & CRLF Injection Sanitization]\n";

$t->assert(MimeBuilder::isHeaderValueClean('Clean subject line'), 'isHeaderValueClean returns true for clean header');
$t->assert(!MimeBuilder::isHeaderValueClean("Subject\r\nBcc: evil@attacker.com"), 'isHeaderValueClean returns false for literal CRLF');
$t->assert(!MimeBuilder::isHeaderValueClean("Subject%0aBcc: evil@attacker.com"), 'isHeaderValueClean returns false for URL-encoded %0a');
$t->assert(!MimeBuilder::isHeaderValueClean("Subject%0dBcc: evil@attacker.com"), 'isHeaderValueClean returns false for URL-encoded %0d');

$sanitized = MimeBuilder::sanitizeHeaderValue("victim@example.com\r\nBcc: evil@attacker.com");
$t->assert(!str_contains($sanitized, "\r") && !str_contains($sanitized, "\n"), 'sanitizeHeaderValue strips carriage return and line feed');

$builder = new MimeBuilder();
$builder->setFrom('ops@logihertz.com', 'Logihertz Operations')
    ->addTo('client@example.com', 'Client Partner')
    ->setSubject('Quarterly Security Report')
    ->setTextBody('Plain text report content')
    ->setHtmlBody('<h1>Security Report</h1><p>HTML content</p>')
    ->setListUnsubscribe('https://logihertz.com/unsub', true);

$builtMime = $builder->build();
$t->assert(str_contains($builtMime, 'multipart/alternative'), 'MimeBuilder generates multipart/alternative for dual text/html body');
$t->assert(str_contains($builtMime, 'List-Unsubscribe: <https://logihertz.com/unsub>'), 'MimeBuilder renders List-Unsubscribe header');
$t->assert(str_contains($builtMime, 'List-Unsubscribe-Post: List-Unsubscribe=One-Click'), 'MimeBuilder renders RFC 8058 one-click unsubscribe header');

// -----------------------------------------------------------------------------
// Group 7: SmtpMultiplexer Dry-Run Transport & Connection Pooling
// -----------------------------------------------------------------------------
echo "\n[Group 7: SmtpMultiplexer Dry-Run Transport & Connection Pooling]\n";

$client = new SmtpMultiplexer(
    host: 'smtp.logihertz.com',
    port: 587,
    tlsMode: 'starttls',
    verifyPeer: true,
    maxMessagesPerConnection: 100,
    username: 'ops_user',
    password: 'secret_password',
    dryRun: true
);

$client->connect();
$t->assert($client->isConnected(), 'Dry-run multiplexer connects and establishes virtual session');

$sent = $client->sendMessage('ops@logihertz.com', 'dest@logihertz.com', $builtMime);
$t->assert($sent === true, 'Dry-run multiplexer dispatches individual email message');

$transcript = $client->getWireTranscript();
$transcriptText = implode("\n", array_column($transcript, 'line'));
$t->assert(str_contains($transcriptText, 'STARTTLS'), 'Wire transcript contains STARTTLS handshake command');
$t->assert(str_contains($transcriptText, 'AUTH LOGIN'), 'Wire transcript contains AUTH command');
$t->assert(str_contains($transcriptText, 'MAIL FROM:<ops@logihertz.com>'), 'Wire transcript contains MAIL FROM envelope command');
$t->assert(str_contains($transcriptText, 'RCPT TO:<dest@logihertz.com>'), 'Wire transcript contains RCPT TO envelope command');

// Batch send with RSET state machine
$batch = [
    ['from' => 'a@logihertz.com', 'to' => 'b@logihertz.com', 'message' => 'msg 1'],
    ['from' => 'c@logihertz.com', 'to' => 'd@logihertz.com', 'message' => 'msg 2'],
];
$batchSent = $client->sendBatch($batch);
$t->assert($batchSent === 2, 'Batch sender dispatches all messages in connection pool');

$transcriptBatchText = implode("\n", array_column($client->getWireTranscript(), 'line'));
$t->assert(str_contains($transcriptBatchText, 'RSET'), 'Wire transcript contains RSET command between multiplexed messages');

$client->disconnect();
$t->assert(!$client->isConnected(), 'Multiplexer cleanly disconnects and issues QUIT');

// -----------------------------------------------------------------------------
// Group 8: MailAuditor 10 Rules & Posture Scoring
// -----------------------------------------------------------------------------
echo "\n[Group 8: MailAuditor 10 Rules & Posture Scoring]\n";

$auditor = new MailAuditor();

// 1. Hardened config test
$hardenedResult = $auditor->auditFile(__DIR__ . '/../fixtures/hardened_mail_config.json');
$t->assert($hardenedResult->summary['total_findings'] === 0, 'Hardened configuration produces 0 security findings');
$t->assert($hardenedResult->postureScore === 100, 'Hardened configuration achieves perfect posture score 100');

// 2. Vulnerable config test
$vulnResult = $auditor->auditFile(__DIR__ . '/../fixtures/vulnerable_mail_config.json');
$t->assert($vulnResult->summary['total_findings'] === 10, 'Vulnerable configuration triggers all 10 security rules');
$t->assert($vulnResult->postureScore === 0, 'Vulnerable configuration receives minimum posture score 0');
$t->assert($vulnResult->summary['critical'] === 3, 'Vulnerable configuration correctly categorizes 3 CRITICAL findings');
$t->assert($vulnResult->summary['high'] === 4, 'Vulnerable configuration correctly categorizes 4 HIGH findings');
$t->assert($vulnResult->summary['medium'] === 2, 'Vulnerable configuration correctly categorizes 2 MEDIUM findings');
$t->assert($vulnResult->summary['low'] === 1, 'Vulnerable configuration correctly categorizes 1 LOW finding');

$vulnRuleIds = array_column(array_map(fn($f) => $f->toArray(), $vulnResult->findings), 'rule_id');
$t->assert(in_array('LH-MAIL-001', $vulnRuleIds, true), 'Triggers LH-MAIL-001 (Plaintext transport)');
$t->assert(in_array('LH-MAIL-002', $vulnRuleIds, true), 'Triggers LH-MAIL-002 (DKIM disabled)');
$t->assert(in_array('LH-MAIL-003', $vulnRuleIds, true), 'Triggers LH-MAIL-003 (Weak key/hash)');
$t->assert(in_array('LH-MAIL-004', $vulnRuleIds, true), 'Triggers LH-MAIL-004 (Undersigned headers)');
$t->assert(in_array('LH-MAIL-005', $vulnRuleIds, true), 'Triggers LH-MAIL-005 (Permissive SPF)');
$t->assert(in_array('LH-MAIL-006', $vulnRuleIds, true), 'Triggers LH-MAIL-006 (Monitor-only DMARC)');
$t->assert(in_array('LH-MAIL-007', $vulnRuleIds, true), 'Triggers LH-MAIL-007 (CRLF protection disabled)');
$t->assert(in_array('LH-MAIL-008', $vulnRuleIds, true), 'Triggers LH-MAIL-008 (Unbounded multiplexing limits)');
$t->assert(in_array('LH-MAIL-009', $vulnRuleIds, true), 'Triggers LH-MAIL-009 (Plaintext password)');
$t->assert(in_array('LH-MAIL-010', $vulnRuleIds, true), 'Triggers LH-MAIL-010 (Missing bounce alignment/one-click)');

// 3. Isolated mathematical deduction test
$partialConfig = json_decode((string) file_get_contents(__DIR__ . '/../fixtures/hardened_mail_config.json'), true);
// Introduce 1 CRITICAL (weight 25) and 1 HIGH (weight 10)
$partialConfig['tls_mode'] = 'none'; // LH-MAIL-001 (CRITICAL: 25)
$partialConfig['dkim_key_bits'] = 1024; // LH-MAIL-003 (HIGH: 10)
$partialResult = $auditor->auditConfiguration($partialConfig);
$t->assert($partialResult->summary['critical'] === 1 && $partialResult->summary['high'] === 1, 'Isolated config yields 1 CRITICAL and 1 HIGH finding');
$t->assert($partialResult->postureScore === 65, 'Exact posture math: 100 - (25*1 + 10*1) = 65');

// -----------------------------------------------------------------------------
// Group 9: Exporters Validation (Table, JSON, SARIF)
// -----------------------------------------------------------------------------
echo "\n[Group 9: Exporters Validation]\n";

$tableOutput = Exporters::renderTable($vulnResult);
$t->assert(str_contains($tableOutput, 'LH-MAIL-001'), 'Table exporter displays rule ID');
$t->assert(str_contains($tableOutput, 'Posture:'), 'Table exporter displays posture score banner');

$jsonOutput = Exporters::exportJson($vulnResult);
$decodedJson = json_decode($jsonOutput, true);
$t->assert(is_array($decodedJson) && isset($decodedJson['posture_score']), 'JSON exporter outputs valid schema with posture_score');
$t->assert($decodedJson['summary']['total_findings'] === 10, 'JSON exporter retains accurate summary totals');

$sarifOutput = Exporters::exportSarif($vulnResult);
$decodedSarif = json_decode($sarifOutput, true);
$t->assert(is_array($decodedSarif) && ($decodedSarif['version'] ?? '') === '2.1.0', 'SARIF exporter outputs OASIS SARIF v2.1.0 schema');
$t->assert(count($decodedSarif['runs'][0]['tool']['driver']['rules']) === 10, 'SARIF exporter defines all 10 core detection rules');
$t->assert(count($decodedSarif['runs'][0]['results']) === 10, 'SARIF exporter maps all detected findings into results');

// -----------------------------------------------------------------------------
// Group 10: CLI Application & Subprocess Exit Codes
// -----------------------------------------------------------------------------
echo "\n[Group 10: CLI Application & Subprocess Exit Codes]\n";

$binPath = escapeshellarg(__DIR__ . '/../bin/lh-mail');

// 1. --help exit code 0
exec("php {$binPath} --help 2>&1", $helpOut, $helpCode);
$t->assert($helpCode === 0, 'CLI --help exits with code 0');

// 2. --version exit code 0
exec("php {$binPath} --version 2>&1", $verOut, $verCode);
$t->assert($verCode === 0, 'CLI --version exits with code 0');

// 3. scan hardened config exit code 0
$hardenedPath = escapeshellarg(__DIR__ . '/../fixtures/hardened_mail_config.json');
exec("php {$binPath} scan {$hardenedPath} 2>&1", $scanHardenedOut, $scanHardenedCode);
$t->assert($scanHardenedCode === 0, 'CLI scan on hardened configuration exits with code 0');

// 4. scan vulnerable config exit code 1
$vulnPath = escapeshellarg(__DIR__ . '/../fixtures/vulnerable_mail_config.json');
exec("php {$binPath} scan {$vulnPath} 2>&1", $scanVulnOut, $scanVulnCode);
$t->assert($scanVulnCode === 1, 'CLI scan on policy-violating configuration exits with code 1');

// 5. scan nonexistent file exit code 2
exec("php {$binPath} scan /nonexistent/file.json 2>&1", $scanErrOut, $scanErrCode);
$t->assert($scanErrCode === 2, 'CLI scan on invalid or missing file exits with code 2');

// 6. sign EML file exit code 0
$emlPath = escapeshellarg(__DIR__ . '/../fixtures/sample_unsigned.eml');
exec("php {$binPath} sign {$emlPath} --domain logihertz.com --selector sig2026 2>&1", $signOut, $signCode);
$t->assert($signCode === 0, 'CLI sign command executes successfully with exit code 0');
$t->assert(str_contains(implode("\n", $signOut), 'DKIM-Signature:'), 'CLI sign command outputs signed RFC 5322 payload');

// 7. send-test dry-run exit code 0
exec("php {$binPath} send-test {$hardenedPath} --dry-run 2>&1", $testOut, $testCode);
$t->assert($testCode === 0, 'CLI send-test --dry-run exits with code 0');

exit($t->summary());
