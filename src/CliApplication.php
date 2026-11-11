<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-logimail-engine (bin/lh-mail)
// Module:        Logihertz\LogiMail\CliApplication
// Role:          CLI Execution Controller & Argument Router
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

namespace Logihertz\LogiMail;

use Throwable;

/**
 * Command-line interface router and controller for bin/lh-mail.
 */
class CliApplication
{
    public const EXIT_OK = 0;
    public const EXIT_POLICY_VIOLATION = 1;
    public const EXIT_USAGE_ERROR = 2;

    /**
     * Run the application with command line arguments.
     *
     * @param array<int, string> $argv Command line arguments.
     * @return int Exit code (0, 1, or 2).
     */
    public function run(array $argv): int
    {
        array_shift($argv); // Remove script name

        if (empty($argv) || in_array('--help', $argv, true) || in_array('-h', $argv, true)) {
            $this->printHelp();
            return empty($argv) ? self::EXIT_USAGE_ERROR : self::EXIT_OK;
        }

        if (in_array('--version', $argv, true) || in_array('-v', $argv, true)) {
            $this->printVersion();
            return self::EXIT_OK;
        }

        $command = array_shift($argv);

        return match ($command) {
            'scan' => $this->handleScan($argv),
            'sign' => $this->handleSign($argv),
            'send-test' => $this->handleSendTest($argv),
            default => $this->handleUnknownCommand($command),
        };
    }

    /**
     * Handle the `scan` subcommand.
     *
     * @param array<int, string> $args Remaining arguments.
     * @return int Exit code.
     */
    private function handleScan(array $args): int
    {
        if (empty($args)) {
            fwrite(STDERR, "Error: Missing target path for 'scan' command.\n");
            fwrite(STDERR, "Usage: lh-mail scan <path-to-config-or-eml> [--format table|json|sarif] [--output <path>]\n");
            return self::EXIT_USAGE_ERROR;
        }

        $targetPath = '';
        $format = 'table';
        $outputPath = null;

        for ($i = 0; $i < count($args); $i++) {
            $arg = $args[$i];
            if ($arg === '--format' || $arg === '-f') {
                $format = strtolower($args[++$i] ?? 'table');
            } elseif (str_starts_with($arg, '--format=')) {
                $format = strtolower(substr($arg, 9));
            } elseif ($arg === '--output' || $arg === '-o') {
                $outputPath = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--output=')) {
                $outputPath = substr($arg, 9);
            } elseif (!str_starts_with($arg, '-') && $targetPath === '') {
                $targetPath = $arg;
            } else {
                fwrite(STDERR, "Error: Unrecognized option '{$arg}'.\n");
                return self::EXIT_USAGE_ERROR;
            }
        }

        if ($targetPath === '') {
            fwrite(STDERR, "Error: Missing target file path.\n");
            return self::EXIT_USAGE_ERROR;
        }

        if (!in_array($format, ['table', 'json', 'sarif'], true)) {
            fwrite(STDERR, "Error: Invalid output format '{$format}'. Allowed: table, json, sarif.\n");
            return self::EXIT_USAGE_ERROR;
        }

        try {
            $auditor = new MailAuditor();
            $result = $auditor->auditFile($targetPath);

            $rendered = match ($format) {
                'json' => Exporters::exportJson($result),
                'sarif' => Exporters::exportSarif($result),
                default => Exporters::renderTable($result),
            };

            if ($outputPath !== null) {
                if (file_put_contents($outputPath, $rendered) === false) {
                    fwrite(STDERR, "Error: Unable to write report to '{$outputPath}'.\n");
                    return self::EXIT_USAGE_ERROR;
                }
                echo "Report successfully written to {$outputPath}\n";
            } else {
                echo $rendered;
            }

            return $result->summary['total_findings'] > 0 ? self::EXIT_POLICY_VIOLATION : self::EXIT_OK;
        } catch (Throwable $e) {
            fwrite(STDERR, 'Audit Error: ' . $e->getMessage() . "\n");
            return self::EXIT_USAGE_ERROR;
        }
    }

    /**
     * Handle the `sign` subcommand.
     *
     * @param array<int, string> $args Remaining arguments.
     * @return int Exit code.
     */
    private function handleSign(array $args): int
    {
        if (empty($args)) {
            fwrite(STDERR, "Error: Missing input EML file for 'sign' command.\n");
            fwrite(STDERR, "Usage: lh-mail sign <input.eml> --domain <domain> --selector <selector> [--key <key.pem>] [--output <path>]\n");
            return self::EXIT_USAGE_ERROR;
        }

        $inputPath = '';
        $domain = '';
        $selector = '';
        $keyPath = null;
        $outputPath = null;

        for ($i = 0; $i < count($args); $i++) {
            $arg = $args[$i];
            if ($arg === '--domain' || $arg === '-d') {
                $domain = $args[++$i] ?? '';
            } elseif (str_starts_with($arg, '--domain=')) {
                $domain = substr($arg, 9);
            } elseif ($arg === '--selector' || $arg === '-s') {
                $selector = $args[++$i] ?? '';
            } elseif (str_starts_with($arg, '--selector=')) {
                $selector = substr($arg, 11);
            } elseif ($arg === '--key' || $arg === '-k') {
                $keyPath = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--key=')) {
                $keyPath = substr($arg, 6);
            } elseif ($arg === '--output' || $arg === '-o') {
                $outputPath = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--output=')) {
                $outputPath = substr($arg, 9);
            } elseif (!str_starts_with($arg, '-') && $inputPath === '') {
                $inputPath = $arg;
            } else {
                fwrite(STDERR, "Error: Unrecognized option '{$arg}'.\n");
                return self::EXIT_USAGE_ERROR;
            }
        }

        if ($inputPath === '' || !is_file($inputPath)) {
            fwrite(STDERR, "Error: Input EML file not found or unreadable: '{$inputPath}'\n");
            return self::EXIT_USAGE_ERROR;
        }

        if ($domain === '' || $selector === '') {
            fwrite(STDERR, "Error: Both --domain and --selector are mandatory for DKIM signing.\n");
            return self::EXIT_USAGE_ERROR;
        }

        try {
            $rawEml = file_get_contents($inputPath);
            if ($rawEml === false) {
                fwrite(STDERR, "Error: Failed to read '{$inputPath}'.\n");
                return self::EXIT_USAGE_ERROR;
            }

            $signer = new DkimSigner();

            if ($keyPath !== null) {
                if (!is_file($keyPath)) {
                    fwrite(STDERR, "Error: Private key PEM file not found: '{$keyPath}'\n");
                    return self::EXIT_USAGE_ERROR;
                }
                $privateKeyPem = file_get_contents($keyPath);
                if ($privateKeyPem === false) {
                    fwrite(STDERR, "Error: Failed to read private key file: '{$keyPath}'\n");
                    return self::EXIT_USAGE_ERROR;
                }
            } else {
                // Generate ephemeral 2048-bit RSA key
                $res = openssl_pkey_new([
                    'private_key_bits' => 2048,
                    'private_key_type' => OPENSSL_KEYTYPE_RSA,
                ]);
                if ($res === false) {
                    fwrite(STDERR, "Error: Failed to generate ephemeral RSA signing key.\n");
                    return self::EXIT_USAGE_ERROR;
                }
                openssl_pkey_export($res, $privateKeyPem);
            }

            $signedMessage = $signer->sign($rawEml, $domain, $selector, $privateKeyPem);

            if ($outputPath !== null) {
                if (file_put_contents($outputPath, $signedMessage) === false) {
                    fwrite(STDERR, "Error: Failed to write signed message to '{$outputPath}'.\n");
                    return self::EXIT_USAGE_ERROR;
                }
                echo "Signed RFC 5322 message written to {$outputPath}\n";
            } else {
                echo $signedMessage;
            }

            return self::EXIT_OK;
        } catch (Throwable $e) {
            fwrite(STDERR, 'Signing Error: ' . $e->getMessage() . "\n");
            return self::EXIT_USAGE_ERROR;
        }
    }

    /**
     * Handle the `send-test` subcommand.
     *
     * @param array<int, string> $args Remaining arguments.
     * @return int Exit code.
     */
    private function handleSendTest(array $args): int
    {
        if (empty($args)) {
            fwrite(STDERR, "Error: Missing configuration path for 'send-test' command.\n");
            fwrite(STDERR, "Usage: lh-mail send-test <mail_config.json> [--dry-run]\n");
            return self::EXIT_USAGE_ERROR;
        }

        $configPath = $args[0];
        $dryRun = in_array('--dry-run', $args, true);

        if (!is_file($configPath)) {
            fwrite(STDERR, "Error: Config file not found: '{$configPath}'\n");
            return self::EXIT_USAGE_ERROR;
        }

        try {
            $config = json_decode((string) file_get_contents($configPath), true, 512, JSON_THROW_ON_ERROR);

            $client = new SmtpMultiplexer(
                host: (string) ($config['host'] ?? '127.0.0.1'),
                port: (int) ($config['port'] ?? 587),
                tlsMode: (string) ($config['tls_mode'] ?? 'starttls'),
                verifyPeer: (bool) ($config['verify_peer'] ?? true),
                timeoutSeconds: (int) ($config['socket_timeout_seconds'] ?? 30),
                maxMessagesPerConnection: (int) ($config['max_messages_per_connection'] ?? 100),
                dryRun: $dryRun || (bool) ($config['dry_run'] ?? false),
            );

            $builder = new MimeBuilder();
            $builder->setFrom('test@' . ($config['dkim_domain'] ?? 'localhost'), 'LogiMail Test')
                ->addTo('recipient@' . ($config['dkim_domain'] ?? 'localhost'))
                ->setSubject('LogiMail Self-Test Probe')
                ->setTextBody("This is an automated delivery probe from lh-logimail-engine.\r\nTimestamp: " . date(DATE_ATOM));

            $rawMsg = $builder->build();
            $client->sendMessage('test@' . ($config['dkim_domain'] ?? 'localhost'), 'recipient@' . ($config['dkim_domain'] ?? 'localhost'), $rawMsg);
            $client->disconnect();

            echo "✓ Delivery probe dispatched successfully (Dry-Run: " . ($client->getWireTranscript() ? 'true' : 'false') . ").\n";
            return self::EXIT_OK;
        } catch (Throwable $e) {
            fwrite(STDERR, 'Transport Error: ' . $e->getMessage() . "\n");
            return self::EXIT_USAGE_ERROR;
        }
    }

    /**
     * Print help information.
     */
    public function printHelp(): void
    {
        echo <<<HELP
lh-mail: Enterprise Zero-Dependency RFC 6376 DKIM Signer & Mail Posture Auditor
Version: 0.1.0 | Logihertz Systems (OPC) Private Limited

USAGE:
  lh-mail scan <path-to-config-or-eml> [options]
  lh-mail sign <input.eml> --domain <domain> --selector <selector> [options]
  lh-mail send-test <mail_config.json> [--dry-run]
  lh-mail --version
  lh-mail --help

COMMANDS:
  scan        Audit mail gateway configuration or EML message against rules LH-MAIL-001..010
  sign        Canonicalize and sign an RFC 5322 EML message with relaxed/relaxed RSA-SHA256 DKIM
  send-test   Execute connection pooling dry-run or live SMTP dispatch probe

SCAN OPTIONS:
  --format, -f <table|json|sarif>   Report output format (default: table)
  --output, -o <path>               Optional destination file path for report

SIGN OPTIONS:
  --domain, -d <domain>             DKIM signing domain (d= tag, required)
  --selector, -s <selector>         DKIM key selector (s= tag, required)
  --key, -k <path>                  RSA private key PEM (generates ephemeral 2048-bit key if omitted)
  --output, -o <path>               Write signed EML to file (defaults to stdout)

EXIT CODES:
  0   Audit clean (zero policy findings) or operation succeeded
  1   Security policy findings detected (total_findings > 0)
  2   CLI usage error, invalid options, or unreadable target

HELP;
    }

    /**
     * Print version details.
     */
    public function printVersion(): void
    {
        echo sprintf(
            "%s v%s (PHP %s, ext-openssl, ext-json, ext-spl)\n%s\nCreator & Sole Developer: Sameer Tawade <ops@logihertz.com>\n",
            Exporters::TOOL_NAME,
            Exporters::TOOL_VERSION,
            PHP_VERSION,
            Exporters::ORGANIZATION
        );
    }

    /**
     * Handle unrecognized command.
     */
    private function handleUnknownCommand(string $command): int
    {
        fwrite(STDERR, "Error: Unknown command '{$command}'.\n");
        fwrite(STDERR, "Run 'lh-mail --help' for available commands.\n");
        return self::EXIT_USAGE_ERROR;
    }
}
