<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-logimail-engine (bin/lh-mail)
// Module:        Logihertz\LogiMail\Exporters
// Role:          Rich ANSI Table, Canonical JSON, and OASIS SARIF v2.1.0 Exporters
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

namespace Logihertz\LogiMail;

/**
 * Report exporters providing ANSI terminal tables, canonical JSON, and OASIS SARIF v2.1.0.
 */
class Exporters
{
    public const string TOOL_NAME = 'lh-logimail-engine';
    public const string TOOL_VERSION = '0.1.0';
    public const string ORGANIZATION = 'Logihertz Systems (OPC) Private Limited';
    public const string REPOSITORY_URL = 'https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-logimail-engine';

    /**
     * Render an ANSI / ASCII colored terminal report table.
     *
     * @param AuditResult $result The audit result object.
     * @return string Formatted terminal output string.
     */
    public static function renderTable(AuditResult $result): string
    {
        $out = [];
        $out[] = '================================================================================';
        $out[] = sprintf('  Logihertz Mail & DKIM Security Engine (%s v%s)', self::TOOL_NAME, self::TOOL_VERSION);
        $out[] = '================================================================================';
        $out[] = sprintf('Target:     %s', $result->target);
        $out[] = sprintf('Scan Type:  %s', ucfirst($result->targetType));
        $out[] = sprintf('Timestamp:  %s', $result->timestamp);

        // Colorize score
        $score = $result->postureScore;
        $scoreColor = match (true) {
            $score >= 80 => "\033[32m", // Green
            $score >= 50 => "\033[33m", // Yellow
            default => "\033[31m",      // Red
        };
        $resetColor = "\033[0m";

        $out[] = sprintf("Posture:    %s[%d/100]%s", $scoreColor, $score, $resetColor);
        $out[] = '--------------------------------------------------------------------------------';
        $out[] = sprintf(
            'Summary:    Total Findings: %d | Critical: %d | High: %d | Medium: %d | Low: %d',
            $result->summary['total_findings'],
            $result->summary['critical'],
            $result->summary['high'],
            $result->summary['medium'],
            $result->summary['low']
        );
        $out[] = '--------------------------------------------------------------------------------';

        if (empty($result->findings)) {
            $out[] = '';
            $out[] = sprintf("  %s✓ No mail infrastructure vulnerabilities or policy violations detected!%s", "\033[32m", $resetColor);
            $out[] = '';
            $out[] = '================================================================================';
            return implode("\n", $out) . "\n";
        }

        $out[] = '';
        $out[] = sprintf(
            '%-13s %-10s %-10s %-42s',
            'RULE ID',
            'SEVERITY',
            'CWE',
            'DESCRIPTION'
        );
        $out[] = str_repeat('-', 80);

        foreach ($result->findings as $finding) {
            $sevColor = match ($finding->severity) {
                'CRITICAL' => "\033[31;1m", // Bold Red
                'HIGH' => "\033[31m",       // Red
                'MEDIUM' => "\033[33m",     // Yellow
                'LOW' => "\033[36m",        // Cyan
                default => "\033[0m",
            };

            $desc = strlen($finding->title) > 42 ? substr($finding->title, 0, 39) . '...' : $finding->title;

            $out[] = sprintf(
                '%-13s %s%-10s%s %-10s %-42s',
                $finding->ruleId,
                $sevColor,
                $finding->severity,
                $resetColor,
                $finding->cwe,
                $desc
            );

            if ($finding->evidence !== null) {
                $out[] = sprintf('  Evidence: %s', $finding->evidence);
            }
        }

        $out[] = '';
        $out[] = '================================================================================';
        return implode("\n", $out) . "\n";
    }

    /**
     * Export audit results as canonical pretty-printed JSON.
     *
     * @param AuditResult $result
     * @return string Valid JSON string.
     */
    public static function exportJson(AuditResult $result): string
    {
        $payload = [
            'tool' => [
                'name' => self::TOOL_NAME,
                'version' => self::TOOL_VERSION,
                'organization' => self::ORGANIZATION,
                'homepage' => 'https://logihertz.com/',
            ],
            'scan_target' => $result->target,
            'target_type' => $result->targetType,
            'timestamp' => $result->timestamp,
            'posture_score' => $result->postureScore,
            'summary' => $result->summary,
            'findings' => array_map(static fn(AuditFinding $f): array => $f->toArray(), $result->findings),
        ];

        return json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    }

    /**
     * Export audit results complying with OASIS SARIF v2.1.0 standard schema.
     *
     * @param AuditResult $result
     * @return string Valid SARIF JSON string.
     */
    public static function exportSarif(AuditResult $result): string
    {
        // Build driver rule definitions
        $rules = [];
        foreach (MailAuditor::RULE_METADATA as $ruleId => $meta) {
            $level = match ($meta['severity']) {
                'CRITICAL', 'HIGH' => 'error',
                'MEDIUM' => 'warning',
                'LOW' => 'note',
                default => 'none',
            };

            $rules[] = [
                'id' => $ruleId,
                'name' => str_replace('-', '', $ruleId),
                'shortDescription' => [
                    'text' => $meta['title'],
                ],
                'fullDescription' => [
                    'text' => sprintf('%s (%s, Weight: %d)', $meta['title'], $meta['cwe'], $meta['weight']),
                ],
                'defaultConfiguration' => [
                    'level' => $level,
                ],
                'helpUri' => self::REPOSITORY_URL . '#core-detection-rules',
                'properties' => [
                    'cwe' => [$meta['cwe']],
                    'precision' => 'very-high',
                    'security-severity' => (string) ($meta['weight'] / 2.5),
                ],
            ];
        }

        // Map findings to SARIF results
        $sarifResults = [];
        foreach ($result->findings as $finding) {
            $level = match ($finding->severity) {
                'CRITICAL', 'HIGH' => 'error',
                'MEDIUM' => 'warning',
                'LOW' => 'note',
                default => 'none',
            };

            $sarifResults[] = [
                'ruleId' => $finding->ruleId,
                'level' => $level,
                'message' => [
                    'text' => $finding->description . ($finding->evidence !== null ? " [Evidence: {$finding->evidence}]" : ''),
                ],
                'locations' => [
                    [
                        'physicalLocation' => [
                            'artifactLocation' => [
                                'uri' => $result->target,
                                'uriBaseId' => '%SRCROOT%',
                            ],
                        ],
                    ],
                ],
                'properties' => [
                    'recommendation' => $finding->recommendation,
                    'cwe' => $finding->cwe,
                ],
            ];
        }

        $sarif = [
            '$schema' => 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => self::TOOL_NAME,
                            'version' => self::TOOL_VERSION,
                            'organization' => self::ORGANIZATION,
                            'informationUri' => self::REPOSITORY_URL,
                            'rules' => $rules,
                        ],
                    ],
                    'results' => $sarifResults,
                ],
            ],
        ];

        return json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    }
}
