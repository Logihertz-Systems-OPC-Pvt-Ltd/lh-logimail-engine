<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-logimail-engine (bin/lh-mail)
// Module:        Logihertz\LogiMail\DkimSigner
// Role:          RFC 6376 Relaxed/Relaxed Canonicalizer & RSA-SHA256 Signer
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

namespace Logihertz\LogiMail;

use InvalidArgumentException;
use RuntimeException;

/**
 * Implements RFC 6376 DomainKeys Identified Mail (DKIM) with relaxed/relaxed
 * canonicalization and RSA-SHA256 signature generation and validation.
 */
class DkimSigner
{
    public const array DEFAULT_HEADERS_TO_SIGN = [
        'from',
        'to',
        'subject',
        'date',
        'message-id',
        'mime-version',
        'content-type',
    ];

    /**
     * Inspect an RSA private key PEM string to extract modulus bit length and validate type.
     *
     * @param string $pem The PEM-formatted private key.
     * @return array{valid: bool, bits: int, type: string, error: ?string}
     */
    public function inspectPrivateKey(string $pem): array
    {
        $key = openssl_pkey_get_private($pem);
        if ($key === false) {
            return [
                'valid' => false,
                'bits' => 0,
                'type' => 'UNKNOWN',
                'error' => 'Unable to parse private key PEM.',
            ];
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            return [
                'valid' => false,
                'bits' => 0,
                'type' => 'UNKNOWN',
                'error' => 'Unable to extract key details.',
            ];
        }

        $type = match ($details['type']) {
            OPENSSL_KEYTYPE_RSA => 'RSA',
            OPENSSL_KEYTYPE_DSA => 'DSA',
            OPENSSL_KEYTYPE_DH => 'DH',
            OPENSSL_KEYTYPE_EC => 'EC',
            default => 'OTHER',
        };

        return [
            'valid' => $type === 'RSA',
            'bits' => $details['bits'] ?? 0,
            'type' => $type,
            'error' => $type === 'RSA' ? null : 'Key is not an RSA private key.',
        ];
    }

    /**
     * Canonicalize a single header field using RFC 6376 Section 3.4.2 relaxed algorithm.
     *
     * - Convert header field name to lowercase.
     * - Unfold header continuations (CRLF followed by WSP becomes single space).
     * - Compress sequences of WSP into a single space.
     * - Strip leading and trailing WSP from the header value.
     *
     * @param string $headerName Field name.
     * @param string $headerValue Field value.
     * @return string Formatted as "headername:value" without trailing CRLF.
     */
    public function canonicalizeHeaderRelaxed(string $headerName, string $headerValue): string
    {
        $name = strtolower(trim($headerName));

        // Unfold continuations: CRLF or bare LF/CR followed by WSP
        $val = preg_replace("/\r\n[ \t]+|\r[ \t]+|\n[ \t]+/", ' ', $headerValue);
        // Compress multiple WSP characters to a single space
        $val = preg_replace('/[ \t]+/', ' ', (string) $val);
        // Strip leading and trailing whitespace
        $val = trim((string) $val);

        return $name . ':' . $val;
    }

    /**
     * Canonicalize body text using RFC 6376 Section 3.4.4 relaxed algorithm.
     *
     * - Normalize line endings to CRLF.
     * - Strip trailing whitespace from each line before CRLF.
     * - Compress sequences of WSP within a line to a single space.
     * - Compress multiple trailing empty lines to a single CRLF.
     * - If the body is empty or whitespace-only, the canonical body is empty string "".
     *
     * @param string $body Raw message body.
     * @return string Canonicalized body ending with CRLF or empty string.
     */
    public function canonicalizeBodyRelaxed(string $body): string
    {
        if ($body === '') {
            return '';
        }

        // Normalize all newlines to CRLF
        $normalized = preg_replace("/\r\n|\r|\n/", "\r\n", $body);
        $lines = explode("\r\n", (string) $normalized);

        $processedLines = [];
        foreach ($lines as $line) {
            // Compress internal WSP to single space
            $trimmed = preg_replace('/[ \t]+/', ' ', $line);
            // Strip trailing WSP
            $trimmed = rtrim((string) $trimmed, " \t");
            $processedLines[] = $trimmed;
        }

        // Remove empty lines from the end
        while (!empty($processedLines) && end($processedLines) === '') {
            array_pop($processedLines);
        }

        if (empty($processedLines)) {
            return '';
        }

        return implode("\r\n", $processedLines) . "\r\n";
    }

    /**
     * Compute RFC 6376 base64-encoded SHA-256 body hash (bh=).
     *
     * @param string $canonicalBody Relaxed canonicalized body.
     * @return string Base64 encoded SHA-256 digest.
     */
    public function computeBodyHash(string $canonicalBody): string
    {
        return base64_encode(hash('sha256', $canonicalBody, true));
    }

    /**
     * Sign an RFC 5322 message with RFC 6376 relaxed/relaxed RSA-SHA256 DKIM-Signature.
     *
     * @param string $rawMessage Full RFC 5322 message (headers + body).
     * @param string $domain Signing domain (d= tag).
     * @param string $selector DKIM selector (s= tag).
     * @param string $privateKeyPem RSA private key PEM string.
     * @param array<string> $headersToSign Header names to include in signature.
     * @param int|null $timestamp Optional timestamp (defaults to current time).
     * @return string Signed message with prepended DKIM-Signature header.
     *
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function sign(
        string $rawMessage,
        string $domain,
        string $selector,
        string $privateKeyPem,
        array $headersToSign = self::DEFAULT_HEADERS_TO_SIGN,
        ?int $timestamp = null
    ): string {
        $keyInspection = $this->inspectPrivateKey($privateKeyPem);
        if (!$keyInspection['valid']) {
            throw new InvalidArgumentException('Invalid RSA private key: ' . ($keyInspection['error'] ?? 'Unknown error'));
        }

        // Split message into headers and body
        $parts = preg_split("/\r\n\r\n|\n\n/", $rawMessage, 2);
        $headerSection = $parts[0] ?? '';
        $bodySection = $parts[1] ?? '';

        // Canonicalize body and compute hash
        $canonicalBody = $this->canonicalizeBodyRelaxed($bodySection);
        $bodyHash = $this->computeBodyHash($canonicalBody);

        // Parse message headers into list preserving case and order
        $parsedHeaders = $this->parseHeaders($headerSection);

        // Identify matched headers to sign (in case-insensitive order requested)
        $signedHeaderNames = [];
        $canonicalHeadersList = [];

        foreach ($headersToSign as $reqHeader) {
            $lowerReq = strtolower($reqHeader);
            // Search backwards or first occurrence matching RFC conventions
            foreach ($parsedHeaders as $header) {
                if (strtolower($header['name']) === $lowerReq) {
                    $signedHeaderNames[] = $header['name'];
                    $canonicalHeadersList[] = $this->canonicalizeHeaderRelaxed($header['name'], $header['value']) . "\r\n";
                    break;
                }
            }
        }

        if (empty($signedHeaderNames)) {
            throw new RuntimeException('None of the requested headers to sign were found in the message.');
        }

        $timestampVal = $timestamp ?? time();
        $hList = implode(':', array_map('strtolower', $signedHeaderNames));

        // Construct uncommitted DKIM-Signature header
        $dkimParams = [
            'v=1',
            'a=rsa-sha256',
            'c=relaxed/relaxed',
            'd=' . $domain,
            's=' . $selector,
            't=' . $timestampVal,
            'h=' . $hList,
            'bh=' . $bodyHash,
            'b=',
        ];
        $dkimHeaderValue = implode('; ', $dkimParams);

        // Per RFC 6376 Section 3.7: Canonicalize the DKIM-Signature header without the 'b=' value and without trailing CRLF
        $canonicalDkimHeader = $this->canonicalizeHeaderRelaxed('DKIM-Signature', $dkimHeaderValue);

        // Prepare data to sign: canonical headers + canonical DKIM-Signature
        $dataToSign = implode('', $canonicalHeadersList) . $canonicalDkimHeader;

        // Perform RSA-SHA256 signature
        $binarySignature = '';
        $pkey = openssl_pkey_get_private($privateKeyPem);
        if ($pkey === false || !openssl_sign($dataToSign, $binarySignature, $pkey, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Cryptographic signing failed: ' . openssl_error_string());
        }

        $b64Signature = base64_encode($binarySignature);
        $finalDkimHeader = 'DKIM-Signature: ' . $dkimHeaderValue . $b64Signature . "\r\n";

        // Prepend DKIM-Signature to raw message
        return $finalDkimHeader . $rawMessage;
    }

    /**
     * Verify a signed RFC 5322 message against an RSA public key PEM.
     *
     * @param string $signedMessage The message containing a DKIM-Signature header.
     * @param string|null $publicKeyPem The RSA public key PEM. If null, extracted from private key if possible.
     * @return bool True if valid, false otherwise.
     */
    public function verify(string $signedMessage, ?string $publicKeyPem = null): bool
    {
        if ($publicKeyPem === null) {
            return false;
        }

        $parts = preg_split("/\r\n\r\n|\n\n/", $signedMessage, 2);
        $headerSection = $parts[0] ?? '';
        $bodySection = $parts[1] ?? '';

        $headers = $this->parseHeaders($headerSection);
        $dkimHeader = null;
        $otherHeaders = [];

        foreach ($headers as $h) {
            if (strtolower($h['name']) === 'dkim-signature' && $dkimHeader === null) {
                $dkimHeader = $h['value'];
            } else {
                $otherHeaders[] = $h;
            }
        }

        if ($dkimHeader === null) {
            return false;
        }

        // Parse DKIM tags
        $tags = [];
        $rawTags = explode(';', $dkimHeader);
        foreach ($rawTags as $rawTag) {
            $tagParts = explode('=', trim($rawTag), 2);
            if (count($tagParts) === 2) {
                $tags[trim($tagParts[0])] = trim($tagParts[1]);
            }
        }

        if (!isset($tags['b'], $tags['bh'], $tags['h'])) {
            return false;
        }

        // Check canonical body hash
        $canonicalBody = $this->canonicalizeBodyRelaxed($bodySection);
        $expectedBodyHash = $this->computeBodyHash($canonicalBody);
        if ($tags['bh'] !== $expectedBodyHash) {
            return false;
        }

        // Reconstruct signed headers
        $signedHeaderNames = explode(':', $tags['h']);
        $canonicalHeadersList = [];
        foreach ($signedHeaderNames as $name) {
            $lowerName = strtolower(trim($name));
            foreach ($otherHeaders as $h) {
                if (strtolower($h['name']) === $lowerName) {
                    $canonicalHeadersList[] = $this->canonicalizeHeaderRelaxed($h['name'], $h['value']) . "\r\n";
                    break;
                }
            }
        }

        // Reconstruct DKIM-Signature header up to 'b='
        $uncommittedTags = [];
        foreach ($tags as $k => $v) {
            if ($k === 'b') {
                $uncommittedTags[] = 'b=';
            } else {
                $uncommittedTags[] = $k . '=' . $v;
            }
        }
        $uncommittedValue = implode('; ', $uncommittedTags);
        $canonicalDkim = $this->canonicalizeHeaderRelaxed('DKIM-Signature', $uncommittedValue);

        $dataToVerify = implode('', $canonicalHeadersList) . $canonicalDkim;
        $binarySignature = base64_decode($tags['b'], true);
        if ($binarySignature === false) {
            return false;
        }

        $pubKey = openssl_pkey_get_public($publicKeyPem);
        if ($pubKey === false) {
            return false;
        }

        return openssl_verify($dataToVerify, $binarySignature, $pubKey, OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * Parse raw header block into an array of header records unfolding continuations.
     *
     * @param string $headerSection Raw header string.
     * @return array<int, array{name: string, value: string}>
     */
    public function parseHeaders(string $headerSection): array
    {
        $normalized = preg_replace("/\r\n|\r|\n/", "\r\n", $headerSection);
        $lines = explode("\r\n", (string) $normalized);
        $headers = [];
        $currentName = '';
        $currentValue = '';

        foreach ($lines as $line) {
            if ($line === '') {
                continue;
            }

            if (str_starts_with($line, ' ') || str_starts_with($line, "\t")) {
                // Continuation line
                $currentValue .= "\r\n" . $line;
            } else {
                if ($currentName !== '') {
                    $headers[] = [
                        'name' => $currentName,
                        'value' => $currentValue,
                    ];
                }

                $colonPos = strpos($line, ':');
                if ($colonPos !== false) {
                    $currentName = substr($line, 0, $colonPos);
                    $currentValue = substr($line, $colonPos + 1);
                } else {
                    $currentName = '';
                    $currentValue = '';
                }
            }
        }

        if ($currentName !== '') {
            $headers[] = [
                'name' => $currentName,
                'value' => $currentValue,
            ];
        }

        return $headers;
    }
}
