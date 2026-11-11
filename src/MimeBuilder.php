<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-logimail-engine (bin/lh-mail)
// Module:        Logihertz\LogiMail\MimeBuilder
// Role:          RFC 5322 / RFC 2045 MIME Builder with CRLF Injection Guard
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

namespace Logihertz\LogiMail;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use InvalidArgumentException;

/**
 * Builds RFC 5322 / RFC 2045 compliant MIME messages with strict CRLF injection
 * mitigation and RFC 8058 one-click unsubscribe headers.
 */
class MimeBuilder
{
    private string $from = '';
    /** @var array<string> */
    private array $to = [];
    /** @var array<string> */
    private array $cc = [];
    private ?string $replyTo = null;
    private string $subject = '';
    private ?string $textBody = null;
    private ?string $htmlBody = null;
    private ?string $messageId = null;
    private ?DateTimeInterface $date = null;
    private ?string $listUnsubscribe = null;
    private bool $listUnsubscribeOneClick = false;

    /**
     * Determine if a header value contains CRLF injection attempts (%0a, %0d, \r, \n).
     *
     * @param string $val Value to inspect.
     * @return bool True if clean, false if injection sequences detected.
     */
    public static function isHeaderValueClean(string $val): bool
    {
        if (preg_match("/[\r\n]|%0a|%0d|%0A|%0D/i", $val) === 1) {
            return false;
        }

        return true;
    }

    /**
     * Strictly sanitize header value by removing any \r, \n, and URL-encoded newlines.
     *
     * @param string $val Raw header string.
     * @return string Sanitized single-line header value.
     */
    public static function sanitizeHeaderValue(string $val): string
    {
        // Strip URL-encoded CR / LF variations
        $cleaned = preg_replace('/%0[ad]/i', '', $val);
        // Strip literal CR and LF characters
        $cleaned = str_replace(["\r", "\n"], '', (string) $cleaned);
        // Normalize multiple spaces
        $cleaned = preg_replace('/[ \t]+/', ' ', (string) $cleaned);

        return trim((string) $cleaned);
    }

    /**
     * Set the From address with optional display name.
     */
    public function setFrom(string $email, ?string $name = null): self
    {
        $this->from = $this->formatAddress($email, $name);
        return $this;
    }

    /**
     * Add a recipient to the To list.
     */
    public function addTo(string $email, ?string $name = null): self
    {
        $this->to[] = $this->formatAddress($email, $name);
        return $this;
    }

    /**
     * Add a recipient to the Cc list.
     */
    public function addCc(string $email, ?string $name = null): self
    {
        $this->cc[] = $this->formatAddress($email, $name);
        return $this;
    }

    /**
     * Set the Reply-To address.
     */
    public function setReplyTo(string $email, ?string $name = null): self
    {
        $this->replyTo = $this->formatAddress($email, $name);
        return $this;
    }

    /**
     * Set the email subject line.
     */
    public function setSubject(string $subject): self
    {
        $this->subject = self::sanitizeHeaderValue($subject);
        return $this;
    }

    /**
     * Set the plain text body.
     */
    public function setTextBody(string $text): self
    {
        $this->textBody = $text;
        return $this;
    }

    /**
     * Set the HTML body.
     */
    public function setHtmlBody(string $html): self
    {
        $this->htmlBody = $html;
        return $this;
    }

    /**
     * Set explicit Message-ID or null to auto-generate.
     */
    public function setMessageId(?string $id): self
    {
        $this->messageId = $id !== null ? self::sanitizeHeaderValue($id) : null;
        return $this;
    }

    /**
     * Set the message Date header.
     */
    public function setDate(?DateTimeInterface $date): self
    {
        $this->date = $date;
        return $this;
    }

    /**
     * Configure RFC 8058 one-click list unsubscribe header.
     *
     * @param string $urlOrMailto Target unsubscribe URL or mailto.
     * @param bool $oneClick Whether to include List-Unsubscribe-Post: List-Unsubscribe=One-Click.
     */
    public function setListUnsubscribe(string $urlOrMailto, bool $oneClick = true): self
    {
        $this->listUnsubscribe = self::sanitizeHeaderValue($urlOrMailto);
        $this->listUnsubscribeOneClick = $oneClick;
        return $this;
    }

    /**
     * Build the complete RFC 5322 MIME message string.
     *
     * @return string Validated RFC 5322 MIME message.
     * @throws InvalidArgumentException
     */
    public function build(): string
    {
        if ($this->from === '') {
            throw new InvalidArgumentException('Sender From address is required.');
        }

        if (empty($this->to)) {
            throw new InvalidArgumentException('At least one To recipient is required.');
        }

        $dateHeader = ($this->date ?? new DateTimeImmutable('now', new DateTimeZone('UTC')))
            ->format(DateTimeInterface::RFC2822);

        $domain = 'localhost';
        if (preg_match('/@([a-zA-Z0-9.-]+)/', $this->from, $matches)) {
            $domain = $matches[1];
        }

        $messageIdHeader = $this->messageId ?? sprintf('<%s.%s@%s>', bin2hex(random_bytes(8)), (string) time(), $domain);

        $headers = [];
        $headers[] = 'From: ' . $this->from;
        $headers[] = 'To: ' . implode(', ', $this->to);

        if (!empty($this->cc)) {
            $headers[] = 'Cc: ' . implode(', ', $this->cc);
        }

        if ($this->replyTo !== null) {
            $headers[] = 'Reply-To: ' . $this->replyTo;
        }

        $headers[] = 'Subject: ' . $this->subject;
        $headers[] = 'Date: ' . $dateHeader;
        $headers[] = 'Message-ID: ' . $messageIdHeader;

        if ($this->listUnsubscribe !== null) {
            $headers[] = 'List-Unsubscribe: <' . $this->listUnsubscribe . '>';
            if ($this->listUnsubscribeOneClick) {
                $headers[] = 'List-Unsubscribe-Post: List-Unsubscribe=One-Click';
            }
        }

        $headers[] = 'MIME-Version: 1.0';

        $body = '';

        if ($this->textBody !== null && $this->htmlBody !== null) {
            // Multipart alternative
            $boundary = '----=_Part_' . bin2hex(random_bytes(16));
            $headers[] = 'Content-Type: multipart/alternative; boundary="' . $boundary . '"';

            $bodyParts = [];
            $bodyParts[] = '--' . $boundary;
            $bodyParts[] = "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n";
            $bodyParts[] = $this->encodeQuotedPrintable($this->textBody);

            $bodyParts[] = '--' . $boundary;
            $bodyParts[] = "Content-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n";
            $bodyParts[] = $this->encodeQuotedPrintable($this->htmlBody);

            $bodyParts[] = '--' . $boundary . '--';

            $body = implode("\r\n", $bodyParts);
        } elseif ($this->htmlBody !== null) {
            $headers[] = 'Content-Type: text/html; charset=UTF-8';
            $headers[] = 'Content-Transfer-Encoding: quoted-printable';
            $body = $this->encodeQuotedPrintable($this->htmlBody);
        } else {
            // Default to plain text
            $text = $this->textBody ?? '';
            $headers[] = 'Content-Type: text/plain; charset=UTF-8';
            $headers[] = 'Content-Transfer-Encoding: quoted-printable';
            $body = $this->encodeQuotedPrintable($text);
        }

        return implode("\r\n", $headers) . "\r\n\r\n" . $body;
    }

    /**
     * Format email address with optional name and sanitize against CRLF injection.
     */
    private function formatAddress(string $email, ?string $name = null): string
    {
        $sanitizedEmail = self::sanitizeHeaderValue($email);
        if ($name !== null && $name !== '') {
            $sanitizedName = self::sanitizeHeaderValue($name);
            return sprintf('"%s" <%s>', str_replace('"', '\"', $sanitizedName), $sanitizedEmail);
        }

        return $sanitizedEmail;
    }

    /**
     * Encode body content as quoted-printable with standardized CRLF line endings.
     */
    private function encodeQuotedPrintable(string $input): string
    {
        $normalized = preg_replace("/\r\n|\r|\n/", "\r\n", $input);
        return quoted_printable_encode((string) $normalized);
    }
}
