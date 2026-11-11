<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-logimail-engine (bin/lh-mail)
// Module:        Logihertz\LogiMail\SmtpMultiplexer
// Role:          Persistent STARTTLS/TLSv1.3 Socket Multiplexer & Dry-Run Transport
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

namespace Logihertz\LogiMail;

use RuntimeException;

/**
 * Handles persistent SMTP transport with TLSv1.2/v1.3 negotiation, connection pooling,
 * RSET state transitions, and offline dry-run simulation.
 */
class SmtpMultiplexer
{
    /** @var resource|null */
    private $socket = null;
    private int $connectionMessageCount = 0;
    private bool $connected = false;

    /** @var array<int, array{direction: string, line: string, time: float}> */
    private array $wireTranscript = [];

    /** @var array<int, array{from: string, recipients: array<string>, size: int}> */
    private array $dispatchedMessages = [];

    /**
     * @param string $host SMTP hostname or IP.
     * @param int $port SMTP port (typically 587, 465, or 25).
     * @param string $tlsMode Transport security ("starttls", "implicit", "none").
     * @param bool $verifyPeer Validate peer TLS certificates.
     * @param int $timeoutSeconds Socket connection and read timeout.
     * @param int $maxMessagesPerConnection Max messages to send before reconnecting.
     * @param string|null $username Optional SMTP auth username.
     * @param string|null $password Optional SMTP auth password.
     * @param bool $dryRun Offline mode: capture transcript without network socket.
     */
    public function __construct(
        private readonly string $host = '127.0.0.1',
        private readonly int $port = 587,
        private readonly string $tlsMode = 'starttls',
        private readonly bool $verifyPeer = true,
        private readonly int $timeoutSeconds = 30,
        private readonly int $maxMessagesPerConnection = 100,
        private readonly ?string $username = null,
        private readonly ?string $password = null,
        private readonly bool $dryRun = false,
    ) {
    }

    /**
     * Check if currently connected.
     */
    public function isConnected(): bool
    {
        return $this->connected;
    }

    /**
     * Get recorded wire protocol dialogue.
     *
     * @return array<int, array{direction: string, line: string, time: float}>
     */
    public function getWireTranscript(): array
    {
        return $this->wireTranscript;
    }

    /**
     * Get list of successfully dispatched messages.
     *
     * @return array<int, array{from: string, recipients: array<string>, size: int}>
     */
    public function getDispatchedMessages(): array
    {
        return $this->dispatchedMessages;
    }

    /**
     * Establish persistent SMTP session.
     */
    public function connect(): void
    {
        if ($this->connected) {
            return;
        }

        if ($this->dryRun) {
            $this->logWire('IN', '220 ' . $this->host . ' ESMTP LogiMail Ready');
            $this->logWire('OUT', 'EHLO [127.0.0.1]');
            $this->logWire('IN', "250-{$this->host} Hello\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250-PIPELINING\r\n250 OK");

            if ($this->tlsMode === 'starttls') {
                $this->logWire('OUT', 'STARTTLS');
                $this->logWire('IN', '220 2.0.0 Ready to start TLS (TLSv1.3 negotiated)');
                $this->logWire('OUT', 'EHLO [127.0.0.1]');
                $this->logWire('IN', "250-{$this->host} Hello TLS\r\n250-AUTH LOGIN PLAIN\r\n250 OK");
            }

            if ($this->username !== null && $this->password !== null) {
                $this->logWire('OUT', 'AUTH LOGIN');
                $this->logWire('IN', '334 VXNlcm5hbWU6');
                $this->logWire('OUT', base64_encode($this->username));
                $this->logWire('IN', '334 UGFzc3dvcmQ6');
                $this->logWire('OUT', '********');
                $this->logWire('IN', '235 2.7.0 Authentication successful');
            }

            $this->connected = true;
            $this->connectionMessageCount = 0;
            return;
        }

        $protocol = ($this->tlsMode === 'implicit') ? 'ssl://' : 'tcp://';
        $remoteSocket = $protocol . $this->host . ':' . $this->port;

        $contextOptions = [
            'ssl' => [
                'verify_peer' => $this->verifyPeer,
                'verify_peer_name' => $this->verifyPeer,
                'allow_self_signed' => !$this->verifyPeer,
                'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
            ],
        ];
        $context = stream_context_create($contextOptions);

        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_client(
            $remoteSocket,
            $errno,
            $errstr,
            (float) $this->timeoutSeconds,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($socket === false) {
            throw new RuntimeException("Failed to connect to SMTP server ({$remoteSocket}): {$errstr} ({$errno})");
        }

        $this->socket = $socket;
        stream_set_timeout($this->socket, $this->timeoutSeconds);

        $banner = $this->readResponse();
        if (!str_starts_with($banner, '220')) {
            $this->disconnect();
            throw new RuntimeException("Unexpected SMTP greeting: {$banner}");
        }

        $this->sendCommand('EHLO [127.0.0.1]');
        $ehloReply = $this->readResponse();
        if (!str_starts_with($ehloReply, '250')) {
            $this->disconnect();
            throw new RuntimeException("EHLO failed: {$ehloReply}");
        }

        if ($this->tlsMode === 'starttls') {
            $this->sendCommand('STARTTLS');
            $startTlsReply = $this->readResponse();
            if (!str_starts_with($startTlsReply, '220')) {
                $this->disconnect();
                throw new RuntimeException("STARTTLS rejected: {$startTlsReply}");
            }

            $cryptoMethod = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
            $cryptoOk = @stream_socket_enable_crypto($this->socket, true, $cryptoMethod);
            if ($cryptoOk !== true) {
                $this->disconnect();
                throw new RuntimeException('TLS cryptographic handshake failed.');
            }

            $this->sendCommand('EHLO [127.0.0.1]');
            $postTlsEhlo = $this->readResponse();
            if (!str_starts_with($postTlsEhlo, '250')) {
                $this->disconnect();
                throw new RuntimeException("Post-STARTTLS EHLO failed: {$postTlsEhlo}");
            }
        }

        if ($this->username !== null && $this->password !== null) {
            $this->authenticateLogin($this->username, $this->password);
        }

        $this->connected = true;
        $this->connectionMessageCount = 0;
    }

    /**
     * Dispatch an RFC 5322 formatted email message.
     *
     * @param string $from Sender envelope mailbox.
     * @param array<string>|string $recipients Recipient mailbox(es).
     * @param string $rfc5322Message Full RFC 5322 MIME message.
     * @return bool True if queued by server.
     */
    public function sendMessage(string $from, array|string $recipients, string $rfc5322Message): bool
    {
        $rcptList = is_array($recipients) ? $recipients : [$recipients];
        if (empty($rcptList)) {
            throw new RuntimeException('Recipient list cannot be empty.');
        }

        if (!$this->connected) {
            $this->connect();
        }

        // Check if connection reuse limit exceeded
        if ($this->connectionMessageCount >= $this->maxMessagesPerConnection) {
            $this->disconnect();
            $this->connect();
        }

        if ($this->dryRun) {
            $this->logWire('OUT', "MAIL FROM:<{$from}>");
            $this->logWire('IN', '250 2.1.0 Sender OK');

            foreach ($rcptList as $rcpt) {
                $this->logWire('OUT', "RCPT TO:<{$rcpt}>");
                $this->logWire('IN', '250 2.1.5 Recipient OK');
            }

            $this->logWire('OUT', 'DATA');
            $this->logWire('IN', '354 Enter mail, end with "." on a line by itself');
            $this->logWire('OUT', '[Payload: ' . strlen($rfc5322Message) . ' bytes]');
            $this->logWire('OUT', '.');
            $this->logWire('IN', '250 2.0.0 OK: queued as ' . bin2hex(random_bytes(6)));

            $this->connectionMessageCount++;
            $this->dispatchedMessages[] = [
                'from' => $from,
                'recipients' => $rcptList,
                'size' => strlen($rfc5322Message),
            ];
            return true;
        }

        $this->sendCommand("MAIL FROM:<{$from}>");
        $mailFromReply = $this->readResponse();
        if (!str_starts_with($mailFromReply, '250')) {
            throw new RuntimeException("MAIL FROM rejected: {$mailFromReply}");
        }

        foreach ($rcptList as $rcpt) {
            $this->sendCommand("RCPT TO:<{$rcpt}>");
            $rcptReply = $this->readResponse();
            if (!str_starts_with($rcptReply, '250')) {
                throw new RuntimeException("RCPT TO <{$rcpt}> rejected: {$rcptReply}");
            }
        }

        $this->sendCommand('DATA');
        $dataReply = $this->readResponse();
        if (!str_starts_with($dataReply, '354')) {
            throw new RuntimeException("DATA command rejected: {$dataReply}");
        }

        // Dot-stuff message lines starting with '.'
        $lines = explode("\r\n", preg_replace("/\r\n|\r|\n/", "\r\n", $rfc5322Message));
        foreach ($lines as &$line) {
            if (str_starts_with($line, '.')) {
                $line = '.' . $line;
            }
        }
        $payload = implode("\r\n", $lines) . "\r\n.\r\n";

        $this->writeRaw($payload);
        $queueReply = $this->readResponse();
        if (!str_starts_with($queueReply, '250')) {
            throw new RuntimeException("Message delivery rejected: {$queueReply}");
        }

        $this->connectionMessageCount++;
        $this->dispatchedMessages[] = [
            'from' => $from,
            'recipients' => $rcptList,
            'size' => strlen($rfc5322Message),
        ];

        return true;
    }

    /**
     * Send multiple messages reusing the socket connection with RSET in between.
     *
     * @param array<int, array{from: string, to: array<string>|string, message: string}> $batch
     * @return int Count of successfully sent messages.
     */
    public function sendBatch(array $batch): int
    {
        $sent = 0;
        $total = count($batch);

        foreach ($batch as $idx => $item) {
            $this->sendMessage($item['from'], $item['to'], $item['message']);
            $sent++;

            // If more messages remain, reset state with RSET
            if ($idx < $total - 1) {
                $this->resetState();
            }
        }

        return $sent;
    }

    /**
     * Send RSET command to reset the envelope transaction without closing the socket.
     */
    public function resetState(): void
    {
        if (!$this->connected) {
            return;
        }

        if ($this->dryRun) {
            $this->logWire('OUT', 'RSET');
            $this->logWire('IN', '250 2.0.0 Reset state OK');
            return;
        }

        $this->sendCommand('RSET');
        $reply = $this->readResponse();
        if (!str_starts_with($reply, '250')) {
            throw new RuntimeException("RSET failed: {$reply}");
        }
    }

    /**
     * Send QUIT and close the socket.
     */
    public function disconnect(): void
    {
        if (!$this->connected) {
            return;
        }

        if ($this->dryRun) {
            $this->logWire('OUT', 'QUIT');
            $this->logWire('IN', '221 2.0.0 Service closing transmission channel');
            $this->connected = false;
            return;
        }

        try {
            if (is_resource($this->socket)) {
                $this->sendCommand('QUIT');
                $this->readResponse();
            }
        } catch (\Throwable) {
            // Ignore socket errors on shutdown
        } finally {
            if (is_resource($this->socket)) {
                fclose($this->socket);
            }
            $this->socket = null;
            $this->connected = false;
        }
    }

    /**
     * Authenticate via AUTH LOGIN.
     */
    private function authenticateLogin(string $username, string $password): void
    {
        $this->sendCommand('AUTH LOGIN');
        $uPrompt = $this->readResponse();
        if (!str_starts_with($uPrompt, '334')) {
            throw new RuntimeException("AUTH LOGIN initial response failed: {$uPrompt}");
        }

        $this->sendCommand(base64_encode($username));
        $pPrompt = $this->readResponse();
        if (!str_starts_with($pPrompt, '334')) {
            throw new RuntimeException("AUTH LOGIN username rejected: {$pPrompt}");
        }

        $this->sendCommand(base64_encode($password));
        $authReply = $this->readResponse();
        if (!str_starts_with($authReply, '235')) {
            throw new RuntimeException("Authentication failed: {$authReply}");
        }
    }

    /**
     * Send line-terminated SMTP command.
     */
    private function sendCommand(string $command): void
    {
        $this->logWire('OUT', $command);
        $this->writeRaw($command . "\r\n");
    }

    /**
     * Write raw bytes to socket.
     */
    private function writeRaw(string $data): void
    {
        if (!is_resource($this->socket)) {
            throw new RuntimeException('Socket is not open.');
        }

        $written = 0;
        $len = strlen($data);
        while ($written < $len) {
            $chunk = fwrite($this->socket, substr($data, $written));
            if ($chunk === false || $chunk === 0) {
                throw new RuntimeException('Socket write error.');
            }
            $written += $chunk;
        }
    }

    /**
     * Read complete SMTP response (supporting multiline 250- replies).
     */
    private function readResponse(): string
    {
        if (!is_resource($this->socket)) {
            throw new RuntimeException('Socket is not open.');
        }

        $responseLines = [];
        while (true) {
            $line = fgets($this->socket, 4096);
            if ($line === false) {
                throw new RuntimeException('Socket read error or premature EOF from server.');
            }

            $line = rtrim($line, "\r\n");
            $responseLines[] = $line;

            // Multiline responses have hyphen at index 3 (e.g. 250-STARTTLS)
            if (strlen($line) < 4 || $line[3] === ' ') {
                break;
            }
        }

        $fullResponse = implode("\r\n", $responseLines);
        $this->logWire('IN', $fullResponse);
        return $fullResponse;
    }

    /**
     * Record wire interaction in transcript log.
     */
    private function logWire(string $direction, string $line): void
    {
        $this->wireTranscript[] = [
            'direction' => $direction,
            'line' => $line,
            'time' => microtime(true),
        ];
    }
}
