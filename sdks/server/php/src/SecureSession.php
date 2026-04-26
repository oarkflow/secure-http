<?php

declare(strict_types=1);

namespace Oarkflow\SecureHttp\Server;

use RuntimeException;

final class SecureSession
{
    public function __construct(
        public readonly string $sessionID,
        public readonly string $encKey,
        public readonly string $macKey,
        public readonly int $expiresAtMs,
        public readonly array $metadata = [],
    ) {
    }

    public function encrypt(string $plaintext): array
    {
        $nonce = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $this->encKey, OPENSSL_RAW_DATA, $nonce, $tag);
        if ($ciphertext === false) {
            throw new RuntimeException('encryption failed');
        }
        $ciphertextWithTag = $ciphertext . $tag;
        $timestamp = time();
        $hmac = self::computeHMAC($this->macKey, $nonce . $ciphertextWithTag . self::uint64BE($timestamp));
        return [
            'nonce' => base64_encode($nonce),
            'ciphertext' => base64_encode($ciphertextWithTag),
            'hmac' => base64_encode($hmac),
            'timestamp' => $timestamp,
        ];
    }

    public function decrypt(array $message, int $messageTTLms): string
    {
        $nonce = self::decodeBase64((string) ($message['nonce'] ?? ''), 'nonce');
        $ciphertextWithTag = self::decodeBase64((string) ($message['ciphertext'] ?? ''), 'ciphertext');
        $providedHMAC = self::decodeBase64((string) ($message['hmac'] ?? ''), 'hmac');
        $timestamp = (int) ($message['timestamp'] ?? 0);
        $drift = (int) floor(microtime(true) * 1000) - ($timestamp * 1000);
        if (abs($drift) > $messageTTLms) {
            throw new RuntimeException('message expired');
        }
        $expectedHMAC = self::computeHMAC($this->macKey, $nonce . $ciphertextWithTag . self::uint64BE($timestamp));
        if (!hash_equals($expectedHMAC, $providedHMAC)) {
            throw new RuntimeException('HMAC verification failed');
        }
        $tag = substr($ciphertextWithTag, -16);
        $ciphertext = substr($ciphertextWithTag, 0, -16);
        $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $this->encKey, OPENSSL_RAW_DATA, $nonce, $tag);
        if ($plaintext === false) {
            throw new RuntimeException('decryption failed');
        }
        return $plaintext;
    }

    public function toArray(): array
    {
        return [
            'session_id' => $this->sessionID,
            'enc_key' => base64_encode($this->encKey),
            'mac_key' => base64_encode($this->macKey),
            'expires_at_ms' => $this->expiresAtMs,
            'metadata' => $this->metadata,
        ];
    }

    public static function fromArray(array $payload): self
    {
        return new self(
            (string) ($payload['session_id'] ?? ''),
            self::decodeBase64((string) ($payload['enc_key'] ?? ''), 'enc_key'),
            self::decodeBase64((string) ($payload['mac_key'] ?? ''), 'mac_key'),
            (int) ($payload['expires_at_ms'] ?? 0),
            is_array($payload['metadata'] ?? null) ? $payload['metadata'] : [],
        );
    }

    private static function decodeBase64(string $value, string $fieldName): string
    {
        if (trim($value) === '') {
            throw new RuntimeException($fieldName . ' is required');
        }
        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            throw new RuntimeException('invalid base64 for ' . $fieldName);
        }
        return $decoded;
    }

    private static function computeHMAC(string $key, string $payload): string
    {
        return hash_hmac('sha256', $payload, $key, true);
    }

    private static function uint64BE(int $value): string
    {
        $high = ($value >> 32) & 0xffffffff;
        $low = $value & 0xffffffff;
        return pack('N2', $high, $low);
    }
}
