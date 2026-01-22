<?php

namespace PAYwiz\Payments;

use PAYwiz\Payments\Exceptions\ApiException;

/**
 * Webhook Handler
 * 
 * Handles webhook signature verification and payload parsing.
 */
class WebhookHandler
{
    private string $webhookSecret;
    private int $tolerance;

    /**
     * Create a new WebhookHandler instance
     *
     * @param string $webhookSecret Your webhook signing secret
     * @param int $tolerance Maximum age of webhook in seconds (default: 300 = 5 minutes)
     */
    public function __construct(string $webhookSecret, int $tolerance = 300)
    {
        $this->webhookSecret = $webhookSecret;
        $this->tolerance = $tolerance;
    }

    /**
     * Verify webhook signature and return parsed payload
     *
     * @param string $payload Raw request body
     * @param string $signature Value of X-Webhook-Signature header
     * @param int $timestamp Value of X-Webhook-Timestamp header
     * @return array Parsed webhook payload
     * @throws ApiException If signature is invalid or timestamp is outside tolerance
     * 
     * @example
     * $handler = new WebhookHandler('your-webhook-secret');
     * 
     * $payload = file_get_contents('php://input');
     * $signature = $_SERVER['HTTP_X_WEBHOOK_SIGNATURE'] ?? '';
     * $timestamp = (int) ($_SERVER['HTTP_X_WEBHOOK_TIMESTAMP'] ?? 0);
     * 
     * try {
     *     $event = $handler->verifyAndParse($payload, $signature, $timestamp);
     *     
     *     switch ($event['type']) {
     *         case 'account.created':
     *             // Handle account created
     *             break;
     *         case 'account.approved':
     *             // Handle account approved
     *             break;
     *     }
     * } catch (ApiException $e) {
     *     http_response_code(401);
     *     echo 'Invalid signature';
     * }
     */
    public function verifyAndParse(string $payload, string $signature, int $timestamp): array
    {
        $this->verifySignature($payload, $signature, $timestamp);
        
        $decoded = json_decode($payload, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new ApiException('Invalid webhook payload: ' . json_last_error_msg(), 400);
        }
        
        return $decoded;
    }

    /**
     * Verify webhook signature
     *
     * @param string $payload Raw request body
     * @param string $signature Value of X-Webhook-Signature header
     * @param int $timestamp Value of X-Webhook-Timestamp header
     * @return bool True if signature is valid
     * @throws ApiException If signature is invalid or timestamp is outside tolerance
     */
    public function verifySignature(string $payload, string $signature, int $timestamp): bool
    {
        // Check timestamp is within tolerance
        $now = time();
        if (abs($now - $timestamp) > $this->tolerance) {
            throw new ApiException(
                'Webhook timestamp outside tolerance window',
                401,
                ['timestamp' => 'Request is too old or from the future']
            );
        }

        // Calculate expected signature
        $signedPayload = "{$timestamp}.{$payload}";
        $expectedSignature = hash_hmac('sha256', $signedPayload, $this->webhookSecret);

        // Extract actual signature (remove 'v1=' prefix)
        $actualSignature = $this->extractSignature($signature);

        // Use timing-safe comparison
        if (!hash_equals($expectedSignature, $actualSignature)) {
            throw new ApiException(
                'Invalid webhook signature',
                401,
                ['signature' => 'Signature verification failed']
            );
        }

        return true;
    }

    /**
     * Extract signature from header value
     *
     * @param string $header The X-Webhook-Signature header value
     * @return string The extracted signature
     */
    private function extractSignature(string $header): string
    {
        // Handle format: v1=<signature>
        if (str_starts_with($header, 'v1=')) {
            return substr($header, 3);
        }
        
        return $header;
    }

    /**
     * Create handler from request (convenience method)
     *
     * @param string $webhookSecret Your webhook signing secret
     * @return array Parsed and verified webhook payload
     * @throws ApiException If verification fails
     * 
     * @example
     * try {
     *     $event = WebhookHandler::handleRequest('your-webhook-secret');
     *     // Process $event
     * } catch (ApiException $e) {
     *     http_response_code(401);
     *     exit;
     * }
     */
    public static function handleRequest(string $webhookSecret): array
    {
        $handler = new self($webhookSecret);
        
        $payload = file_get_contents('php://input');
        $signature = $_SERVER['HTTP_X_WEBHOOK_SIGNATURE'] ?? '';
        $timestamp = (int) ($_SERVER['HTTP_X_WEBHOOK_TIMESTAMP'] ?? 0);
        
        return $handler->verifyAndParse($payload, $signature, $timestamp);
    }

    /**
     * Get the event type from a webhook payload
     *
     * @param array $payload Parsed webhook payload
     * @return string|null The event type
     */
    public static function getEventType(array $payload): ?string
    {
        return $payload['type'] ?? null;
    }

    /**
     * Get the event data from a webhook payload
     *
     * @param array $payload Parsed webhook payload
     * @return array|null The event data
     */
    public static function getEventData(array $payload): ?array
    {
        return $payload['data'] ?? null;
    }

    /**
     * Check if webhook is from live mode
     *
     * @param array $payload Parsed webhook payload
     * @return bool True if live mode
     */
    public static function isLiveMode(array $payload): bool
    {
        return $payload['livemode'] ?? false;
    }
}
