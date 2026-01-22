<?php

namespace PAYwiz\Payments;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use PAYwiz\Payments\Exceptions\ApiException;

/**
 * PAYwiz Payments SDK Client
 * 
 * Main client for interacting with the PAYwiz Payments Platform API.
 * Provides methods for merchant onboarding, transactions, and refunds.
 */
class PAYwizClient
{
    private Client $httpClient;
    private string $apiKey;
    private string $baseUrl;

    /**
     * Create a new PAYwiz client instance
     *
     * @param string $apiKey Your API key from the PAYwiz platform
     * @param string $environment 'sandbox' or 'production'
     * @param string|null $baseUrl Custom base URL (optional)
     */
    public function __construct(
        string $apiKey,
        string $environment = 'sandbox',
        ?string $baseUrl = null
    ) {
        $this->apiKey = $apiKey;
        
        if ($baseUrl) {
            $this->baseUrl = rtrim($baseUrl, '/');
        } else {
            $this->baseUrl = $environment === 'production'
                ? 'https://api-pay.araspayment.com'
                : 'https://api-develop.araspayment.com';
        }

        $this->httpClient = new Client([
            'base_uri' => $this->baseUrl,
            'timeout' => 30,
            'headers' => [
                'X-API-Key' => $this->apiKey,
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ],
        ]);
    }

    // =========================================================================
    // ONBOARDING
    // =========================================================================

    /**
     * Onboard a new merchant account
     *
     * Creates a new merchant with all necessary Adyen entities:
     * - Legal Entity
     * - Account Holder
     * - Balance Account
     * - Business Line
     * - Store
     * - Hosted Onboarding URL
     *
     * @param array $merchantData Merchant information
     * @return array Response containing accountId, onboardingUrl, etc.
     * @throws ApiException
     * 
     * @example
     * $result = $client->createMerchant([
     *     'companyName' => 'Coffee House LLC',
     *     'email' => 'owner@coffeehouse.com',
     *     'phone' => '+14155551234',
     *     'contactName' => 'John Smith',
     *     'website' => 'https://coffeehouse.com',
     *     'industry' => 'restaurant',
     *     'businessType' => 'organization',
     *     'organizationType' => 'privateCompany',
     *     'taxId' => '12-3456789',
     *     'referenceId' => 'YOUR_INTERNAL_ID',
     *     'themeId' => 'YOUR_THEME_ID',
     *     'redirectUrl' => 'https://yoursite.com/complete',
     *     'address' => [
     *         'street' => '123 Main St',
     *         'city' => 'San Francisco',
     *         'state' => 'CA',
     *         'postalCode' => '94107',
     *         'country' => 'US'
     *     ]
     * ]);
     */
    public function createMerchant(array $merchantData): array
    {
        return $this->post('/api/v1/onboarding/accounts', $merchantData);
    }

    /**
     * Get merchant onboarding status
     *
     * @param int $accountId The merchant's account ID
     * @return array Status information including verification status
     * @throws ApiException
     * 
     * @example
     * $status = $client->getMerchantStatus(123);
     * if ($status['data']['paymentSetup']['status'] === 'complete') {
     *     echo "Merchant is approved!";
     * }
     */
    public function getMerchantStatus(int $accountId): array
    {
        return $this->get("/api/v1/onboarding/accounts/{$accountId}/status");
    }

    /**
     * Regenerate onboarding URL
     *
     * Use this when the original onboarding URL has expired (URLs are valid for 1 hour).
     *
     * @param string $accountHolderId The merchant's account holder ID (e.g., AH00000000000000000000001)
     * @param string|null $redirectUrl URL to redirect after onboarding completion
     * @param string|null $themeId Custom theme ID for the onboarding page
     * @return array Contains new onboardingUrl
     * @throws ApiException
     * 
     * @example
     * $result = $client->regenerateOnboardingUrl(
     *     'AH00000000000000000000001',
     *     'https://yoursite.com/complete',
     *     'YOUR_THEME_ID'
     * );
     */
    public function regenerateOnboardingUrl(
        string $accountHolderId,
        ?string $redirectUrl = null,
        ?string $themeId = null
    ): array {
        $data = [];
        
        if ($redirectUrl !== null) {
            $data['redirectUrl'] = $redirectUrl;
        }
        
        if ($themeId !== null) {
            $data['themeId'] = $themeId;
        }
        
        return $this->post("/api/v1/onboarding/accounts/{$accountHolderId}/onboarding-url", $data);
    }

    /**
     * Check if merchant is fully verified and can process payments
     *
     * @param int $accountId The merchant's account ID
     * @return bool True if merchant is approved and can process payments
     * @throws ApiException
     */
    public function isMerchantApproved(int $accountId): bool
    {
        $status = $this->getMerchantStatus($accountId);
        return ($status['data']['paymentSetup']['status'] ?? '') === 'complete';
    }

    // =========================================================================
    // TRANSACTIONS
    // =========================================================================

    /**
     * Get transactions
     *
     * Retrieve transaction history with optional filters.
     *
     * @param array $filters Optional filters
     * @return array List of transactions
     * @throws ApiException
     * 
     * @example
     * // Get all transactions
     * $transactions = $client->getTransactions();
     * 
     * // With filters
     * $transactions = $client->getTransactions([
     *     'startDate' => '2024-01-01',
     *     'endDate' => '2024-01-31',
     *     'status' => 'captured',
     *     'page' => 1,
     *     'limit' => 50
     * ]);
     */
    public function getTransactions(array $filters = []): array
    {
        return $this->get('/api/v1/transactions', $filters);
    }

    /**
     * Get transaction by PSP reference
     *
     * @param string $pspReference The Adyen PSP reference
     * @return array|null Transaction data or null if not found
     * @throws ApiException
     */
    public function getTransactionByPspReference(string $pspReference): ?array
    {
        $transactions = $this->getTransactions(['pspReference' => $pspReference]);
        return $transactions['data'][0] ?? null;
    }

    // =========================================================================
    // REFUNDS
    // =========================================================================

    /**
     * Process a refund
     *
     * @param string $pspReference The original transaction PSP reference
     * @param float $amount Amount to refund (in dollars, e.g., 10.50)
     * @return array Refund result
     * @throws ApiException
     * 
     * @example
     * // Full refund
     * $result = $client->processRefund('XYZABC123456', 100.00);
     * 
     * // Partial refund
     * $result = $client->processRefund('XYZABC123456', 25.50);
     */
    public function processRefund(string $pspReference, float $amount): array
    {
        if ($amount <= 0) {
            throw new ApiException('Refund amount must be greater than 0', 400, [
                'amount' => 'Amount must be a positive number'
            ]);
        }

        return $this->post('/api/v1/refunds/process', [
            'pspReference' => $pspReference,
            'amount' => round($amount, 2),
        ]);
    }

    // =========================================================================
    // HTTP METHODS
    // =========================================================================

    /**
     * Make a GET request
     */
    private function get(string $endpoint, array $query = []): array
    {
        try {
            $response = $this->httpClient->get($endpoint, [
                'query' => $query,
            ]);
            return json_decode($response->getBody()->getContents(), true);
        } catch (RequestException $e) {
            throw $this->handleException($e);
        }
    }

    /**
     * Make a POST request
     */
    private function post(string $endpoint, array $data = []): array
    {
        try {
            $response = $this->httpClient->post($endpoint, [
                'json' => $data,
            ]);
            return json_decode($response->getBody()->getContents(), true);
        } catch (RequestException $e) {
            throw $this->handleException($e);
        }
    }

    /**
     * Handle HTTP exceptions
     */
    private function handleException(RequestException $e): ApiException
    {
        $response = $e->getResponse();
        $statusCode = $response?->getStatusCode() ?? 500;
        $body = null;
        $message = $e->getMessage();
        $errors = [];

        if ($response) {
            $body = json_decode($response->getBody()->getContents(), true);
            $message = $body['message'] ?? $message;
            $errors = $body['errors'] ?? [];
        }

        return new ApiException($message, $statusCode, $errors, $body);
    }

    // =========================================================================
    // UTILITY METHODS
    // =========================================================================

    /**
     * Get the base URL being used
     */
    public function getBaseUrl(): string
    {
        return $this->baseUrl;
    }

    /**
     * Set a custom timeout
     */
    public function setTimeout(int $seconds): void
    {
        $this->httpClient = new Client([
            'base_uri' => $this->baseUrl,
            'timeout' => $seconds,
            'headers' => [
                'X-API-Key' => $this->apiKey,
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ],
        ]);
    }
}
