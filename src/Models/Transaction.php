<?php

namespace Aras\Payments\Models;

/**
 * Transaction Model
 */
class Transaction
{
    public ?int $id = null;
    public ?string $pspReference = null;
    public ?string $merchantReference = null;
    public ?float $amount = null;
    public ?string $currency = null;
    public ?string $status = null;
    public ?string $paymentMethod = null;
    public ?string $cardBrand = null;
    public ?string $cardSummary = null;
    public ?string $shopperEmail = null;
    public ?string $shopperReference = null;
    public ?int $accountId = null;
    public ?string $accountName = null;
    public ?\DateTime $createdAt = null;
    public ?\DateTime $capturedAt = null;

    public function __construct(array $data = [])
    {
        foreach ($data as $key => $value) {
            if (property_exists($this, $key)) {
                if (in_array($key, ['createdAt', 'capturedAt']) && $value) {
                    $this->$key = new \DateTime($value);
                } else {
                    $this->$key = $value;
                }
            }
        }
    }

    /**
     * Create from API response
     */
    public static function fromResponse(array $data): self
    {
        return new self([
            'id' => $data['id'] ?? null,
            'pspReference' => $data['pspReference'] ?? $data['psp_reference'] ?? null,
            'merchantReference' => $data['merchantReference'] ?? $data['merchant_reference'] ?? null,
            'amount' => isset($data['amountValue']) ? floatval($data['amountValue']) : null,
            'currency' => $data['amountCurrency'] ?? $data['currency'] ?? null,
            'status' => $data['status'] ?? null,
            'paymentMethod' => $data['paymentMethod'] ?? $data['payment_method'] ?? null,
            'cardBrand' => $data['cardBrand'] ?? null,
            'cardSummary' => $data['cardSummary'] ?? null,
            'shopperEmail' => $data['shopperEmail'] ?? null,
            'shopperReference' => $data['shopperReference'] ?? null,
            'accountId' => $data['accountId'] ?? $data['account_id'] ?? null,
            'accountName' => $data['accountName'] ?? null,
            'createdAt' => $data['createdAt'] ?? $data['created_at'] ?? null,
            'capturedAt' => $data['capturedAt'] ?? null,
        ]);
    }

    /**
     * Create collection from API response
     */
    public static function fromResponseCollection(array $response): array
    {
        $transactions = [];
        $data = $response['data'] ?? $response;
        
        foreach ($data as $item) {
            $transactions[] = self::fromResponse($item);
        }
        
        return $transactions;
    }

    /**
     * Check if transaction is captured
     */
    public function isCaptured(): bool
    {
        return $this->status === 'captured';
    }

    /**
     * Check if transaction can be refunded
     */
    public function canRefund(): bool
    {
        return $this->isCaptured() && $this->amount > 0;
    }
}
