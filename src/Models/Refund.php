<?php

namespace Aras\Payments\Models;

/**
 * Refund Model
 */
class Refund
{
    public ?string $pspReference = null;
    public ?string $originalPspReference = null;
    public ?float $amount = null;
    public ?string $currency = null;
    public ?string $status = null;
    public ?string $reason = null;
    public ?\DateTime $createdAt = null;

    public function __construct(array $data = [])
    {
        foreach ($data as $key => $value) {
            if (property_exists($this, $key)) {
                if ($key === 'createdAt' && $value) {
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
    public static function fromResponse(array $response): self
    {
        $data = $response['data'] ?? $response;
        
        return new self([
            'pspReference' => $data['pspReference'] ?? null,
            'originalPspReference' => $data['originalPspReference'] ?? null,
            'amount' => isset($data['amount']) ? floatval($data['amount']) : null,
            'currency' => $data['currency'] ?? 'USD',
            'status' => $data['status'] ?? null,
            'reason' => $data['reason'] ?? null,
            'createdAt' => $data['createdAt'] ?? null,
        ]);
    }

    /**
     * Check if refund was successful
     */
    public function isSuccessful(): bool
    {
        return in_array($this->status, ['received', 'completed', 'success']);
    }
}
