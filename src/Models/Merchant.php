<?php

namespace Aras\Payments\Models;

/**
 * Merchant Model
 * 
 * Represents a merchant account in the Aras Payments platform.
 */
class Merchant
{
    public ?int $id = null;
    public string $companyName;
    public string $email;
    public string $phone;
    public ?string $contactName = null;
    public ?string $website = null;
    public ?string $industry = null;
    public string $businessType = 'organization';
    public ?string $organizationType = null;
    public ?string $dba = null;
    public ?string $taxId = null;
    public ?string $referenceId = null;
    public ?int $settlementDelayDays = null;
    public ?string $shopperStatement = null;
    public ?string $estimatedMonthlyVolume = null;
    public ?string $estimatedAverageTicket = null;
    public ?Address $address = null;

    // Response fields (populated after creation)
    public ?string $onboardingUrl = null;
    public ?string $status = null;
    public ?string $verificationStatus = null;
    public ?string $balanceAccountId = null;
    public ?string $legalEntityId = null;
    public ?string $accountHolderId = null;

    /**
     * Create a new Merchant instance
     */
    public function __construct(array $data = [])
    {
        foreach ($data as $key => $value) {
            if (property_exists($this, $key)) {
                if ($key === 'address' && is_array($value)) {
                    $this->address = new Address($value);
                } else {
                    $this->$key = $value;
                }
            }
        }
    }

    /**
     * Convert to array for API request
     */
    public function toArray(): array
    {
        $data = [
            'companyName' => $this->companyName,
            'email' => $this->email,
            'phone' => $this->phone,
        ];

        // Add optional fields if set
        $optionalFields = [
            'contactName',
            'website',
            'industry',
            'businessType',
            'organizationType',
            'dba',
            'taxId',
            'referenceId',
            'settlementDelayDays',
            'shopperStatement',
            'estimatedMonthlyVolume',
            'estimatedAverageTicket',
        ];

        foreach ($optionalFields as $field) {
            if ($this->$field !== null) {
                $data[$field] = $this->$field;
            }
        }

        if ($this->address !== null) {
            $data['address'] = $this->address->toArray();
        }

        return $data;
    }

    /**
     * Create from API response
     */
    public static function fromResponse(array $response): self
    {
        $merchant = new self();
        
        // Map account data
        if (isset($response['data']['account'])) {
            $account = $response['data']['account'];
            $merchant->id = $account['id'] ?? null;
            $merchant->companyName = $account['companyName'] ?? '';
            $merchant->email = $account['email'] ?? '';
            $merchant->phone = $account['phone'] ?? '';
            $merchant->referenceId = $account['referenceId'] ?? null;
        }

        // Map onboarding URL
        $merchant->onboardingUrl = $response['data']['onboardingUrl'] ?? null;

        // Map Adyen data
        if (isset($response['data']['adyen'])) {
            $adyen = $response['data']['adyen'];
            $merchant->legalEntityId = $adyen['legalEntityId'] ?? null;
            $merchant->accountHolderId = $adyen['accountHolderId'] ?? null;
            $merchant->balanceAccountId = $adyen['balanceAccountId'] ?? null;
        }

        return $merchant;
    }

    /**
     * Check if merchant is approved
     */
    public function isApproved(): bool
    {
        return $this->status === 'complete';
    }

    /**
     * Check if merchant is pending verification
     */
    public function isPending(): bool
    {
        return in_array($this->verificationStatus, ['pending', 'inReview']);
    }
}
