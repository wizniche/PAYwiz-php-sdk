# PAYwiz Payments PHP SDK

Official PHP SDK for the Payments Platform. Easily integrate merchant onboarding, transaction management, and refund processing into your PHP application.

## Installation

```bash
composer require paywiz/payments-sdk
```

## Quick Start

```php
<?php
require 'vendor/autoload.php';

use PAYwiz\Payments\PAYwizClient;
use PAYwiz\Payments\Exceptions\ApiException;

// Initialize the client
$client = new PAYwizClient('your-api-key', 'sandbox');
```

## Merchant Onboarding

### Create a New Merchant

```php
try {
    $result = $client->createMerchant([
        'companyName' => 'Coffee House LLC',
        'email' => 'owner@coffeehouse.com',
        'phone' => '+14155551234',
        'contactName' => 'John Smith',
        'website' => 'https://coffeehouse.com',
        'industry' => 'restaurant',
        'businessType' => 'organization',
        'organizationType' => 'privateCompany',
        'taxId' => '12-3456789',
        'referenceId' => 'MY_INTERNAL_ID_123',
        'settlementDelayDays' => 1,
        'themeId' => 'YOUR_THEME_ID',
        'redirectUrl' => 'https://yoursite.com/complete',
        'address' => [
            'street' => '123 Main St',
            'city' => 'San Francisco',
            'state' => 'CA',
            'postalCode' => '94107',
            'country' => 'US'
        ]
    ]);

    // Redirect merchant to complete KYC
    $onboardingUrl = $result['data']['onboardingUrl'];
    $accountId = $result['data']['account']['id'];
    
    echo "Redirect merchant to: $onboardingUrl\n";
    echo "Store account ID for later: $accountId\n";

} catch (ApiException $e) {
    echo "Error: " . $e->getMessage() . "\n";
    
    if ($e->isValidationError()) {
        print_r($e->getErrors());
    }
}
```

### Check Merchant Status

```php
$status = $client->getMerchantStatus($accountId);

echo "Status: " . $status['data']['paymentSetup']['status'] . "\n";
echo "Verification: " . $status['data']['paymentSetup']['verificationStatus'] . "\n";

// Quick check
if ($client->isMerchantApproved($accountId)) {
    echo "Merchant is approved and can process payments!";
}
```

### Regenerate Onboarding URL

URLs expire after 1 hour. Regenerate if needed:

```php
// Basic usage
$result = $client->regenerateOnboardingUrl('AH00000000000000000000001');
$newUrl = $result['data']['onboardingUrl'];

// With redirect URL and theme
$result = $client->regenerateOnboardingUrl(
    'AH00000000000000000000001',
    'https://yoursite.com/complete',
    'YOUR_THEME_ID'
);
```

## Transactions

### Get Transactions

```php
// Get all transactions
$transactions = $client->getTransactions();

// With filters
$transactions = $client->getTransactions([
    'startDate' => '2024-01-01',
    'endDate' => '2024-01-31',
    'status' => 'captured',
    'page' => 1,
    'limit' => 50
]);

// Get by PSP reference
$transaction = $client->getTransactionByPspReference('XYZABC123456');
```

## Refunds

### Process a Refund

```php
try {
    // Full refund
    $result = $client->processRefund('MXNS422RC226C665');
    
    // Partial refund ($15.00 = 1500 cents)
    $result = $client->processRefund('MXNS422RC226C665', 1500);
    
    // With reason
    $result = $client->processRefund('MXNS422RC226C665', 1500, 'Customer request');
    
    echo "Refund status: " . $result['data']['status'] . "\n";

} catch (ApiException $e) {
    if ($e->isNotFound()) {
        echo "Transaction not found\n";
    } else {
        echo "Refund failed: " . $e->getMessage() . "\n";
    }
}
```

## Using Models

The SDK includes model classes for type-safe operations:

```php
use PAYwiz\Payments\Models\Merchant;
use PAYwiz\Payments\Models\Transaction;

// Create merchant with model
$merchant = new Merchant([
    'companyName' => 'Coffee House LLC',
    'email' => 'owner@coffeehouse.com',
    'phone' => '+14155551234',
    'address' => [
        'street' => '123 Main St',
        'city' => 'San Francisco',
        'state' => 'CA',
        'postalCode' => '94107',
        'country' => 'US'
    ]
]);

$result = $client->createMerchant($merchant->toArray());
$createdMerchant = Merchant::fromResponse($result);

echo "Account ID: " . $createdMerchant->id . "\n";
echo "Onboarding URL: " . $createdMerchant->onboardingUrl . "\n";

// Parse transactions
$response = $client->getTransactions();
$transactions = Transaction::fromResponseCollection($response);

foreach ($transactions as $transaction) {
    echo "{$transaction->pspReference}: {$transaction->amount} {$transaction->currency}\n";
    
    if ($transaction->canRefund()) {
        // Process refund...
    }
}
```

## Error Handling

```php
use PAYwiz\Payments\Exceptions\ApiException;

try {
    $result = $client->createMerchant($data);
} catch (ApiException $e) {
    // Get error message
    echo $e->getMessage();
    
    // Get HTTP status code
    echo $e->getCode(); // 400, 401, 404, 500, etc.
    
    // Get validation errors
    if ($e->isValidationError()) {
        foreach ($e->getErrors() as $error) {
            echo $error['field'] . ': ' . $error['message'] . "\n";
        }
    }
    
    // Check error types
    if ($e->isAuthError()) {
        echo "Invalid API key or unauthorized";
    }
    
    if ($e->isNotFound()) {
        echo "Resource not found";
    }
    
    // Get full response body
    print_r($e->getResponseBody());
}
```

## Configuration

### Custom Base URL

```php
// For self-hosted or custom environments
$client = new PAYwizClient(
    'your-api-key',
    'production',
    'https://custom.yourdomain.com'
);
```

### Custom Timeout

```php
$client = new PAYwizClient('your-api-key', 'production');
$client->setTimeout(60); // 60 seconds
```

## Webhook Handling

Securely handle webhooks with signature verification:

```php
use PAYwiz\Payments\WebhookHandler;
use PAYwiz\Payments\Exceptions\ApiException;

// Quick method - handles everything
try {
    $event = WebhookHandler::handleRequest('your-webhook-secret');
    
    switch ($event['type']) {
        case 'account.created':
            $account = $event['data']['account'];
            echo "New account: " . $account['companyName'];
            break;
            
        case 'account.approved':
            $account = $event['data']['account'];
            // Enable features for merchant
            break;
            
        case 'account.updated':
            // Handle update
            break;
    }
    
    http_response_code(200);
    echo 'OK';
    
} catch (ApiException $e) {
    http_response_code(401);
    echo 'Invalid signature';
}
```

### Manual Verification

```php
$handler = new WebhookHandler('your-webhook-secret');

$payload = file_get_contents('php://input');
$signature = $_SERVER['HTTP_X_WEBHOOK_SIGNATURE'] ?? '';
$timestamp = (int) ($_SERVER['HTTP_X_WEBHOOK_TIMESTAMP'] ?? 0);

try {
    $event = $handler->verifyAndParse($payload, $signature, $timestamp);
    // Process event...
} catch (ApiException $e) {
    // Invalid signature or expired timestamp
}
```

### Webhook Events

| Event | Description |
|-------|-------------|
| `account.created` | New merchant account created |
| `account.updated` | Merchant account information updated |
| `account.approved` | Merchant account approved and active |

## Industries

Valid industry values for merchant onboarding:

- `retail`
- `restaurant`
- `ecommerce`
- `services`
- `technology`
- `grocery`
- `accommodation`
- `transportation`
- `healthcare`
- `education`
- `entertainment`

## Organization Types

Valid organization types:

- `privateCompany`
- `publicCompany`
- `soleProprietorship`
- `nonProfit`
- `partnershipIncorporated`
- `associationIncorporated`
- `governmentalOrganization`
- `listedPublicCompany`

## Support

- Email: support@wizniche.com

## License

MIT License
