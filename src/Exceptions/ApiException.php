<?php

namespace Aras\Payments\Exceptions;

use Exception;

class ApiException extends Exception
{
    protected array $errors;
    protected ?array $responseBody;

    public function __construct(
        string $message,
        int $code = 0,
        array $errors = [],
        ?array $responseBody = null
    ) {
        parent::__construct($message, $code);
        $this->errors = $errors;
        $this->responseBody = $responseBody;
    }

    /**
     * Get validation errors
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    /**
     * Get full response body
     */
    public function getResponseBody(): ?array
    {
        return $this->responseBody;
    }

    /**
     * Check if this is a validation error
     */
    public function isValidationError(): bool
    {
        return $this->code === 400 && !empty($this->errors);
    }

    /**
     * Check if this is a not found error
     */
    public function isNotFound(): bool
    {
        return $this->code === 404;
    }

    /**
     * Check if this is an authentication error
     */
    public function isAuthError(): bool
    {
        return $this->code === 401 || $this->code === 403;
    }
}
