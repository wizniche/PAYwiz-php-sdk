<?php

namespace Aras\Payments\Models;

/**
 * Address Model
 */
class Address
{
    public string $street;
    public ?string $street2 = null;
    public string $city;
    public string $state;
    public string $postalCode;
    public string $country = 'US';

    public function __construct(array $data = [])
    {
        foreach ($data as $key => $value) {
            if (property_exists($this, $key)) {
                $this->$key = $value;
            }
        }
    }

    public function toArray(): array
    {
        $data = [
            'street' => $this->street,
            'city' => $this->city,
            'state' => $this->state,
            'postalCode' => $this->postalCode,
            'country' => $this->country,
        ];

        if ($this->street2 !== null) {
            $data['street2'] = $this->street2;
        }

        return $data;
    }
}
