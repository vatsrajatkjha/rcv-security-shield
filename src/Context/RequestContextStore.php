<?php

namespace VendorShield\Shield\Context;

class RequestContextStore
{
    protected array $context = [];

    public function set(array $context): void
    {
        $this->context = $context;
    }

    public function merge(array $context): void
    {
        $this->context = array_replace_recursive($this->context, $context);
    }

    public function all(): array
    {
        return $this->context;
    }

    public function clear(): void
    {
        $this->context = [];
    }
}
