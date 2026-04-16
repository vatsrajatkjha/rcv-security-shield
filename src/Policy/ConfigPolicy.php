<?php

namespace VendorShield\Shield\Policy;

use VendorShield\Shield\Contracts\PolicyContract;

class ConfigPolicy implements PolicyContract
{
    public function __construct(
        protected string $guard,
        protected string $condition,
        protected string $action,
        protected int $priority = 0,
    ) {}

    public function evaluate(mixed $context): PolicyDecision
    {
        // Simple condition matching for config-defined policies
        if (empty($this->condition)) {
            return $this->toDecision();
        }

        // Pattern-based condition: "field:pattern"
        if (is_array($context) && str_contains($this->condition, ':')) {
            [$field, $pattern] = explode(':', $this->condition, 2);

            $value = data_get($context, $field, '');

            if (is_string($value) && preg_match("/{$pattern}/i", $value)) {
                return $this->toDecision();
            }

            return PolicyDecision::allow('Condition not matched');
        }

        return PolicyDecision::allow('Condition not applicable');
    }

    public function guard(): string
    {
        return $this->guard;
    }

    public function priority(): int
    {
        return $this->priority;
    }

    protected function toDecision(): PolicyDecision
    {
        return match ($this->action) {
            'block', 'deny' => PolicyDecision::deny("Policy rule: {$this->condition}"),
            'monitor' => PolicyDecision::monitor("Policy rule: {$this->condition}"),
            'escalate' => PolicyDecision::escalate("Policy rule: {$this->condition}"),
            default => PolicyDecision::allow(),
        };
    }

    public function toArray(): array
    {
        return [
            'guard' => $this->guard,
            'condition' => $this->condition,
            'action' => $this->action,
            'priority' => $this->priority,
        ];
    }
}
