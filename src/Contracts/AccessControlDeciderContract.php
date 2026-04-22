<?php

namespace VendorShield\Shield\Contracts;

use Illuminate\Http\Request;
use VendorShield\Shield\Support\AccessDecision;

interface AccessControlDeciderContract
{
    public function decide(Request $request, array $context = []): ?AccessDecision;
}
