<?php

namespace VendorShield\Shield\Access;

use Illuminate\Http\Request;
use VendorShield\Shield\Contracts\AccessControlDeciderContract;
use VendorShield\Shield\Support\AccessDecision;

class NullAccessControlDecider implements AccessControlDeciderContract
{
    public function decide(Request $request, array $context = []): ?AccessDecision
    {
        return null;
    }
}
