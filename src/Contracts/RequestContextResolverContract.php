<?php

namespace VendorShield\Shield\Contracts;

use Illuminate\Http\Request;

interface RequestContextResolverContract
{
    public function resolve(Request $request): array;
}
