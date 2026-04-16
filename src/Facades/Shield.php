<?php

namespace VendorShield\Shield\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static bool enabled()
 * @method static string mode()
 * @method static \VendorShield\Shield\Contracts\GuardContract|null guard(string $name)
 * @method static array guards()
 * @method static \VendorShield\Shield\Policy\PolicyEngine policy()
 * @method static \VendorShield\Shield\Tenant\TenantContext tenant(?string $tenantId = null)
 * @method static \VendorShield\Shield\Contracts\IntelligenceClientContract intelligence()
 * @method static \VendorShield\Shield\Audit\AuditLogger audit()
 * @method static \VendorShield\Shield\Config\ConfigResolver config()
 * @method static array health()
 *
 * @see \VendorShield\Shield\ShieldManager
 */
class Shield extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'shield';
    }
}
