<?php

namespace VendorShield\Shield\Context;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use VendorShield\Shield\Contracts\RequestContextResolverContract;

class DefaultRequestContextResolver implements RequestContextResolverContract
{
    public function __construct(
        protected AuthFactory $auth,
    ) {}

    public function resolve(Request $request): array
    {
        $requestId = (string) ($request->attributes->get('shield_request_id') ?? Str::uuid());
        $request->attributes->set('shield_request_id', $requestId);

        return [
            'request_id' => $requestId,
            'occurred_at' => now()->toIso8601String(),
            'request' => [
                'ip_address' => $request->ip(),
                'forwarded_for' => array_values(array_filter(array_map('trim', explode(',', (string) $request->headers->get('X-Forwarded-For', ''))))),
                'method' => $request->method(),
                'scheme' => $request->getScheme(),
                'host' => $request->getHost(),
                'path' => $request->path(),
                'full_url' => $request->fullUrl(),
                'route_name' => optional($request->route())->getName(),
                'user_agent' => Str::limit((string) $request->userAgent(), 1024, ''),
                'referer' => $request->headers->get('referer'),
                'session_id' => $request->hasSession() ? $request->session()->getId() : null,
                'input_keys' => array_values(array_keys(Arr::except($request->all(), ['password', 'password_confirmation', 'current_password', 'token', '_token']))),
                'file_keys' => array_values(array_keys($request->allFiles())),
            ],
            'actor' => $this->resolveActor(),
        ];
    }

    protected function resolveActor(): array
    {
        foreach (array_keys((array) config('auth.guards', [])) as $guard) {
            try {
                $user = $this->auth->guard($guard)->user();
            } catch (\Throwable) {
                $user = null;
            }

            if ($user === null) {
                continue;
            }

            $identifier = (string) $user->getAuthIdentifier();

            return [
                'authenticated' => true,
                'guard' => $guard,
                'id' => $identifier,
                'actor_key' => $guard . ':' . $identifier,
                'type' => get_class($user),
                'name' => $user->name ?? $user->full_name ?? $user->title ?? null,
                'email' => $user->email ?? null,
            ];
        }

        return [
            'authenticated' => false,
            'guard' => null,
            'id' => null,
            'actor_key' => null,
            'type' => null,
            'name' => null,
            'email' => null,
        ];
    }
}
