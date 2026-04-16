<?php

namespace VendorShield\Shield\Support;

final class FailSafe
{
    /**
     * Execute a callback and swallow any exception.
     */
    public static function run(callable $callback, mixed $default = null): mixed
    {
        try {
            return $callback();
        } catch (\Throwable) {
            return $default;
        }
    }

    /**
     * Safely dispatch a side effect such as an event or callback.
     */
    public static function dispatch(callable $callback): void
    {
        self::run($callback);
    }

    /**
     * Ensure a directory exists.
     */
    public static function ensureDirectory(string $path, int $mode = 0755): bool
    {
        if (is_dir($path)) {
            return true;
        }

        return (bool) self::run(fn () => mkdir($path, $mode, true), false);
    }

    /**
     * Safely write a file.
     */
    public static function writeFile(string $path, string $contents): bool
    {
        return self::run(fn () => file_put_contents($path, $contents) !== false, false);
    }
}
