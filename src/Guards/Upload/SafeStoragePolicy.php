<?php

namespace VendorShield\Shield\Guards\Upload;

/**
 * Safe storage policy enforcement engine.
 *
 * Validates that upload storage paths are outside the web root,
 * generates hash-based directory sharding, and enforces file
 * permissions on stored uploads.
 */
class SafeStoragePolicy
{
    /**
     * Validate that a storage path is outside the web root.
     *
     * @param  string  $storagePath  The configured storage path.
     * @param  string  $publicPath  The application's public directory.
     */
    public function isStoragePathSafe(string $storagePath, string $publicPath): bool
    {
        $realStorage = realpath($storagePath);
        $realPublic = realpath($publicPath);

        // If either path doesn't resolve, we can't validate
        if ($realStorage === false || $realPublic === false) {
            // If storage path doesn't exist yet, check the parent
            $parentStorage = realpath(dirname($storagePath));
            if ($parentStorage === false) {
                return true; // Can't determine, caller must handle
            }
            $realStorage = $parentStorage.DIRECTORY_SEPARATOR.basename($storagePath);
        }

        // Storage must NOT be under public path
        return ! str_starts_with($realStorage, $realPublic);
    }

    /**
     * Generate a hash-based sharded directory path.
     *
     * Creates a 2-level directory structure based on the file hash
     * to avoid filesystem bottlenecks with millions of files.
     *
     * Example: hash "a1b2c3d4..." → "a1/b2/a1b2c3d4..."
     *
     * @param  string  $fileHash  SHA-256 hash of the file.
     * @return string Relative path with directory sharding.
     */
    public function generateShardedPath(string $fileHash): string
    {
        $shard1 = substr($fileHash, 0, 2);
        $shard2 = substr($fileHash, 2, 2);

        return $shard1.DIRECTORY_SEPARATOR.$shard2;
    }

    /**
     * Build the complete safe storage path for a file.
     *
     * @param  string  $basePath  The configured storage base path.
     * @param  string  $fileHash  SHA-256 hash of the file.
     * @param  string  $safeFilename  The randomized filename (from FilenameCanonicalizer).
     * @return string Complete storage path.
     */
    public function buildStoragePath(string $basePath, string $fileHash, string $safeFilename): string
    {
        $shardedDir = $this->generateShardedPath($fileHash);

        return rtrim($basePath, DIRECTORY_SEPARATOR)
            .DIRECTORY_SEPARATOR
            .$shardedDir
            .DIRECTORY_SEPARATOR
            .$safeFilename;
    }

    /**
     * Enforce read-only permissions on a stored file.
     *
     * @param  string  $filePath  Path to the stored file.
     * @return bool True if permissions were set successfully.
     */
    public function enforceReadOnly(string $filePath): bool
    {
        if (! file_exists($filePath)) {
            return false;
        }

        return chmod($filePath, 0444);
    }

    /**
     * Validate that a path contains no traversal sequences.
     */
    public function isPathTraversalFree(string $path): bool
    {
        $normalized = str_replace('\\', '/', $path);

        if (str_contains($normalized, '../')
            || str_contains($normalized, './')
            || str_contains($normalized, '\0')) {
            return false;
        }

        return true;
    }
}
