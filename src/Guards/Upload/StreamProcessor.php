<?php

namespace VendorShield\Shield\Guards\Upload;

use Illuminate\Http\UploadedFile;

/**
 * Stream-safe file processing engine.
 *
 * Ensures that file scanning operations don't consume or corrupt
 * the original upload stream. Creates safe temporary copies for
 * scanning while preserving the original for Laravel's pipeline.
 *
 * Octane-compatible: no shared state, scoped lifecycle.
 */
class StreamProcessor
{
    /**
     * Tracked temporary files for cleanup.
     *
     * @var array<string>
     */
    protected array $tempFiles = [];

    /**
     * Get a safe file path for scanning an uploaded file.
     *
     * If the file already has a real path (standard PHP uploads),
     * returns it directly. For stream-based uploads (Octane/Swoole),
     * creates a temporary copy.
     *
     * @param UploadedFile $file The uploaded file.
     * @return string|null Path to a scannable file, or null on failure.
     */
    public function getScanPath(UploadedFile $file): ?string
    {
        $realPath = $file->getRealPath();

        if ($realPath !== false && $realPath !== '' && is_readable($realPath)) {
            return $realPath;
        }

        // Stream-based upload: create temp copy
        return $this->createTempCopy($file);
    }

    /**
     * Create a temporary copy of an uploaded file for scanning.
     */
    protected function createTempCopy(UploadedFile $file): ?string
    {
        $tempPath = tempnam(sys_get_temp_dir(), 'shield_scan_');

        if ($tempPath === false) {
            return null;
        }

        try {
            $stream = fopen($file->getPathname(), 'rb');
            if ($stream === false) {
                unlink($tempPath);
                return null;
            }

            $target = fopen($tempPath, 'wb');
            if ($target === false) {
                fclose($stream);
                unlink($tempPath);
                return null;
            }

            stream_copy_to_stream($stream, $target);
            fclose($stream);
            fclose($target);

            $this->tempFiles[] = $tempPath;

            return $tempPath;
        } catch (\Throwable) {
            @unlink($tempPath);
            return null;
        }
    }

    /**
     * Compute SHA-256 hash of a file.
     *
     * @return string|null The hex-encoded SHA-256 hash.
     */
    public function computeHash(string $filePath): ?string
    {
        if (! is_readable($filePath)) {
            return null;
        }

        $hash = hash_file('sha256', $filePath);

        return $hash !== false ? $hash : null;
    }

    /**
     * Get file size safely.
     */
    public function getFileSize(string $filePath): int
    {
        $size = @filesize($filePath);
        return $size !== false ? $size : 0;
    }

    /**
     * Clean up all temporary files created during scanning.
     */
    public function cleanup(): void
    {
        foreach ($this->tempFiles as $path) {
            if (file_exists($path)) {
                @unlink($path);
            }
        }
        $this->tempFiles = [];
    }

    public function __destruct()
    {
        $this->cleanup();
    }
}
