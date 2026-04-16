<?php

namespace VendorShield\Shield\Guards;

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Cache;
use VendorShield\Shield\Async\ShieldAnalysisJob;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\GuardContract;
use VendorShield\Shield\Events\GuardTriggered;
use VendorShield\Shield\Events\ThreatDetected;
use VendorShield\Shield\Guards\Upload\ArchiveInspector;
use VendorShield\Shield\Guards\Upload\ContentScannerV2;
use VendorShield\Shield\Guards\Upload\FilenameCanonicalizer;
use VendorShield\Shield\Guards\Upload\MagicByteValidator;
use VendorShield\Shield\Guards\Upload\PolyglotDetector;
use VendorShield\Shield\Guards\Upload\RecursiveDecoder;
use VendorShield\Shield\Guards\Upload\SafeStoragePolicy;
use VendorShield\Shield\Guards\Upload\StreamProcessor;
use VendorShield\Shield\Support\FailSafe;
use VendorShield\Shield\Support\GuardResult;
use VendorShield\Shield\Support\Severity;

class UploadGuard implements GuardContract
{
    /**
     * Immutable blacklist of strictly prohibited executable extensions.
     */
    protected const SYSTEM_BLOCKED_EXTENSIONS = [
        'php', 'php3', 'php4', 'php5', 'php7', 'pht', 'phps', 'phar', 'phpt', 'pgif', 'phtml', 'phtm', 'inc',
        'asp', 'aspx', 'config', 'cer', 'asa', 'soap',
        'jsp', 'jspx', 'jsw', 'jsv', 'jspf', 'wss', 'do', 'action',
        'pl', 'pm', 'cgi', 'lib',
        'cfm', 'cfml', 'cfc', 'dbm',
        'js', 'json', 'node', 'py', 'rb',
        'sh', 'bat', 'cmd', 'ps1', 'vbs', 'exe', 'dll', 'so', 'msi', 'com', 'pif', 'scr',
    ];

    /**
     * Immutable blacklist of strictly prohibited explicit files.
     */
    protected const SYSTEM_BLOCKED_FILES = [
        '.htaccess', 'web.config', 'uwsgi.ini', '.user.ini', 'php.ini',
        'composer.json', 'package.json', 'yarn.lock', 'package-lock.json',
        '__init__.py',
    ];

    /**
     * Cache prefix for scan results.
     */
    protected const CACHE_PREFIX = 'shield:upload:scan:';

    /**
     * Supported extension to MIME mapping.
     *
     * @var array<string, array<int, string>>
     */
    protected const EXTENSION_MIME_MAP = [
        'jpg' => ['image/jpeg'],
        'jpeg' => ['image/jpeg'],
        'png' => ['image/png'],
        'gif' => ['image/gif'],
        'webp' => ['image/webp'],
        'pdf' => ['application/pdf'],
        'txt' => ['text/plain'],
        'csv' => ['text/csv', 'text/plain'],
        'doc' => ['application/msword'],
        'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
        'xls' => ['application/vnd.ms-excel'],
        'xlsx' => ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
        'zip' => ['application/zip'],
        'gz' => ['application/gzip', 'application/x-gzip'],
        'tar' => ['application/x-tar'],
        'tgz' => ['application/gzip', 'application/x-gzip'],
        'bz2' => ['application/x-bzip2'],
        'rar' => ['application/vnd.rar', 'application/x-rar-compressed'],
        '7z' => ['application/x-7z-compressed'],
    ];

    public function __construct(
        protected ConfigResolver $config,
        protected AuditLogger $audit,
        protected FilenameCanonicalizer $filenameSanitizer,
        protected RecursiveDecoder $decoder,
        protected MagicByteValidator $magicValidator,
        protected PolyglotDetector $polyglotDetector,
        protected ContentScannerV2 $contentScanner,
        protected SafeStoragePolicy $storagePolicy,
        protected StreamProcessor $streamProcessor,
        protected ArchiveInspector $archiveInspector,
    ) {}

    public function name(): string
    {
        return 'upload';
    }

    public function enabled(): bool
    {
        return $this->config->guardEnabled('upload');
    }

    public function mode(): string
    {
        return $this->config->guardMode('upload');
    }

    /**
     * Validate an uploaded file through the Zero-Trust security pipeline.
     *
     * Pipeline (10 stages):
     * 1. Stream Processing (safe scan path)
     * 2. Hash Cache Check (skip if known-clean)
     * 3. Filename Canonicalization & Validation
     * 4. Extension Validation (with unicode normalization)
     * 5. Size Validation
     * 6. MIME Type Validation
     * 7. Magic Byte Validation (expanded, fail-closed)
     * 8. Polyglot Detection
     * 9. Recursive Decode + Content Scan (full file)
     * 10. Async Deep Scan dispatch
     */
    public function handle(mixed $context): GuardResult
    {
        if (! $context instanceof UploadedFile) {
            return GuardResult::pass($this->name());
        }

        try {
            return $this->runPipeline($context);
        } finally {
            $this->streamProcessor->cleanup();
        }
    }

    /**
     * Validate a batch of uploaded files.
     *
     * @param  array<UploadedFile>  $files
     * @return array<GuardResult>
     */
    public function handleBatch(array $files): array
    {
        return array_map(fn (UploadedFile $file) => $this->handle($file), $files);
    }

    /**
     * Execute the full security pipeline.
     */
    protected function runPipeline(UploadedFile $file): GuardResult
    {
        // Stage 1: Get safe scan path
        $scanPath = $this->streamProcessor->getScanPath($file);
        $failClosed = $this->config->guard('upload', 'fail_closed_on_error', true);

        if ($scanPath === null) {
            if ($failClosed) {
                return $this->failResult(
                    'Unable to access uploaded file for security scanning',
                    Severity::High,
                    ['filename' => $file->getClientOriginalName()],
                );
            }

            return GuardResult::pass($this->name());
        }

        // Stage 2: Hash cache check
        $fileHash = $this->streamProcessor->computeHash($scanPath);
        if ($fileHash !== null && $this->config->guard('upload', 'scan_cache_enabled', true)) {
            $cached = $this->checkCache($fileHash);
            if ($cached !== null) {
                return $cached;
            }
        }

        // Stage 3-9: Security checks pipeline
        $checks = [
            fn () => $this->checkFilenameStructure($file),
            fn () => $this->checkExtension($file),
            fn () => $this->checkFileSize($file),
            fn () => $this->checkMimeSignals($file, $scanPath),
            fn () => $this->checkPolyglot($file, $scanPath),
            fn () => $this->checkArchive($file, $scanPath),
            fn () => $this->checkContent($file, $scanPath),
        ];

        foreach ($checks as $check) {
            $result = $check();
            if (! $result->passed) {
                $this->handleResult($result, $file);

                return ($this->mode() === 'enforce') ? $result : GuardResult::monitor(
                    guard: $this->name(),
                    message: $result->message,
                    severity: $result->severity,
                    metadata: $result->metadata,
                );
            }
        }

        // Stage 10: Cache clean result & dispatch async scan
        if ($fileHash !== null && $this->config->guard('upload', 'scan_cache_enabled', true)) {
            $this->cacheResult($fileHash, true);
        }

        if ($this->config->guard('upload', 'async_scan', true)) {
            $this->dispatchAsyncScan($file, $scanPath, $fileHash);
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Stage 3: Validate filename structure with full canonicalization.
     */
    protected function checkFilenameStructure(UploadedFile $file): GuardResult
    {
        $rawName = $file->getClientOriginalName();

        // Check for specific malicious files (before canonicalization, to catch exact matches)
        if (in_array(strtolower($rawName), self::SYSTEM_BLOCKED_FILES, true)) {
            return $this->failResult(
                "Blocked sensitive configuration file: {$rawName}",
                Severity::Critical,
                ['filename' => $rawName],
            );
        }

        $maxFilenameLength = (int) $this->config->guard('upload', 'max_filename_length', 120);
        if (strlen($rawName) > $maxFilenameLength) {
            return $this->failResult(
                "Filename exceeds maximum allowed length: {$rawName}",
                Severity::Medium,
                ['filename' => $rawName, 'max_length' => $maxFilenameLength],
            );
        }

        // Null byte injection (check raw name before canonicalization)
        if (str_contains($rawName, "\0") || str_contains($rawName, '%00')) {
            return $this->failResult(
                "Filename contains null byte injection: {$rawName}",
                Severity::Critical,
                ['filename' => $rawName],
            );
        }

        // RTLO character injection
        if (str_contains($rawName, "\xE2\x80\xAE") || str_contains($rawName, '%E2%80%AE')) {
            return $this->failResult(
                "Filename contains RTLO character injection: {$rawName}",
                Severity::High,
                ['filename' => $rawName],
            );
        }

        // Windows bypass: Trailing dots and spaces
        if (preg_match('/[\s\.]+$/', $rawName)) {
            return $this->failResult(
                "Filename contains illegal trailing characters: {$rawName}",
                Severity::High,
                ['filename' => $rawName],
            );
        }

        // Windows bypass: Alternate Data Streams (ADS)
        if (str_contains($rawName, ':$') || str_contains($rawName, '::$DATA')) {
            return $this->failResult(
                "Filename contains Alternate Data Stream injection: {$rawName}",
                Severity::Critical,
                ['filename' => $rawName],
            );
        }

        // Path Traversal chars (../, ..\) — check raw AND decoded forms
        if (preg_match('/(?:(?:\.\.+)[\\\\\/]|(?:[\\\\\/]+\.\.+))/i', $rawName)) {
            return $this->failResult(
                "Filename contains path traversal characters: {$rawName}",
                Severity::High,
                ['filename' => $rawName],
            );
        }

        // Double-encoded path traversal (%252e%252e%252f etc.)
        $decodedName = rawurldecode(rawurldecode($rawName));
        if ($decodedName !== $rawName && preg_match('/(?:(?:\.\.+)[\\\\\/]|(?:[\\\\\/]+\.\.+))/i', $decodedName)) {
            return $this->failResult(
                "Filename contains encoded path traversal: {$rawName}",
                Severity::Critical,
                ['filename' => $rawName, 'decoded' => $decodedName],
            );
        }

        $baseName = basename(str_replace('\\', '/', $rawName));
        if (! $this->config->guard('upload', 'allow_hidden_dotfiles', false) && str_starts_with($baseName, '.')) {
            return $this->failResult(
                "Hidden dotfile uploads are not allowed: {$rawName}",
                Severity::High,
                ['filename' => $rawName],
            );
        }

        // XSS/Command Injection in filename
        if (preg_match('/[;<>\"\' =]/i', $rawName)) {
            return $this->failResult(
                "Filename contains illegal characters: {$rawName}",
                Severity::High,
                ['filename' => $rawName],
            );
        }

        // URL-encoded newline/carriage return characters
        if (preg_match('/%0[aAdD]/i', $rawName)) {
            return $this->failResult(
                "Filename contains encoded newline/carriage return: {$rawName}",
                Severity::High,
                ['filename' => $rawName],
            );
        }

        // Extensionless file rejection
        if ($this->config->guard('upload', 'reject_extensionless', true)) {
            $canonicalized = $this->filenameSanitizer->canonicalize($rawName);
            if ($this->filenameSanitizer->isExtensionless($canonicalized)) {
                return $this->failResult(
                    "Extensionless file upload rejected: {$rawName}",
                    Severity::High,
                    ['filename' => $rawName],
                );
            }
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Stage 4: Validate file extension (with unicode homoglyph normalization).
     */
    protected function checkExtension(UploadedFile $file): GuardResult
    {
        $rawName = $file->getClientOriginalName();
        $userBlocked = $this->config->guard('upload', 'blocked_extensions', []);
        $blocked = array_unique(array_merge(self::SYSTEM_BLOCKED_EXTENSIONS, $userBlocked));
        $allowed = array_map('strtolower', $this->config->guard('upload', 'allowed_extensions', []));
        $canonicalized = $this->filenameSanitizer->canonicalize($rawName);

        // Standard extension check
        $extension = strtolower($file->getClientOriginalExtension());

        if ($extension === '') {
            return $this->failResult(
                'File extension could not be determined',
                Severity::High,
                ['filename' => $rawName],
            );
        }

        if ($this->config->guard('upload', 'unicode_normalization', true)) {
            $normalizedExt = $this->filenameSanitizer->extractExtension($canonicalized);

            if ($normalizedExt !== $extension && in_array($normalizedExt, $blocked, true)) {
                return $this->failResult(
                    "Unicode homoglyph attack detected: extension normalizes to .{$normalizedExt}",
                    Severity::Critical,
                    ['filename' => $rawName, 'raw_ext' => $extension, 'normalized_ext' => $normalizedExt],
                );
            }
        } else {
            $normalizedExt = $extension;
        }

        $effectiveExtension = $normalizedExt !== '' ? $normalizedExt : $extension;

        if (in_array($effectiveExtension, $blocked, true)) {
            return $this->failResult(
                "Blocked file extension: .{$effectiveExtension}",
                Severity::High,
                ['filename' => $rawName, 'extension' => $effectiveExtension],
            );
        }

        if (! empty($allowed) && ! in_array($effectiveExtension, $allowed, true)) {
            return $this->failResult(
                "File extension is not allowed: .{$effectiveExtension}",
                Severity::High,
                ['filename' => $rawName, 'extension' => $effectiveExtension],
            );
        }

        // Unicode homoglyph normalization check
        if ($this->config->guard('upload', 'unicode_normalization', true)) {
            // Check ALL extensions in multi-dot filenames
            $allExtensions = $this->filenameSanitizer->extractAllExtensions($canonicalized);
            foreach ($allExtensions as $ext) {
                if (in_array($ext, $blocked, true)) {
                    return $this->failResult(
                        "Double extension attack detected (normalized): {$rawName}",
                        Severity::Critical,
                        ['filename' => $rawName, 'detected_extension' => $ext],
                    );
                }
            }
        }

        // Double extension check (original behavior preserved)
        $parts = explode('.', $rawName);
        if (count($parts) > 2) {
            foreach (array_slice($parts, 0, -1) as $part) {
                if (in_array(strtolower($part), $blocked, true)) {
                    return $this->failResult(
                        "Double extension attack detected: {$rawName}",
                        Severity::Critical,
                        ['filename' => $rawName],
                    );
                }
            }
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Stage 5: Validate file size.
     */
    protected function checkFileSize(UploadedFile $file): GuardResult
    {
        $maxSize = $this->config->guard('upload', 'max_file_size', 52428800);

        if ($file->getSize() > $maxSize) {
            return $this->failResult(
                'File exceeds maximum allowed size',
                Severity::Medium,
                [
                    'filename' => $file->getClientOriginalName(),
                    'size' => $file->getSize(),
                    'max_size' => $maxSize,
                ],
            );
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Stage 6: Validate MIME type.
     */
    protected function checkMimeSignals(UploadedFile $file, string $scanPath): GuardResult
    {
        $extension = strtolower($file->getClientOriginalExtension());
        $allowedMimes = $this->config->guard('upload', 'allowed_mimes', []);
        $serverMime = (string) $file->getMimeType();
        $clientMime = (string) $file->getClientMimeType();

        if (! empty($allowedMimes) && ! in_array($serverMime, $allowedMimes, true)) {
            return $this->failResult(
                "Server-detected MIME type not allowed: {$serverMime}",
                Severity::High,
                [
                    'filename' => $file->getClientOriginalName(),
                    'mime' => $serverMime,
                ],
            );
        }

        $expectedMimes = self::EXTENSION_MIME_MAP[$extension] ?? [];
        if (! empty($expectedMimes) && ! in_array($serverMime, $expectedMimes, true)) {
            return $this->failResult(
                'Server-detected MIME does not match the file extension',
                Severity::High,
                [
                    'filename' => $file->getClientOriginalName(),
                    'extension' => $extension,
                    'server_mime' => $serverMime,
                    'expected_mimes' => $expectedMimes,
                ],
            );
        }

        if ($this->config->guard('upload', 'compare_client_mime', true) && $clientMime !== '' && $clientMime !== $serverMime) {
            return $this->failResult(
                'Client-declared MIME does not match the server-detected MIME',
                Severity::High,
                [
                    'filename' => $file->getClientOriginalName(),
                    'client_mime' => $clientMime,
                    'server_mime' => $serverMime,
                ],
            );
        }

        if (! $this->config->guard('upload', 'verify_magic_bytes', true)) {
            return GuardResult::pass($this->name());
        }

        $rejectUnknown = $this->config->guard('upload', 'reject_unknown_mime', true);
        $result = $this->magicValidator->validate($scanPath, $serverMime, $rejectUnknown);

        if (! $result->valid) {
            return $this->failResult(
                $result->message,
                $result->mismatch ? Severity::High : Severity::Medium,
                [
                    'filename' => $file->getClientOriginalName(),
                    'declared_mime' => $result->declaredMime,
                    'detected_mime' => $result->detectedMime,
                    'client_mime' => $clientMime,
                ],
            );
        }

        if (! empty($expectedMimes) && $result->detectedMime !== null && ! in_array($result->detectedMime, $expectedMimes, true)) {
            return $this->failResult(
                'Magic-byte signature does not match the file extension',
                Severity::Critical,
                [
                    'filename' => $file->getClientOriginalName(),
                    'extension' => $extension,
                    'detected_mime' => $result->detectedMime,
                    'expected_mimes' => $expectedMimes,
                ],
            );
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Stage 8: Polyglot detection.
     */
    protected function checkPolyglot(UploadedFile $file, string $scanPath): GuardResult
    {
        if (! $this->config->guard('upload', 'polyglot_detection', true)) {
            return GuardResult::pass($this->name());
        }

        $mime = $file->getMimeType();
        $result = $this->polyglotDetector->scan($scanPath, $mime);

        if ($result->isPolyglot) {
            $detail = ! empty($result->findings)
                ? $result->findings[0]['detail'] ?? 'Polyglot file detected'
                : 'Polyglot file detected';

            return $this->failResult(
                "Polyglot file detected: {$detail}",
                Severity::Critical,
                [
                    'filename' => $file->getClientOriginalName(),
                    'mime' => $mime,
                    'findings' => $result->findings,
                ],
            );
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Stage 9: Archive blocking and synchronous inspection.
     */
    protected function checkArchive(UploadedFile $file, string $scanPath): GuardResult
    {
        $inspection = $this->archiveInspector->inspect(
            $scanPath,
            strtolower($file->getClientOriginalExtension()),
            (int) $this->config->guard('upload', 'archive_max_entries', 500),
            (int) $this->config->guard('upload', 'archive_max_uncompressed_bytes', 104857600),
            (bool) $this->config->guard('upload', 'block_archives', true),
        );

        if (($inspection['archive'] ?? false) && ($inspection['blocked'] ?? false)) {
            return $this->failResult(
                $inspection['message'] ?? 'Archive rejected by security policy',
                Severity::Critical,
                array_merge(
                    ['filename' => $file->getClientOriginalName()],
                    $inspection['metadata'] ?? [],
                ),
            );
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Stage 9: Recursive decode + enhanced content scanning.
     */
    protected function checkContent(UploadedFile $file, string $scanPath): GuardResult
    {
        $fullScan = $this->config->guard('upload', 'full_content_scan', true);
        $maxScanBytes = $fullScan ? 0 : $this->config->guard('upload', 'content_scan_bytes', 8192);

        $result = $this->contentScanner->scan($scanPath, $maxScanBytes);

        if (! $result->clean) {
            $detail = ! empty($result->findings)
                ? $result->findings[0]['detail'] ?? 'Dangerous content detected'
                : ($result->error ?? 'Dangerous content detected');

            return $this->failResult(
                'Dangerous content detected in uploaded file',
                Severity::Critical,
                [
                    'filename' => $file->getClientOriginalName(),
                    'mime' => $file->getMimeType(),
                    'scan_detail' => $detail,
                ],
            );
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Check scan cache for a previously scanned file.
     */
    protected function checkCache(string $fileHash): ?GuardResult
    {
        $cacheKey = self::CACHE_PREFIX.$fileHash;
        $ttl = $this->config->guard('upload', 'scan_cache_ttl', 3600);

        try {
            $cached = Cache::get($cacheKey);
            if ($cached === true) {
                return GuardResult::pass($this->name());
            }
        } catch (\Throwable) {
            // Cache failure should not block scanning
        }

        return null;
    }

    /**
     * Cache a scan result.
     */
    protected function cacheResult(string $fileHash, bool $clean): void
    {
        $cacheKey = self::CACHE_PREFIX.$fileHash;
        $ttl = $this->config->guard('upload', 'scan_cache_ttl', 3600);

        try {
            Cache::put($cacheKey, $clean, $ttl);
        } catch (\Throwable) {
            // Cache failure should not block
        }
    }

    /**
     * Dispatch async deep scan.
     */
    protected function dispatchAsyncScan(UploadedFile $file, string $scanPath, ?string $fileHash): void
    {
        if (! $this->config->get('async.enabled', true)) {
            return;
        }

        try {
            ShieldAnalysisJob::dispatch([
                'guard' => $this->name(),
                'filename' => $file->getClientOriginalName(),
                'mime' => $file->getMimeType(),
                'size' => $file->getSize(),
                'hash' => $fileHash ?? hash_file('sha256', $scanPath),
                'path' => $scanPath,
                'timestamp' => now()->toIso8601String(),
            ])->onQueue($this->config->get('async.queue', 'shield'));
        } catch (\Throwable) {
            // Never block upload due to async failure
        }
    }

    /**
     * Create a failing guard result and trigger events.
     */
    protected function failResult(string $message, Severity $severity, array $metadata = []): GuardResult
    {
        return GuardResult::fail(
            guard: $this->name(),
            message: $message,
            severity: $severity,
            metadata: $metadata,
        );
    }

    protected function handleResult(GuardResult $result, UploadedFile $file): void
    {
        FailSafe::dispatch(function () use ($result) {
            if ($this->mode() === 'enforce') {
                event(new ThreatDetected($this->name(), $result));
            } else {
                event(new GuardTriggered($this->name(), $result));
            }
        });

        FailSafe::dispatch(fn () => $this->audit->guardEvent($this->name(), 'upload_threat', $result));
    }
}
