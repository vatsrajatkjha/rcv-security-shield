<?php

namespace VendorShield\Shield\Guards\Upload;

/**
 * Polyglot file detection engine.
 *
 * Detects files that are valid in multiple formats simultaneously
 * (e.g., a file that is both a valid JPEG and contains executable PHP).
 * Uses multi-header scanning, script token detection in binary files,
 * and Shannon entropy analysis.
 */
class PolyglotDetector
{
    /**
     * Known file magic signatures for polyglot header scan.
     */
    protected const FILE_HEADERS = [
        'jpeg' => "\xFF\xD8\xFF",
        'png' => "\x89\x50\x4E\x47",
        'gif87' => 'GIF87a',
        'gif89' => 'GIF89a',
        'pdf' => '%PDF',
        'zip' => "PK\x03\x04",
        'rar' => 'Rar!',
        'gzip' => "\x1f\x8b",
        'bmp' => 'BM',
        'ole2' => "\xD0\xCF\x11\xE0",
        'elf' => "\x7FELF",
        'mz' => 'MZ',       // PE/EXE
    ];

    /**
     * Script patterns that should never appear in binary file formats.
     */
    protected const SCRIPT_TOKENS = [
        '<?php',
        '<?=',
        '<%',
        '<script',
        '#!/',           // Shebang
        'eval(',
        'system(',
        'exec(',
        'shell_exec(',
        'assert(',
        'passthru(',
        'proc_open(',
        'popen(',
        'create_function(',
        'call_user_func(',
        'preg_replace',  // with /e modifier
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$_FILES',
        '$_SERVER',
        '$_COOKIE',
        '__HALT_COMPILER',
    ];

    /**
     * MIME types considered "binary" where script tokens are anomalous.
     */
    protected const BINARY_MIMES = [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp',
        'image/tiff', 'image/x-icon',
        'application/pdf',
        'application/zip',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/msword', 'application/vnd.ms-excel',
        'audio/mpeg', 'audio/wav', 'audio/ogg',
        'video/mp4', 'video/webm',
    ];

    /**
     * Scan a file for polyglot characteristics.
     *
     * @param  string  $filePath  Path to the uploaded file.
     * @param  string  $declaredMime  The declared MIME type.
     */
    public function scan(string $filePath, string $declaredMime): PolyglotResult
    {
        if (! is_readable($filePath)) {
            return PolyglotResult::error('File not readable');
        }

        $fileSize = @filesize($filePath);
        if ($fileSize === false || $fileSize === 0) {
            return PolyglotResult::clean();
        }

        $findings = [];

        // 1. Multi-header detection: scan for multiple file type headers
        $headerFindings = $this->detectMultipleHeaders($filePath);
        if (! empty($headerFindings)) {
            $findings = array_merge($findings, $headerFindings);
        }

        // 2. Script token detection in binary files
        if (in_array($declaredMime, self::BINARY_MIMES, true)) {
            $scriptFindings = $this->detectScriptTokens($filePath, $fileSize);
            if (! empty($scriptFindings)) {
                $findings = array_merge($findings, $scriptFindings);
            }
        }

        // 3. Entropy analysis for suspicious regions
        $entropyFindings = $this->analyzeEntropy($filePath, $declaredMime, $fileSize);
        if (! empty($entropyFindings)) {
            $findings = array_merge($findings, $entropyFindings);
        }

        if (! empty($findings)) {
            return PolyglotResult::detected($findings);
        }

        return PolyglotResult::clean();
    }

    /**
     * Detect multiple file type headers within the first 1KB.
     */
    protected function detectMultipleHeaders(string $filePath): array
    {
        $content = @file_get_contents($filePath, false, null, 0, 1024);
        if ($content === false) {
            return [];
        }

        $findings = [];
        $detectedTypes = [];

        foreach (self::FILE_HEADERS as $type => $signature) {
            // Check at offset 0 (primary header)
            if (str_starts_with($content, $signature)) {
                $detectedTypes[] = $type;
            }
            // Also check if signatures appear anywhere in first 1KB
            if (! str_starts_with($content, $signature) && str_contains($content, $signature)) {
                $detectedTypes[] = "{$type}(embedded)";
            }
        }

        if (count($detectedTypes) > 1) {
            $findings[] = [
                'type' => 'multi_header',
                'detail' => 'Multiple file type signatures detected: '.implode(', ', $detectedTypes),
                'detected_types' => $detectedTypes,
            ];
        }

        return $findings;
    }

    /**
     * Detect script tokens inside files declared as binary formats.
     * Scans the full file in chunks to catch payloads hidden at any offset.
     */
    protected function detectScriptTokens(string $filePath, int $fileSize): array
    {
        $findings = [];
        $chunkSize = 8192;
        $handle = @fopen($filePath, 'rb');

        if ($handle === false) {
            return [];
        }

        try {
            $offset = 0;
            while (! feof($handle)) {
                $chunk = fread($handle, $chunkSize);
                if ($chunk === false) {
                    break;
                }

                $lowerChunk = strtolower($chunk);
                foreach (self::SCRIPT_TOKENS as $token) {
                    if (str_contains($lowerChunk, strtolower($token))) {
                        $findings[] = [
                            'type' => 'script_in_binary',
                            'detail' => "Script token '{$token}' found in binary file at offset ~{$offset}",
                            'token' => $token,
                            'offset' => $offset,
                        ];
                        fclose($handle);

                        return $findings; // One finding is enough to flag
                    }
                }

                $offset += strlen($chunk);
            }
        } finally {
            if (is_resource($handle)) {
                fclose($handle);
            }
        }

        return $findings;
    }

    /**
     * Analyze Shannon entropy of file regions.
     *
     * Binary images typically have moderate entropy (5.0-7.5).
     * Embedded encrypted/packed payloads show near-maximum entropy (~8.0)
     * or very low entropy (0.0-2.0) in regions that should be moderate.
     */
    protected function analyzeEntropy(string $filePath, string $declaredMime, int $fileSize): array
    {
        // Only analyze binary files larger than 1KB
        if (! in_array($declaredMime, self::BINARY_MIMES, true) || $fileSize < 1024) {
            return [];
        }

        $findings = [];
        $regionSize = min(4096, (int) ($fileSize / 4));

        // Check entropy at the end of the file (common payload location)
        $tailContent = @file_get_contents($filePath, false, null, max(0, $fileSize - $regionSize), $regionSize);
        if ($tailContent === false) {
            return [];
        }

        $tailEntropy = $this->calculateShannon($tailContent);

        // For most binary formats, tail entropy near 0 with significant length
        // suggests appended plaintext (like PHP code)
        if ($tailEntropy < 2.0 && strlen($tailContent) > 256) {
            // Low entropy tail in a binary file → possible plaintext payload
            $lowerTail = strtolower($tailContent);
            foreach (['<?php', '<?=', '<script', 'eval(', 'system('] as $marker) {
                if (str_contains($lowerTail, $marker)) {
                    $findings[] = [
                        'type' => 'entropy_anomaly',
                        'detail' => "Low entropy region at file tail contains script markers (entropy: {$tailEntropy})",
                        'entropy' => $tailEntropy,
                    ];
                    break;
                }
            }
        }

        return $findings;
    }

    /**
     * Calculate Shannon entropy of a byte string.
     *
     * @return float Entropy value between 0.0 (uniform) and 8.0 (random).
     */
    protected function calculateShannon(string $data): float
    {
        $length = strlen($data);
        if ($length === 0) {
            return 0.0;
        }

        $frequencies = array_count_values(str_split($data));
        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $probability = $count / $length;
            if ($probability > 0) {
                $entropy -= $probability * log($probability, 2);
            }
        }

        return round($entropy, 4);
    }
}

/**
 * Result of polyglot detection scan.
 */
class PolyglotResult
{
    public function __construct(
        public readonly bool $isPolyglot,
        public readonly array $findings = [],
        public readonly ?string $error = null,
    ) {}

    public static function clean(): static
    {
        return new static(isPolyglot: false);
    }

    public static function detected(array $findings): static
    {
        return new static(isPolyglot: true, findings: $findings);
    }

    public static function error(string $message): static
    {
        return new static(isPolyglot: false, error: $message);
    }
}
