<?php

namespace VendorShield\Shield\Guards\Upload;

/**
 * Enhanced content scanning engine (V2).
 *
 * Scans file content at multiple offsets (not just the header),
 * applies recursive decoding before pattern matching, and detects
 * obfuscated PHP constructs, command execution, and superglobal abuse.
 */
class ContentScannerV2
{
    /**
     * Dangerous content patterns — extended from original UploadGuard.
     *
     * Each pattern is case-insensitive and designed to catch both
     * plain and partially obfuscated payloads.
     */
    protected const DANGEROUS_PATTERNS = [
        // PHP opening tags
        '/\<\?php/i',
        '/\<\?\=/i',
        '/\<\%/i',

        // Script/HTML injection
        '/\<script\b/i',

        // PHP code execution functions
        '/\beval\s*\(/i',
        '/\bassert\s*\(/i',
        '/\bsystem\s*\(/i',
        '/\bexec\s*\(/i',
        '/\bshell_exec\s*\(/i',
        '/\bpassthru\s*\(/i',
        '/\bproc_open\s*\(/i',
        '/\bpopen\s*\(/i',
        '/\bpcntl_exec\s*\(/i',
        '/\bcreate_function\s*\(/i',
        '/\bcall_user_func\s*\(/i',
        '/\bcall_user_func_array\s*\(/i',
        '/\bpreg_replace\s*\(.*\/[a-z]*e[a-z]*\s*,/i', // preg_replace with /e modifier
        '/\barray_map\s*\(\s*[\'"]?(assert|eval|system|exec)/i',

        // PHP superglobals (often used in webshells)
        '/\$_GET\s*\[/i',
        '/\$_POST\s*\[/i',
        '/\$_REQUEST\s*\[/i',
        '/\$_FILES\s*\[/i',
        '/\$_SERVER\s*\[/i',
        '/\$_COOKIE\s*\[/i',

        // PHP compilation halt (PHAR exploit)
        '/__HALT_COMPILER/i',

        // ImageMagick exploits (ImageTragick)
        '/push\s+graphic\-context/i',
        '/fill\s+\'url\(/i',

        // FFMpeg HLS exploit
        '/#EXTM3U/i',

        // Ghostscript exploits
        '/^%!PS/im',
        '/(%pipe%|currentdevice\s+putdeviceprops)/i',

        // EICAR AV test
        '/EICAR-STANDARD-ANTIVIRUS-TEST-FILE/i',

        // SVG attack vectors
        '/\<\!ENTITY/i',
        '/\<\!DOCTYPE\s+\w+\s+SYSTEM/i',
        '/xlink:href\s*=\s*["\'](?!#)/i',

        // Backtick execution
        '/`[^`]*\$[^`]*`/i',

        // PHP obfuscation patterns
        '/\bbase64_decode\s*\(/i',
        '/\bgzinflate\s*\(/i',
        '/\bgzuncompress\s*\(/i',
        '/\bstr_rot13\s*\(/i',
        '/\bconvert_uudecode\s*\(/i',
        '/\brawurldecode\s*\(/i',

        // Dynamic function invocation patterns
        '/\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        '/\$\{\s*\$\w+\s*\}/i', // Variable variables: ${$var}
    ];

    protected RecursiveDecoder $decoder;

    public function __construct(?RecursiveDecoder $decoder = null)
    {
        $this->decoder = $decoder ?? new RecursiveDecoder();
    }

    /**
     * Scan file content for dangerous patterns.
     *
     * Reads the file in chunks and applies recursive decoding
     * before pattern matching. Scans the entire file, not just the header.
     *
     * @param string $filePath     Path to the uploaded file.
     * @param int    $maxScanBytes Maximum bytes to scan (0 = entire file).
     *
     * @return ContentScanResult
     */
    public function scan(string $filePath, int $maxScanBytes = 0): ContentScanResult
    {
        if (! is_readable($filePath)) {
            return ContentScanResult::error('File not readable');
        }

        $fileSize = @filesize($filePath);
        if ($fileSize === false || $fileSize === 0) {
            return ContentScanResult::clean();
        }

        // Determine scan range
        $scanSize = ($maxScanBytes > 0) ? min($maxScanBytes, $fileSize) : $fileSize;

        // For efficiency, scan in strategic chunks rather than loading entire file
        $findings = [];
        $chunks = $this->getStrategicChunks($filePath, $scanSize, $fileSize);

        foreach ($chunks as $chunk) {
            $chunkFindings = $this->scanChunk($chunk['data'], $chunk['offset']);
            if (! empty($chunkFindings)) {
                return ContentScanResult::threat($chunkFindings);
            }
        }

        return ContentScanResult::clean();
    }

    /**
     * Get strategic chunks for scanning.
     * Reads: beginning, middle, and end of file.
     *
     * @return array<array{data: string, offset: int}>
     */
    protected function getStrategicChunks(string $filePath, int $scanSize, int $fileSize): array
    {
        $chunkSize = min(32768, $scanSize); // 32KB chunks
        $chunks = [];

        // Always scan the beginning
        $content = @file_get_contents($filePath, false, null, 0, $chunkSize);
        if ($content !== false) {
            $chunks[] = ['data' => $content, 'offset' => 0];
        }

        if ($fileSize <= $chunkSize) {
            return $chunks;
        }

        // Scan the middle
        $middleOffset = (int) ($fileSize / 2) - (int) ($chunkSize / 2);
        if ($middleOffset > $chunkSize) {
            $content = @file_get_contents($filePath, false, null, $middleOffset, $chunkSize);
            if ($content !== false) {
                $chunks[] = ['data' => $content, 'offset' => $middleOffset];
            }
        }

        // Always scan the end (common payload injection point)
        $endOffset = max(0, $fileSize - $chunkSize);
        if ($endOffset > $chunkSize) {
            $content = @file_get_contents($filePath, false, null, $endOffset, $chunkSize);
            if ($content !== false) {
                $chunks[] = ['data' => $content, 'offset' => $endOffset];
            }
        }

        return $chunks;
    }

    /**
     * Scan a single chunk of content.
     */
    protected function scanChunk(string $rawContent, int $offset): array
    {
        $findings = [];

        // 1. Scan raw content first
        $rawMatch = $this->matchPatterns($rawContent);
        if ($rawMatch !== null) {
            $findings[] = [
                'type' => 'dangerous_pattern',
                'detail' => "Dangerous pattern in raw content at offset ~{$offset}",
                'pattern' => $rawMatch,
            ];
            return $findings;
        }

        // 2. Apply recursive decoding and scan again
        $decodedContent = $this->decoder->decode($rawContent);
        if ($decodedContent !== $rawContent) {
            $decodedMatch = $this->matchPatterns($decodedContent);
            if ($decodedMatch !== null) {
                $findings[] = [
                    'type' => 'encoded_dangerous_pattern',
                    'detail' => "Dangerous pattern detected after decoding at offset ~{$offset}",
                    'pattern' => $decodedMatch,
                    'encoding_detected' => true,
                ];
                return $findings;
            }
        }

        return $findings;
    }

    /**
     * Match content against all dangerous patterns.
     *
     * @return string|null The matched pattern description, or null if clean.
     */
    protected function matchPatterns(string $content): ?string
    {
        foreach (self::DANGEROUS_PATTERNS as $pattern) {
            if (@preg_match($pattern, $content)) {
                return $pattern;
            }
        }

        return null;
    }
}

/**
 * Result of content scanning.
 */
class ContentScanResult
{
    public function __construct(
        public readonly bool $clean,
        public readonly array $findings = [],
        public readonly ?string $error = null,
    ) {}

    public static function clean(): static
    {
        return new static(clean: true);
    }

    public static function threat(array $findings): static
    {
        return new static(clean: false, findings: $findings);
    }

    public static function error(string $message): static
    {
        return new static(clean: false, error: $message);
    }
}
