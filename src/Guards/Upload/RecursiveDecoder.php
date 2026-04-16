<?php

namespace VendorShield\Shield\Guards\Upload;

/**
 * Recursive multi-layer encoding detection and decoding engine.
 *
 * Detects and decodes: URL encoding, HTML entities, base64, gzip/zlib,
 * hex sequences, and UTF-7. Loops until content stabilizes (SHA-256
 * comparison between iterations) or max depth is reached.
 */
class RecursiveDecoder
{
    protected int $maxDepth;

    public function __construct(int $maxDepth = 5)
    {
        $this->maxDepth = $maxDepth;
    }

    /**
     * Recursively decode content through all encoding layers.
     *
     * @return string The fully decoded content.
     */
    public function decode(string $content): string
    {
        $previousHash = '';

        for ($i = 0; $i < $this->maxDepth; $i++) {
            $content = $this->decodeLayer($content);

            $currentHash = hash('sha256', $content);
            if ($currentHash === $previousHash) {
                break; // Content stabilized — no more decoding possible
            }
            $previousHash = $currentHash;
        }

        return $content;
    }

    /**
     * Apply all decoding strategies in a single pass.
     */
    protected function decodeLayer(string $content): string
    {
        // 1. URL decode (handles %XX sequences)
        $content = $this->urlDecode($content);

        // 2. HTML entity decode
        $content = $this->htmlDecode($content);

        // 3. UTF-7 decode (must come before base64 to avoid false positives)
        $content = $this->utf7Decode($content);

        // 4. Hex sequence decode (\xNN)
        $content = $this->hexDecode($content);

        // 5. Base64 decode (only if detected)
        $content = $this->base64Decode($content);

        // 6. Gzip/zlib inflate (only if detected)
        $content = $this->gzipDecode($content);

        return $content;
    }

    /**
     * Recursive URL decoding to handle multi-layer encoding.
     */
    protected function urlDecode(string $content): string
    {
        $maxIterations = 10;
        $prev = '';
        $current = $content;

        for ($i = 0; $i < $maxIterations; $i++) {
            $decoded = rawurldecode($current);
            if ($decoded === $prev || $decoded === $current) {
                break;
            }
            $prev = $current;
            $current = $decoded;
        }

        return $current;
    }

    /**
     * HTML entity decoding.
     */
    protected function htmlDecode(string $content): string
    {
        return html_entity_decode($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * Detect and decode UTF-7 encoded content.
     * Pattern: +ADw- encodes '<', +AD4- encodes '>'
     */
    protected function utf7Decode(string $content): string
    {
        // Only attempt conversion if UTF-7 markers are present
        if (preg_match('/\+[A-Za-z0-9\/+]+-/', $content)) {
            $decoded = @mb_convert_encoding($content, 'UTF-8', 'UTF-7');
            if ($decoded !== false && $decoded !== $content) {
                return $decoded;
            }
        }

        return $content;
    }

    /**
     * Detect and decode hex-encoded byte sequences.
     * Handles: \xNN, 0xNN patterns
     */
    protected function hexDecode(string $content): string
    {
        // Match \xNN hex escape sequences
        if (preg_match('/\\\\x[0-9a-fA-F]{2}/', $content)) {
            $decoded = preg_replace_callback(
                '/\\\\x([0-9a-fA-F]{2})/',
                fn ($matches) => chr(hexdec($matches[1])),
                $content,
            );
            if ($decoded !== null) {
                return $decoded;
            }
        }

        return $content;
    }

    /**
     * Detect and decode base64-encoded regions.
     *
     * Only decodes if the content appears to be a valid base64 string
     * AND the decoded result contains printable/meaningful content.
     */
    protected function base64Decode(string $content): string
    {
        // Look for base64-encoded blobs (min 20 chars to avoid false positives)
        if (preg_match_all('/(?:[A-Za-z0-9+\/]{20,}={0,2})/', $content, $matches)) {
            foreach ($matches[0] as $blob) {
                $decoded = base64_decode($blob, true);
                if ($decoded === false) {
                    continue;
                }

                // Only substitute if decoded content contains suspicious patterns
                if ($this->containsSuspiciousPatterns($decoded)) {
                    $content = str_replace($blob, $decoded, $content);
                }
            }
        }

        return $content;
    }

    /**
     * Detect and inflate gzip/zlib compressed content.
     * Magic bytes: \x1f\x8b
     */
    protected function gzipDecode(string $content): string
    {
        if (strlen($content) < 2) {
            return $content;
        }

        // Check for gzip magic bytes
        if ($content[0] === "\x1f" && $content[1] === "\x8b") {
            $decoded = @gzdecode($content);
            if ($decoded !== false) {
                return $decoded;
            }
        }

        // Check for zlib compressed data (0x78 0x01/9C/DA)
        if ($content[0] === "\x78" && in_array($content[1], ["\x01", "\x9C", "\xDA"], true)) {
            $decoded = @gzuncompress($content);
            if ($decoded !== false) {
                return $decoded;
            }
        }

        return $content;
    }

    /**
     * Check if decoded content contains script/code patterns.
     */
    protected function containsSuspiciousPatterns(string $content): bool
    {
        $patterns = [
            '<?php', '<?=', '<%', '<script',
            'eval(', 'system(', 'exec(', 'shell_exec(',
            'assert(', 'passthru(', 'proc_open(', 'popen(',
            '$_GET', '$_POST', '$_REQUEST', '$_FILES',
            '__HALT_COMPILER',
        ];

        $lower = strtolower($content);
        foreach ($patterns as $pattern) {
            if (str_contains($lower, strtolower($pattern))) {
                return true;
            }
        }

        return false;
    }
}
