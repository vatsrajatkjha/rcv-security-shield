<?php

namespace VendorShield\Shield\Guards\Upload;

/**
 * Canonical filename processing engine.
 *
 * Strips traversal sequences, normalizes unicode (NFKC to collapse homoglyphs),
 * removes control characters, enforces extension whitelist, and generates
 * cryptographically random storage filenames.
 */
class FilenameCanonicalizer
{
    /**
     * Unicode homoglyph map: confusable characters → ASCII equivalents.
     *
     * Covers Greek, Cyrillic, and other common confusables that attackers
     * use to create visually identical but technically different extensions.
     */
    protected const HOMOGLYPH_MAP = [
        // Greek look-alikes
        "\xCE\xB1" => 'a', // α → a
        "\xCE\xB5" => 'e', // ε → e
        "\xCE\xB7" => 'n', // η → n (visual)
        "\xCE\xBF" => 'o', // ο → o
        "\xCF\x81" => 'p', // ρ → p
        "\xCE\xA1" => 'P', // Ρ → P
        "\xCF\x87" => 'x', // χ → x
        "\xCE\x91" => 'A', // Α → A
        "\xCE\x92" => 'B', // Β → B
        "\xCE\x95" => 'E', // Ε → E
        "\xCE\x97" => 'H', // Η → H
        "\xCE\x99" => 'I', // Ι → I
        "\xCE\x9A" => 'K', // Κ → K
        "\xCE\x9C" => 'M', // Μ → M
        "\xCE\x9D" => 'N', // Ν → N
        "\xCE\x9F" => 'O', // Ο → O
        "\xCE\xA4" => 'T', // Τ → T
        "\xCE\xA5" => 'Y', // Υ → Y
        "\xCE\xA7" => 'X', // Χ → X
        "\xCE\x96" => 'Z', // Ζ → Z
        // Cyrillic look-alikes
        "\xD0\xB0" => 'a', // а → a
        "\xD0\xB5" => 'e', // е → e
        "\xD0\xBE" => 'o', // о → o
        "\xD1\x80" => 'p', // р → p
        "\xD1\x81" => 'c', // с → c
        "\xD1\x83" => 'y', // у → y
        "\xD0\x90" => 'A', // А → A
        "\xD0\x92" => 'B', // В → B
        "\xD0\x95" => 'E', // Е → E
        "\xD0\x9D" => 'H', // Н → H
        "\xD0\x9A" => 'K', // К → K
        "\xD0\x9C" => 'M', // М → M
        "\xD0\x9E" => 'O', // О → O
        "\xD0\xA0" => 'P', // Р → P
        "\xD0\xA1" => 'C', // С → C
        "\xD0\xA2" => 'T', // Т → T
        "\xD0\xa5" => 'X', // Х → X
        // Latin extended / special
        "\xC4\xB1" => 'i', // ı → i (dotless i)
        "\xC5\xBF" => 's', // ſ → s (long s)
    ];

    /**
     * Canonicalize a filename for security analysis.
     *
     * This returns the normalized, ASCII-safe version of the filename
     * for use in extension checks and pattern matching. It does NOT
     * generate the storage filename — use generateStorageFilename() for that.
     *
     * @return string The canonicalized filename.
     */
    public function canonicalize(string $filename): string
    {
        // 1. URL decode (handles %XX sequences in filenames)
        $name = rawurldecode($filename);
        $name = rawurldecode($name); // Double decode

        // 2. Remove null bytes
        $name = str_replace(["\0", '%00'], '', $name);

        // 3. Unicode NFKC normalization via homoglyph map
        $name = $this->normalizeHomoglyphs($name);

        // 4. Remove control characters (0x00-0x1F, 0x7F-0x9F)
        $name = preg_replace('/[\x00-\x1F\x7F-\x9F]/', '', $name);

        // 5. Strip path traversal sequences
        $name = $this->stripTraversal($name);

        // 6. Remove trailing dots and spaces (Windows bypass)
        $name = rtrim($name, ". \t");

        // 7. Get basename only (strip any remaining directory components)
        $name = basename($name);

        return $name;
    }

    /**
     * Extract the true extension from a canonicalized filename.
     * Handles multi-dot filenames and returns the final extension.
     *
     * @return string The lowercase extension (without dot), or empty string.
     */
    public function extractExtension(string $canonicalizedFilename): string
    {
        $parts = explode('.', $canonicalizedFilename);

        if (count($parts) < 2) {
            return ''; // No extension
        }

        return strtolower(end($parts));
    }

    /**
     * Extract ALL extensions from a filename for multi-extension attack detection.
     *
     * @return array<string> All extensions, lowercased.
     */
    public function extractAllExtensions(string $canonicalizedFilename): array
    {
        $parts = explode('.', $canonicalizedFilename);

        if (count($parts) < 2) {
            return [];
        }

        // Remove the base name part, return all extension segments
        array_shift($parts);

        return array_map('strtolower', $parts);
    }

    /**
     * Check if a filename has no extension (extensionless).
     */
    public function isExtensionless(string $canonicalizedFilename): bool
    {
        return $this->extractExtension($canonicalizedFilename) === '';
    }

    /**
     * Generate a cryptographically random storage filename.
     *
     * @param string $extension The allowed extension to use.
     * @return string Random filename like "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4.jpg"
     */
    public function generateStorageFilename(string $extension): string
    {
        $random = bin2hex(random_bytes(16));

        return $extension !== '' ? "{$random}.{$extension}" : $random;
    }

    /**
     * Replace unicode homoglyphs with their ASCII equivalents.
     */
    protected function normalizeHomoglyphs(string $input): string
    {
        // First, try PHP intl NFKC normalization if available
        if (class_exists(\Normalizer::class)) {
            $normalized = \Normalizer::normalize($input, \Normalizer::FORM_KC);
            if ($normalized !== false) {
                $input = $normalized;
            }
        }

        // Then apply our explicit homoglyph mapping for known confusables
        return strtr($input, self::HOMOGLYPH_MAP);
    }

    /**
     * Strip all forms of path traversal from filename.
     */
    protected function stripTraversal(string $name): string
    {
        // Remove ../ and ..\ in all encoded forms
        $patterns = [
            '../', '..\\',
            '%2e%2e%2f', '%2e%2e/', '..%2f',
            '%2e%2e%5c', '%2e%2e\\', '..%5c',
            '%c0%ae%c0%ae/', // Overlong UTF-8 encoding of ../
            '..%c0%af',      // Overlong UTF-8 /
            '%c1%9c',        // Overlong UTF-8 \
        ];

        $lower = strtolower($name);
        foreach ($patterns as $pattern) {
            if (str_contains($lower, $pattern)) {
                $name = str_ireplace($pattern, '', $name);
            }
        }

        // Strip any remaining directory separators
        $name = str_replace(['/', '\\'], '', $name);

        return $name;
    }
}
