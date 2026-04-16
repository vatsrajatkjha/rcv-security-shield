<?php

namespace VendorShield\Shield\Guards\Upload;

/**
 * Expanded binary magic byte signature validation.
 *
 * Validates file content against known file type signatures.
 * Supports cross-validation: declared MIME vs detected MIME vs magic bytes.
 * Fail-closed: unknown/unmatched signatures are rejected.
 */
class MagicByteValidator
{
    /**
     * Extended magic byte signature database.
     * Format: MIME type => [[offset, bytes], ...]
     */
    protected const SIGNATURES = [
        // Images
        'image/jpeg' => [[0, "\xFF\xD8\xFF"]],
        'image/png' => [[0, "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"]],
        'image/gif' => [[0, 'GIF87a'], [0, 'GIF89a']],
        'image/webp' => [[0, 'RIFF']], // + "WEBP" at offset 8
        'image/bmp' => [[0, 'BM']],
        'image/tiff' => [[0, "II\x2A\x00"], [0, "MM\x00\x2A"]],
        'image/x-icon' => [[0, "\x00\x00\x01\x00"]],
        'image/svg+xml' => [], // Text-based, validated by content scanner

        // Documents
        'application/pdf' => [[0, '%PDF']],

        // Archives (also covers DOCX, XLSX, PPTX which use ZIP container)
        'application/zip' => [[0, "PK\x03\x04"], [0, "PK\x05\x06"]],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => [[0, "PK\x03\x04"]],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => [[0, "PK\x03\x04"]],
        'application/vnd.openxmlformats-officedocument.presentationml.presentation' => [[0, "PK\x03\x04"]],

        // Legacy Office (OLE2 Compound Binary)
        'application/msword' => [[0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"]],
        'application/vnd.ms-excel' => [[0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"]],

        // Audio
        'audio/mpeg' => [[0, "\xFF\xFB"], [0, "\xFF\xF3"], [0, "\xFF\xF2"], [0, 'ID3']],
        'audio/wav' => [[0, 'RIFF']], // + "WAVE" at offset 8
        'audio/ogg' => [[0, 'OggS']],

        // Video
        'video/mp4' => [[4, 'ftyp']], // Offset 4 for MP4 ftyp atom
        'video/webm' => [[0, "\x1A\x45\xDF\xA3"]],
        'video/avi' => [[0, 'RIFF']], // + "AVI " at offset 8

        // Text (no magic bytes — validated by content scanner)
        'text/plain' => [],
        'text/csv' => [],
    ];

    /**
     * MIME types that are text-based and don't have magic bytes.
     */
    protected const TEXT_MIMES = [
        'text/plain', 'text/csv', 'text/html', 'text/xml',
        'image/svg+xml', 'application/json', 'application/xml',
    ];

    /**
     * Validate file magic bytes against its declared or detected MIME type.
     *
     * @param  string  $filePath  Path to the uploaded file.
     * @param  string  $declaredMime  The MIME type as declared by the client or detected by finfo.
     * @param  bool  $failClosed  If true, reject files with no known signature.
     */
    public function validate(string $filePath, string $declaredMime, bool $failClosed = true): MagicByteResult
    {
        if (! is_readable($filePath)) {
            return MagicByteResult::fail('File is not readable for magic byte validation');
        }

        // Text-based formats don't have magic bytes
        if (in_array($declaredMime, self::TEXT_MIMES, true)) {
            return MagicByteResult::pass($declaredMime);
        }

        // Read file header (first 16 bytes is sufficient for all known signatures)
        $header = @file_get_contents($filePath, false, null, 0, 16);
        if ($header === false || strlen($header) < 2) {
            return MagicByteResult::fail('Failed to read file header');
        }

        // Check declared MIME against known signatures
        if (isset(self::SIGNATURES[$declaredMime]) && ! empty(self::SIGNATURES[$declaredMime])) {
            foreach (self::SIGNATURES[$declaredMime] as [$offset, $signature]) {
                if (substr($header, $offset, strlen($signature)) === $signature) {
                    return MagicByteResult::pass($declaredMime);
                }
            }

            return MagicByteResult::mismatch(
                "Magic bytes do not match declared MIME type: {$declaredMime}",
                $declaredMime,
                $this->detectMimeFromBytes($header),
            );
        }

        // Unknown MIME: try to detect actual type from bytes
        $detectedMime = $this->detectMimeFromBytes($header);

        if ($detectedMime !== null && $detectedMime !== $declaredMime) {
            return MagicByteResult::mismatch(
                "Detected MIME ({$detectedMime}) does not match declared ({$declaredMime})",
                $declaredMime,
                $detectedMime,
            );
        }

        if ($failClosed && $detectedMime === null && ! isset(self::SIGNATURES[$declaredMime])) {
            return MagicByteResult::fail("Unknown file type with no signature match: {$declaredMime}");
        }

        return MagicByteResult::pass($detectedMime ?? $declaredMime);
    }

    /**
     * Detect MIME type from magic bytes.
     */
    public function detectMimeFromBytes(string $header): ?string
    {
        foreach (self::SIGNATURES as $mime => $signatures) {
            if (empty($signatures)) {
                continue;
            }
            foreach ($signatures as [$offset, $signature]) {
                if (substr($header, $offset, strlen($signature)) === $signature) {
                    return $mime;
                }
            }
        }

        return null;
    }
}

/**
 * Result of magic byte validation.
 */
class MagicByteResult
{
    public function __construct(
        public readonly bool $valid,
        public readonly string $message,
        public readonly ?string $declaredMime = null,
        public readonly ?string $detectedMime = null,
        public readonly bool $mismatch = false,
    ) {}

    public static function pass(string $mime): static
    {
        return new static(valid: true, message: 'Magic bytes valid', declaredMime: $mime, detectedMime: $mime);
    }

    public static function fail(string $message): static
    {
        return new static(valid: false, message: $message);
    }

    public static function mismatch(string $message, string $declaredMime, ?string $detectedMime): static
    {
        return new static(
            valid: false,
            message: $message,
            declaredMime: $declaredMime,
            detectedMime: $detectedMime,
            mismatch: true,
        );
    }
}
