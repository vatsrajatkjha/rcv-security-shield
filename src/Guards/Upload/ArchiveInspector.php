<?php

namespace VendorShield\Shield\Guards\Upload;

class ArchiveInspector
{
    protected const ARCHIVE_EXTENSIONS = [
        'zip', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'rar', '7z',
    ];

    /**
     * @return array{archive: bool, blocked: bool, message?: string, metadata?: array<string, mixed>}
     */
    public function inspect(string $path, string $extension, int $maxEntries, int $maxUncompressedBytes, bool $blockArchives): array
    {
        $extension = strtolower($extension);

        if (! in_array($extension, self::ARCHIVE_EXTENSIONS, true)) {
            return ['archive' => false, 'blocked' => false];
        }

        if ($blockArchives) {
            return [
                'archive' => true,
                'blocked' => true,
                'message' => 'Archive uploads are blocked by security policy',
                'metadata' => ['extension' => $extension],
            ];
        }

        if ($extension !== 'zip') {
            return [
                'archive' => true,
                'blocked' => true,
                'message' => 'Archive type requires unsupported synchronous inspection',
                'metadata' => ['extension' => $extension],
            ];
        }

        if (! class_exists(\ZipArchive::class)) {
            return [
                'archive' => true,
                'blocked' => true,
                'message' => 'Zip inspection is unavailable on this platform',
                'metadata' => ['extension' => $extension],
            ];
        }

        $zip = new \ZipArchive();
        $opened = $zip->open($path);

        if ($opened !== true) {
            return [
                'archive' => true,
                'blocked' => true,
                'message' => 'Unable to inspect uploaded archive',
                'metadata' => ['extension' => $extension, 'open_result' => $opened],
            ];
        }

        $entryCount = $zip->numFiles;
        if ($entryCount > $maxEntries) {
            $zip->close();

            return [
                'archive' => true,
                'blocked' => true,
                'message' => 'Archive exceeds maximum allowed entry count',
                'metadata' => ['entries' => $entryCount, 'max_entries' => $maxEntries],
            ];
        }

        $totalUncompressedBytes = 0;

        for ($i = 0; $i < $entryCount; $i++) {
            $stat = $zip->statIndex($i);
            if (! is_array($stat)) {
                continue;
            }

            $name = (string) ($stat['name'] ?? '');
            $size = (int) ($stat['size'] ?? 0);
            $compressed = (int) ($stat['comp_size'] ?? 0);

            if ($this->containsTraversal($name)) {
                $zip->close();

                return [
                    'archive' => true,
                    'blocked' => true,
                    'message' => 'Archive contains a path traversal entry',
                    'metadata' => ['entry' => $name],
                ];
            }

            $totalUncompressedBytes += max(0, $size);
            if ($totalUncompressedBytes > $maxUncompressedBytes) {
                $zip->close();

                return [
                    'archive' => true,
                    'blocked' => true,
                    'message' => 'Archive exceeds maximum uncompressed size budget',
                    'metadata' => [
                        'uncompressed_bytes' => $totalUncompressedBytes,
                        'max_uncompressed_bytes' => $maxUncompressedBytes,
                    ],
                ];
            }

            if ($compressed > 0 && $size > 0) {
                $ratio = $size / $compressed;
                if ($ratio > 1000 && $size > 10485760) {
                    $zip->close();

                    return [
                        'archive' => true,
                        'blocked' => true,
                        'message' => 'Archive contains a suspicious compression ratio',
                        'metadata' => ['entry' => $name, 'ratio' => $ratio],
                    ];
                }
            }
        }

        $zip->close();

        return [
            'archive' => true,
            'blocked' => false,
            'metadata' => [
                'entries' => $entryCount,
                'uncompressed_bytes' => $totalUncompressedBytes,
            ],
        ];
    }

    protected function containsTraversal(string $name): bool
    {
        return (bool) preg_match('/(^|[\/\\\\])\.\.([\/\\\\]|$)/', $name);
    }
}
