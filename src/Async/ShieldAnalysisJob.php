<?php

namespace VendorShield\Shield\Async;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Events\AnalysisCompleted;
use VendorShield\Shield\Support\FailSafe;
use VendorShield\Shield\Support\Severity;

class ShieldAnalysisJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * The number of times the job may be attempted.
     */
    public int $tries = 3;

    /**
     * The number of seconds the job can run before timing out.
     */
    public int $timeout = 120;

    public function __construct(
        public readonly array $payload,
    ) {}

    public function handle(AuditLogger $audit): void
    {
        $guard = $this->payload['guard'] ?? 'unknown';

        try {
            $result = $this->analyze();

            // Log the analysis result
            if (! $result->clean) {
                FailSafe::dispatch(fn () => $audit->analysisEvent($guard, $result));
            }

            FailSafe::dispatch(fn () => event(new AnalysisCompleted($guard, $result)));
        } catch (\Throwable $e) {
            // Log failure but don't let it disrupt the queue
            FailSafe::dispatch(fn () => $audit->analysisError($guard, $e->getMessage()));
        }
    }

    /**
     * Perform deep analysis on the payload.
     */
    protected function analyze(): AnalysisResult
    {
        $guard = $this->payload['guard'] ?? 'unknown';

        // Guard-specific deep analysis
        return match ($guard) {
            'http' => $this->analyzeHttp(),
            'upload' => $this->analyzeUpload(),
            default => AnalysisResult::clean($guard),
        };
    }

    /**
     * Deep HTTP request analysis.
     */
    protected function analyzeHttp(): AnalysisResult
    {
        $findings = [];

        // Analyze URL patterns
        $url = $this->payload['url'] ?? '';
        if (preg_match('/\.(env|git|bak|sql|log|config)(\?|$)/i', $url)) {
            $findings[] = [
                'type' => 'sensitive_file_probe',
                'detail' => 'Request targeting sensitive file path',
            ];
        }

        // Analyze user agent for known scanners
        $ua = $this->payload['user_agent'] ?? '';
        $scannerPatterns = ['sqlmap', 'nikto', 'nmap', 'burpsuite', 'dirbuster', 'gobuster', 'wpscan'];
        foreach ($scannerPatterns as $scanner) {
            if (stripos($ua, $scanner) !== false) {
                $findings[] = [
                    'type' => 'scanner_detected',
                    'detail' => "Known scanner user agent: {$scanner}",
                ];
            }
        }

        if (! empty($findings)) {
            return AnalysisResult::threat(
                driver: 'http_deep',
                summary: 'Suspicious request patterns detected',
                severity: Severity::High,
                findings: $findings,
            );
        }

        return AnalysisResult::clean('http_deep');
    }

    protected function analyzeUpload(): AnalysisResult
    {
        $findings = [];
        $filename = $this->payload['filename'] ?? '';
        $path = $this->payload['path'] ?? '';

        // Analyze filename patterns
        if (preg_match('/\.(php|phtml|php[3-7]|phar|shtml)\./i', $filename)) {
            $findings[] = [
                'type' => 'double_extension',
                'detail' => "Suspicious double extension: {$filename}",
            ];
        }

        // Check file hash against known malicious hashes (extensible)
        $hash = $this->payload['hash'] ?? '';
        if (! empty($hash) && $this->isKnownMaliciousHash($hash)) {
            $findings[] = [
                'type' => 'known_malware',
                'detail' => 'File hash matches known malware signature',
            ];
        }

        // Deep Archive Inspection (Zip Slip / Archive Bomb)
        if (! empty($path) && file_exists($path) && preg_match('/\.(zip|tar|gz|bz2|rar)$/i', $filename)) {
            $archiveFindings = $this->inspectArchive($path);
            $findings = array_merge($findings, $archiveFindings);
        }

        if (! empty($findings)) {
            return AnalysisResult::threat(
                driver: 'upload_deep',
                summary: 'Suspicious upload detected',
                severity: Severity::Critical,
                findings: $findings,
            );
        }

        return AnalysisResult::clean('upload_deep');
    }

    /**
     * Inspect archive manifests for Zip Slip or Archive Bombs.
     */
    protected function inspectArchive(string $path): array
    {
        $findings = [];

        if (! class_exists('ZipArchive')) {
            return $findings;
        }

        $zip = new \ZipArchive;
        if ($zip->open($path) === true) {
            $numFiles = $zip->numFiles;

            // Archive Bomb: Too many entries
            if ($numFiles > 10000) {
                $findings[] = [
                    'type' => 'archive_bomb',
                    'detail' => "Archive contains suspicious number of files: {$numFiles}",
                ];
            }

            for ($i = 0; $i < $numFiles; $i++) {
                $stat = $zip->statIndex($i);
                if (! $stat) {
                    continue;
                }

                $name = $stat['name'];

                // Zip Slip: Path traversal in archive manifest
                if (preg_match('/(?:(?:\.\.+)[\\\\\/]|(?:[\\\\\/]+\.\.+))/i', $name)) {
                    $findings[] = [
                        'type' => 'zip_slip',
                        'detail' => "Archive manifest contains path traversal: {$name}",
                    ];
                    break; // Only need to detect one
                }

                // High compression ratio (Archive Bomb)
                if ($stat['size'] > 0 && $stat['comp_size'] > 0) {
                    $ratio = $stat['size'] / $stat['comp_size'];
                    // If a file decompresses to 1000x its compressed size, it's highly suspicious
                    if ($ratio > 1000 && $stat['size'] > 104857600) { // >100MB uncompressed
                        $findings[] = [
                            'type' => 'archive_bomb',
                            'detail' => "Archive contains highly compressed bomb logic: {$name}",
                        ];
                        break;
                    }
                }
            }

            $zip->close();
        }

        return $findings;
    }

    /**
     * Check against known malicious file hashes.
     * In production, this would query a threat intelligence database.
     */
    protected function isKnownMaliciousHash(string $hash): bool
    {
        // Extensible: integrate with VirusTotal, cloud intelligence, etc.
        return false;
    }

    /**
     * Determine the queue this job should run on.
     */
    public function tags(): array
    {
        return ['shield', 'analysis', $this->payload['guard'] ?? 'unknown'];
    }
}
