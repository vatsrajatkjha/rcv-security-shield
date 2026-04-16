<?php

namespace VendorShield\Shield\Tests\Unit\Async;

use Illuminate\Support\Facades\Event;
use VendorShield\Shield\Async\ShieldAnalysisJob;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Events\AnalysisCompleted;
use VendorShield\Shield\Tests\TestCase;

class ShieldAnalysisJobTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Event::fake();
    }

    public function test_it_dispatches_clean_analysis_for_normal_upload()
    {
        $job = new ShieldAnalysisJob([
            'guard' => 'upload',
            'filename' => 'photo.jpg',
            'mime' => 'image/jpeg',
            'size' => 1024,
            'hash' => 'dummy',
        ]);

        $audit = $this->app->make(AuditLogger::class);
        $job->handle($audit);

        Event::assertDispatched(AnalysisCompleted::class, function ($event) {
            return $event->result->clean === true;
        });
    }

    public function test_it_detects_zip_slip_in_archives()
    {
        if (! class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive extension not available.');
        }

        $tmp = tempnam(sys_get_temp_dir(), 'zip');
        $zip = new \ZipArchive;
        $zip->open($tmp, \ZipArchive::CREATE);
        $zip->addFromString('../../../../etc/passwd', 'fake content');
        $zip->close();

        $job = new ShieldAnalysisJob([
            'guard' => 'upload',
            'filename' => 'malicious.zip',
            'path' => $tmp,
        ]);

        $audit = $this->app->make(AuditLogger::class);
        $job->handle($audit);

        Event::assertDispatched(AnalysisCompleted::class, function ($event) {
            return $event->result->clean === false
                && str_contains($event->result->findings[0]['type'], 'zip_slip');
        });

        unlink($tmp);
    }

    public function test_it_detects_archive_bomb_by_compression_ratio()
    {
        if (! class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive extension not available.');
        }

        $tmp = tempnam(sys_get_temp_dir(), 'zip');
        $zip = new \ZipArchive;
        $zip->open($tmp, \ZipArchive::CREATE);
        // Add 101MB of highly compressible data (A's)
        $zip->addFromString('bomb.txt', str_repeat('A', 104857601));
        $zip->close();

        $job = new ShieldAnalysisJob([
            'guard' => 'upload',
            'filename' => 'bomb.zip',
            'path' => $tmp,
        ]);

        $audit = $this->app->make(AuditLogger::class);
        $job->handle($audit);

        Event::assertDispatched(AnalysisCompleted::class, function ($event) {
            return $event->result->clean === false
                && str_contains($event->result->findings[0]['type'], 'archive_bomb');
        });

        unlink($tmp);
    }
}
