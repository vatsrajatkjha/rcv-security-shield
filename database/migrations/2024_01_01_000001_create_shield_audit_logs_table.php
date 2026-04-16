<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('shield_audit_logs', function (Blueprint $table) {
            $table->id();
            $table->string('tenant_id')->nullable()->index();
            $table->string('guard', 50)->index();
            $table->string('event_type', 100)->index();
            $table->string('severity', 20)->index();
            $table->json('payload')->nullable();
            $table->json('context')->nullable();
            $table->timestamp('created_at')->useCurrent()->index();

            // Composite index for efficient querying
            $table->index(['guard', 'severity', 'created_at']);
            $table->index(['tenant_id', 'guard', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('shield_audit_logs');
    }
};
