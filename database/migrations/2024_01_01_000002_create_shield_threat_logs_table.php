<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('shield_threat_logs', function (Blueprint $table) {
            $table->id();
            $table->string('tenant_id')->nullable()->index();
            $table->string('guard', 50)->index();
            $table->string('threat_type', 100)->index();
            $table->string('fingerprint')->nullable()->index();
            $table->json('request_data')->nullable();
            $table->boolean('resolved')->default(false)->index();
            $table->timestamp('created_at')->useCurrent()->index();
            $table->timestamp('resolved_at')->nullable();

            // Composite indexes
            $table->index(['guard', 'threat_type', 'created_at']);
            $table->index(['tenant_id', 'resolved', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('shield_threat_logs');
    }
};
