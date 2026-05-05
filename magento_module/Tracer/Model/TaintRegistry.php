<?php
declare(strict_types=1);

namespace Booyah\Tracer\Model;

/**
 * Per-request in-memory taint identity registry.
 *
 * Maps value_hash → taint_id for the current request.
 * Written by the PHP instrumentor's sourceWrap() calls (via Tracer::source()).
 * Read by the DB/cache/session plugins to detect tainted values at persistence boundaries.
 *
 * Cross-request propagation is handled by TaintLogger::lookupPersistedTaint().
 */
class TaintRegistry
{
    private static string $requestId = '';
    private static string $runId = '';
    private static string $role = 'anonymous';

    /** value_hash → taint_id */
    private static array $hashToTaintId = [];

    /** taint_id → {source_type, param_name, file, line} */
    private static array $taintMeta = [];

    /** taint_ids that were propagated from a previous request (cross-request) */
    private static array $crossRequestTaints = [];

    public static function requestId(): string
    {
        if (self::$requestId === '') {
            self::$requestId = bin2hex(random_bytes(16));
        }
        return self::$requestId;
    }

    public static function runId(): string
    {
        if (self::$runId === '') {
            self::$runId = getenv('BOOYAH_RUN_ID') ?: 'unset';
        }
        return self::$runId;
    }

    public static function role(): string
    {
        return self::$role;
    }

    public static function setRole(string $role): void
    {
        self::$role = $role;
    }

    /**
     * Register a taint source. Called by PHP instrumentor's sourceWrap().
     */
    public static function register(
        string $taintId,
        string $valueHash,
        string $sourceType,
        string $paramName,
        string $file,
        int    $line
    ): void {
        self::$hashToTaintId[$valueHash] = $taintId;
        self::$taintMeta[$taintId] = [
            'source_type' => $sourceType,
            'param_name'  => $paramName,
            'file'        => $file,
            'line'        => $line,
        ];
    }

    /**
     * Propagate a taint_id arriving from a previous request (DB/cache/session read).
     */
    public static function propagate(string $taintId, string $valueHash, string $origin): void
    {
        self::$hashToTaintId[$valueHash] = $taintId;
        self::$crossRequestTaints[$taintId] = $origin;
        if (!isset(self::$taintMeta[$taintId])) {
            self::$taintMeta[$taintId] = [
                'source_type' => 'DB_READ',
                'param_name'  => '',
                'file'        => '',
                'line'        => 0,
            ];
        }
    }

    /**
     * Look up a taint_id by the SHA-256 hash of a value.
     */
    public static function lookup(string $valueHash): ?string
    {
        return self::$hashToTaintId[$valueHash] ?? null;
    }

    public static function meta(string $taintId): array
    {
        return self::$taintMeta[$taintId] ?? [];
    }

    public static function isCrossRequest(string $taintId): bool
    {
        return isset(self::$crossRequestTaints[$taintId]);
    }

    public static function allTaintIds(): array
    {
        return array_values(array_unique(array_values(self::$hashToTaintId)));
    }

    /**
     * True if any cross-request taints have been propagated into this request.
     * Used by DB/cache/session read plugins as a cheap early-exit guard.
     */
    public static function hasCrossRequestTaints(): bool
    {
        return !empty(self::$crossRequestTaints);
    }

    public static function reset(): void
    {
        self::$requestId       = '';
        self::$hashToTaintId   = [];
        self::$taintMeta       = [];
        self::$crossRequestTaints = [];
    }
}
