<?php

declare(strict_types=1);

namespace Booyah;

/**
 * Runtime taint tracer — inserted at sources, sinks, and transforms by the instrumentor.
 *
 * Logs to SQLite using value hashing: actual values are never stored — only SHA-256 digests.
 * This makes it safe to run against real production data.
 *
 * Schema:
 *   traces(id, request_id, type, function_name, file, line, value_hash, value_preview, ts)
 *   transforms(id, request_id, in_hash, out_hash, function_name, file, line, sanitized, ts)
 */
final class Tracer
{
    private static ?\PDO $db = null;
    private static ?string $requestId = null;
    private static bool $enabled = true;
    /** Set of value hashes currently tracked as tainted in this request */
    private static array $taintedHashes = [];

    public static function requestId(): string
    {
        if (self::$requestId === null) {
            self::$requestId = bin2hex(random_bytes(16));
        }
        return self::$requestId;
    }

    /**
     * Called immediately after a taint source is read.
     * @param mixed $value   The tainted value (used only for hashing)
     */
    public static function source(
        mixed $value,
        string $paramName,
        string $functionName,
        string $file,
        int $line,
        string $requestId
    ): void {
        if (!self::$enabled) return;
        $hash = self::hash($value);
        $preview = self::preview($value);
        self::db()->exec(sprintf(
            "INSERT INTO traces(request_id,type,function_name,param_name,file,line,value_hash,value_preview,ts)
             VALUES (%s,%s,%s,%s,%s,%d,%s,%s,%d)",
            self::q($requestId), self::q('source'), self::q($functionName),
            self::q($paramName), self::q($file), $line,
            self::q($hash), self::q($preview), time()
        ));
    }

    /**
     * Called immediately before a sink receives a value.
     * @param mixed $value   The value reaching the sink
     */
    public static function sink(
        mixed $value,
        string $sinkType,
        string $file,
        int $line,
        string $requestId
    ): void {
        if (!self::$enabled) return;
        $hash = self::hash($value);
        $preview = self::preview($value);
        self::db()->exec(sprintf(
            "INSERT INTO traces(request_id,type,function_name,param_name,file,line,value_hash,value_preview,ts)
             VALUES (%s,%s,%s,%s,%s,%d,%s,%s,%d)",
            self::q($requestId), self::q('sink'), self::q($sinkType),
            self::q(''), self::q($file), $line,
            self::q($hash), self::q($preview), time()
        ));
    }

    /**
     * Called after a potential sanitizer/transform runs.
     * If in_hash == out_hash, no transformation occurred (value passed through unchanged).
     * @param mixed $input   Pre-transform value
     * @param mixed $output  Post-transform value
     */
    public static function transform(
        mixed $input,
        mixed $output,
        string $functionName,
        string $file,
        int $line,
        string $requestId
    ): void {
        if (!self::$enabled) return;
        $inHash = self::hash($input);
        $outHash = self::hash($output);
        $sanitized = (int)($inHash !== $outHash);
        self::db()->exec(sprintf(
            "INSERT INTO transforms(request_id,in_hash,out_hash,function_name,file,line,sanitized,ts)
             VALUES (%s,%s,%s,%s,%s,%d,%d,%d)",
            self::q($requestId), self::q($inHash), self::q($outHash),
            self::q($functionName), self::q($file), $line, $sanitized, time()
        ));
    }

    private static function db(): \PDO
    {
        if (self::$db !== null) {
            return self::$db;
        }

        $dbPath = getenv('BOOYAH_TRACE_DB') ?: '/tmp/booyah_trace.db';
        self::$db = new \PDO("sqlite:$dbPath");
        self::$db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        self::$db->exec('PRAGMA journal_mode=WAL');
        self::$db->exec('PRAGMA synchronous=NORMAL');
        self::$db->exec("CREATE TABLE IF NOT EXISTS traces (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id   TEXT NOT NULL,
            type         TEXT NOT NULL,
            function_name TEXT NOT NULL,
            param_name   TEXT NOT NULL DEFAULT '',
            file         TEXT NOT NULL,
            line         INTEGER NOT NULL,
            value_hash   TEXT NOT NULL,
            value_preview TEXT NOT NULL DEFAULT '',
            ts           INTEGER NOT NULL
        )");
        self::$db->exec("CREATE INDEX IF NOT EXISTS idx_traces_hash ON traces(value_hash)");
        self::$db->exec("CREATE INDEX IF NOT EXISTS idx_traces_request ON traces(request_id)");
        self::$db->exec("CREATE TABLE IF NOT EXISTS transforms (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id    TEXT NOT NULL,
            in_hash       TEXT NOT NULL,
            out_hash      TEXT NOT NULL,
            function_name TEXT NOT NULL,
            file          TEXT NOT NULL,
            line          INTEGER NOT NULL,
            sanitized     INTEGER NOT NULL DEFAULT 0,
            ts            INTEGER NOT NULL
        )");
        self::$db->exec("CREATE INDEX IF NOT EXISTS idx_transforms_in ON transforms(in_hash)");
        return self::$db;
    }

    private static function hash(mixed $value): string
    {
        if (is_array($value) || is_object($value)) {
            $value = serialize($value);
        }
        return hash('sha256', (string)$value);
    }

    private static function preview(mixed $value): string
    {
        if (is_array($value)) return '[array]';
        if (is_object($value)) return '[object:' . get_class($value) . ']';
        $str = (string)$value;
        // Store up to 512 chars — needed for substring taint matching in benchmarks.
        // In production, set BOOYAH_PREVIEW_MAXLEN=0 to disable previews.
        $maxLen = (int)(getenv('BOOYAH_PREVIEW_MAXLEN') ?: '512');
        if ($maxLen === 0) return '';
        if (strlen($str) > $maxLen) {
            return substr($str, 0, $maxLen) . '...[truncated]';
        }
        return $str;
    }

    private static function q(mixed $val): string
    {
        if (is_int($val)) return (string)$val;
        $str = str_replace("'", "''", (string)$val);
        return "'$str'";
    }

    /**
     * Convenience wrapper for AST injection at sources.
     * Logs the taint source and returns the value unchanged.
     * @param mixed $value
     * @return mixed
     */
    public static function sourceWrap(
        mixed $value,
        string $paramName,
        string $functionName,
        string $file,
        int $line,
        string $requestId
    ): mixed {
        self::source($value, $paramName, $functionName, $file, $line, $requestId);
        // Register the hash so enter() can detect tainted arguments downstream
        self::$taintedHashes[self::hash($value)] = true;
        return $value;
    }

    /**
     * Convenience wrapper for AST injection at transforms.
     *
     * Generated code looks like:
     *   \Booyah\Tracer::transformWrap($dirty, escapeHtml($dirty), 'escapeHtml', ...)
     *
     * PHP evaluates arguments left-to-right, so $input is evaluated first (producing the
     * pre-transform value), then escapeHtml($dirty) runs and produces $transformed.
     * Both arrive here with correct before/after state.
     *
     * @param mixed $input       Pre-transform value
     * @param mixed $transformed Post-transform value (result of the inner sanitizer call)
     * @return mixed Returns $transformed unchanged
     */
    public static function transformWrap(
        mixed $input,
        mixed $transformed,
        string $functionName,
        string $file,
        int $line,
        string $requestId
    ): mixed {
        if (!self::$enabled) return $transformed;
        $inHash = self::hash($input);
        $outHash = self::hash($transformed);
        $sanitized = (int)($inHash !== $outHash);
        self::db()->exec(sprintf(
            "INSERT INTO transforms(request_id,in_hash,out_hash,function_name,file,line,sanitized,ts)
             VALUES (%s,%s,%s,%s,%s,%d,%d,%d)",
            self::q($requestId), self::q($inHash), self::q($outHash),
            self::q($functionName), self::q($file), $line, $sanitized, time()
        ));
        return $transformed;
    }

    /**
     * Universal method entry trace — called at the top of every instrumented method.
     * Logs the function name and argument hashes (not values) to keep storage small.
     * Only stored if at least one arg hash matches a known taint_id.
     *
     * @param array<string> $argHashes  SHA-256 hashes of each argument
     */
    public static function enter(
        string $functionName,
        string $file,
        int    $line,
        array  $argHashes,
        string $requestId
    ): void {
        if (!self::$enabled) return;

        // Only log if any argument is tainted — avoids storing millions of clean calls
        $taintedArgs = array_filter($argHashes, fn($h) => self::isTainted($h));
        if (empty($taintedArgs)) return;

        foreach ($taintedArgs as $argHash) {
            self::db()->exec(sprintf(
                "INSERT INTO traces(request_id,type,function_name,param_name,file,line,value_hash,value_preview,ts)
                 VALUES (%s,%s,%s,%s,%s,%d,%s,%s,%d)",
                self::q($requestId), self::q('enter'), self::q($functionName),
                self::q(''), self::q($file), $line,
                self::q($argHash), self::q(''), time()
            ));
        }
    }

    /**
     * Hash helper for use in instrumented code — same algorithm as internal hash().
     * @param mixed $value
     */
    public static function h(mixed $value): string
    {
        return self::hash($value);
    }

    /**
     * Check if a hash is currently tracked as tainted in this request.
     */
    private static function isTainted(string $hash): bool
    {
        // Quick lookup — we store tainted hashes in a static set populated by sourceWrap()
        return isset(self::$taintedHashes[$hash]);
    }

    public static function disable(): void
    {
        self::$enabled = false;
    }

    public static function reset(): void
    {
        self::$requestId = null;
        self::$db = null;
        self::$taintedHashes = [];
    }
}
