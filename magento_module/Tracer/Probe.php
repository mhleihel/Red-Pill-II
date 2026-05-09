<?php
declare(strict_types=1);

namespace Booyah\Tracer;

/**
 * Runtime taint probe — injected by AST instrumentation tool.
 *
 * All methods are static to avoid object instantiation overhead.
 * Only writes to DB when BOOYAH_TAINT_ENABLED=1 and a tainted value
 * is detected. Zero overhead on clean (un-tainted) values.
 *
 * DB path: env BOOYAH_TRACE_DB, default /Users/mhleihel/Desktop/Booyah/results/runtime_trace.db
 */
class Probe
{
    private const PREFIXES    = ['BSYH', 'bSRC'];
    private const DB_PATH_ENV = 'BOOYAH_TRACE_DB';
    private const DEFAULT_DB  = '/Users/mhleihel/Desktop/Booyah/results/runtime_trace.db';

    private static ?\PDO $pdo          = null;
    private static string $runId       = '';
    private static string $requestId   = '';
    private static string $traceNonce  = '';
    private static int    $seqNo       = 0;
    private static bool   $enabled     = false;
    private static bool   $dbReady     = false;

    /** value_hash => taint_id for the current request */
    private static array $registry = [];

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /**
     * Call once at process startup (e.g. from a Magento bootstrap plugin).
     * Fails fast if DB is not writable.
     */
    public static function startup(): void
    {
        self::$enabled = (getenv('BOOYAH_TAINT_ENABLED') === '1');
        if (!self::$enabled) {
            return;
        }

        $dbPath = getenv(self::DB_PATH_ENV) ?: self::DEFAULT_DB;
        $dir    = dirname($dbPath);

        if (!is_dir($dir) || !is_writable($dir)) {
            throw new \RuntimeException(
                'Booyah\\Tracer\\Probe: DB directory not writable: ' . $dir
            );
        }

        self::$pdo = new \PDO('sqlite:' . $dbPath);
        self::$pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        self::$pdo->exec('PRAGMA foreign_keys = ON');
        self::$pdo->exec('PRAGMA journal_mode = WAL');
        self::$pdo->exec('PRAGMA synchronous = NORMAL');
        self::$pdo->exec('PRAGMA cache_size = -4000'); // 4 MB page cache

        self::$runId  = getenv('BOOYAH_RUN_ID') ?: ('run-' . bin2hex(random_bytes(8)));
        self::$dbReady = true;
    }

    /**
     * Call at the beginning of each HTTP request (e.g. FrontController plugin).
     */
    public static function initRequest(
        string $httpMethod,
        string $url,
        string $actorContext = 'unknown'
    ): void {
        if (!self::$enabled || !self::$dbReady) {
            return;
        }

        self::$requestId  = self::uuid();
        self::$traceNonce = bin2hex(random_bytes(8));
        self::$seqNo      = 0;
        self::$registry   = [];

        // Upsert trace_run row (idempotent across requests in same run).
        self::$pdo->prepare(
            'INSERT OR IGNORE INTO trace_runs
             (run_id, started_at, component_namespace, component_root, actor_scope)
             VALUES (?, ?, ?, ?, ?)'
        )->execute([
            self::$runId,
            self::now(),
            'Magento\\Review',
            'app/code/Magento/Review/',
            $actorContext,
        ]);

        self::$pdo->prepare(
            'INSERT OR IGNORE INTO requests
             (request_id, run_id, trace_nonce, actor_context, http_method, url, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        )->execute([
            self::$requestId,
            self::$runId,
            self::$traceNonce,
            $actorContext,
            $httpMethod,
            $url,
            self::now(),
        ]);
    }

    /**
     * Call at the end of each HTTP request.
     */
    public static function finalizeRequest(int $statusCode): void
    {
        if (!self::$enabled || !self::$requestId) {
            return;
        }
        self::$pdo->prepare(
            'UPDATE requests SET status_code = ? WHERE request_id = ?'
        )->execute([$statusCode, self::$requestId]);

        self::$requestId = '';
        self::$registry  = [];
    }

    // ── Probe entry points (called by AST-injected code) ──────────────────

    /**
     * Injected at function/method ENTRY.
     * Records CALL_ENTER event if any argument carries taint.
     */
    public static function enter(
        string $fqn,
        array  $args,
        string $file,
        int    $line
    ): void {
        if (!self::$enabled || !self::$requestId) {
            return;
        }

        foreach ($args as $arg) {
            foreach (self::extractTainted($arg) as $value) {
                $taintId = self::ensureTaint($value);
                $nodeId  = self::ensureNode($fqn, $file, $line, 'HOP');
                self::emitEvent('CALL_ENTER', $nodeId, $taintId, $fqn, $file, $line);
            }
        }
    }

    /**
     * Injected at function/method EXIT.
     * Records CALL_EXIT event if the return value carries taint.
     *
     * Returns $returnValue unchanged so callers can use:
     *   return Probe::exit(__METHOD__, $result, __FILE__, __LINE__);
     */
    public static function exit(
        string $fqn,
        $returnValue,
        string $file,
        int    $line
    ) {
        if (self::$enabled && self::$requestId) {
            foreach (self::extractTainted($returnValue) as $value) {
                $taintId = self::ensureTaint($value);
                $nodeId  = self::ensureNode($fqn, $file, $line, 'HOP');
                self::emitEvent('CALL_EXIT', $nodeId, $taintId, $fqn, $file, $line);
            }
        }
        return $returnValue;
    }

    /**
     * Injected at known HTTP input SOURCE points.
     */
    public static function source(
        string $fqn,
        string $field,
        $value,
        string $file,
        int    $line
    ): void {
        if (!self::$enabled || !self::$requestId) {
            return;
        }
        if (!is_string($value) || !self::isTainted($value)) {
            return;
        }

        $taintId = self::ensureTaint($value, 'PV_HTTP_BODY');
        $nodeId  = self::ensureNode($fqn, $file, $line, 'SOURCE');
        self::emitEvent('SOURCE', $nodeId, $taintId, $fqn, $file, $line, ['field' => $field]);
    }

    /**
     * Injected around known sanitizer/encoder functions (TRANSFORM).
     * Detects value change, creates derived taint, records transform record.
     */
    public static function transform(
        string $fqn,
        $input,
        $output,
        string $file,
        int    $line,
        string $markAdded = ''
    ): void {
        if (!self::$enabled || !self::$requestId) {
            return;
        }
        if (!is_string($input) || !self::isTainted($input)) {
            return;
        }

        $inHash  = self::hash($input);
        $outHash = is_string($output) ? self::hash($output) : null;

        $inTaintId = self::$registry[$inHash] ?? self::ensureTaint($input);

        if ($outHash === null || $outHash === $inHash) {
            // Value unchanged (e.g. escapeHtml on a probe token with no special chars).
            // Still write a transforms row so the sanitizer registry can detect the call.
            $marksJson = $markAdded ? json_encode([$markAdded]) : '[]';
            $nodeId    = self::ensureNode($fqn, $file, $line, 'HOP');
            $eventId   = self::emitEvent('TRANSFORM', $nodeId, $inTaintId, $fqn, $file, $line,
                $markAdded ? ['mark_added' => $markAdded] : []);
            self::$pdo->prepare(
                'INSERT OR IGNORE INTO transforms
                 (transform_id, event_id, request_id, in_taint_id, out_taint_id,
                  transformer_fqn, marks_added_json)
                 VALUES (?, ?, ?, ?, ?, ?, ?)'
            )->execute([
                self::uuid(), $eventId, self::$requestId,
                $inTaintId, $inTaintId, $fqn, $marksJson,
            ]);
            return;
        }

        // Value changed — create derived taint with parent reference.
        $outTaintId = self::uuid();
        $marksJson  = $markAdded ? json_encode([$markAdded]) : '[]';

        self::$pdo->prepare(
            'INSERT OR IGNORE INTO taints
             (taint_id, parent_taint_id, taint_type, value_hash, value_len,
              marks_json, first_seen_request_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        )->execute([
            $outTaintId, $inTaintId, 'string', $outHash,
            strlen($output), $marksJson, self::$requestId, self::now(),
        ]);
        self::$registry[$outHash] = $outTaintId;

        $nodeId  = self::ensureNode($fqn, $file, $line, 'HOP');
        $eventId = self::emitEvent('TRANSFORM', $nodeId, $inTaintId, $fqn, $file, $line,
            $markAdded ? ['mark_added' => $markAdded] : []);

        self::$pdo->prepare(
            'INSERT OR IGNORE INTO transforms
             (transform_id, event_id, request_id, in_taint_id, out_taint_id,
              transformer_fqn, marks_added_json)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        )->execute([
            self::uuid(), $eventId, self::$requestId,
            $inTaintId, $outTaintId, $fqn, $marksJson,
        ]);
    }

    /**
     * Injected at DB / session / cache BOUNDARY crossings.
     */
    public static function boundary(
        string $direction,
        string $storeKind,
        string $storeIdentifier,
        $value,
        string $file,
        int    $line,
        string $entityKeyHash = ''
    ): void {
        if (!self::$enabled || !self::$requestId) {
            return;
        }
        if (!is_string($value) || !self::isTainted($value)) {
            return;
        }

        $hash    = self::hash($value);
        $taintId = self::$registry[$hash] ?? self::ensureTaint($value);
        $nodeId  = self::ensureNode($storeIdentifier, $file, $line, 'BOUNDARY');
        $evType  = $direction === 'WRITE' ? 'BOUNDARY_WRITE' : 'BOUNDARY_READ';
        $eventId = self::emitEvent($evType, $nodeId, $taintId, $storeIdentifier, $file, $line);

        self::$pdo->prepare(
            'INSERT OR IGNORE INTO boundaries
             (boundary_id, run_id, request_id, event_id, direction, store_kind,
              store_identifier, entity_key_hash, taint_id, value_hash, ts)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        )->execute([
            self::uuid(), self::$runId, self::$requestId, $eventId,
            $direction, $storeKind, $storeIdentifier,
            $entityKeyHash ?: null, $taintId, $hash, self::now(),
        ]);
    }

    /**
     * Injected at known output SINK points (HTML render, JSON response, email).
     *
     * Handles two cases:
     *  - Value IS a taint token (direct taint, e.g. escapeHtml return value)
     *  - Value CONTAINS taint tokens embedded in a larger string (e.g. rendered HTML block)
     */
    public static function sink(
        string $fqn,
        $value,
        string $sinkContext,
        string $file,
        int    $line
    ): void {
        if (!self::$enabled || !self::$requestId) {
            return;
        }

        // Direct taint: value starts with a prefix
        $direct = self::extractTainted($value);
        foreach ($direct as $v) {
            $taintId = self::ensureTaint($v);
            $nodeId  = self::ensureNode($fqn, $file, $line, 'SINK', $sinkContext);
            self::emitEvent('SINK', $nodeId, $taintId, $fqn, $file, $line,
                ['sink_context' => $sinkContext]);
        }

        // Embedded taint: value is a larger string (HTML/JSON) containing taint tokens
        if (is_string($value) && empty($direct)) {
            foreach (self::extractEmbeddedTaints($value) as $token) {
                // Look up by hash — only emit if we know this taint
                $hash = self::hash($token);
                $taintId = self::$registry[$hash] ?? null;
                if ($taintId === null) {
                    $taintId = self::ensureTaint($token);
                }
                $nodeId = self::ensureNode($fqn, $file, $line, 'SINK', $sinkContext);
                self::emitEvent('SINK', $nodeId, $taintId, $fqn, $file, $line,
                    ['sink_context' => $sinkContext, 'embedded' => true]);
            }
        }
    }

    /**
     * Record an unresolved taint gap: taint entered a function but the
     * chain is broken (value_hash changed without a recorded transform).
     */
    public static function recordGap(
        string $lastTaintId,
        string $nextValueHash,
        string $locationFqn,
        string $locationFile,
        int    $locationLine
    ): void {
        if (!self::$enabled || !self::$requestId) {
            return;
        }

        self::$pdo->prepare(
            'INSERT INTO taint_gaps
             (gap_id, run_id, request_id, last_taint_id, next_value_hash,
              gap_location_fqn, gap_location_file, gap_location_line)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        )->execute([
            self::uuid(), self::$runId, self::$requestId,
            $lastTaintId, $nextValueHash,
            $locationFqn, $locationFile, $locationLine,
        ]);
    }

    // ── Internals ─────────────────────────────────────────────────────────

    private static function isTainted(string $value): bool
    {
        foreach (self::PREFIXES as $p) {
            if (str_starts_with($value, $p)) {
                return true;
            }
        }
        return false;
    }

    /** Recursively extract tainted strings from scalars and arrays (no object traversal). */
    private static function extractTainted($value): array
    {
        if (is_string($value) && self::isTainted($value)) {
            return [$value];
        }
        if (is_array($value)) {
            $found = [];
            foreach ($value as $v) {
                if (is_string($v) && self::isTainted($v)) {
                    $found[] = $v;
                }
            }
            return $found;
        }
        return [];
    }

    /**
     * For SINK detection: scan a string for embedded taint tokens.
     * Returns the raw taint tokens found (e.g. "bSRC_FOO_01") extracted from
     * a larger HTML/JSON string that contains them but doesn't start with them.
     * Matches the longest token up to the first whitespace or HTML delimiter.
     */
    private static function extractEmbeddedTaints(string $haystack): array
    {
        $found = [];
        foreach (self::PREFIXES as $prefix) {
            $offset = 0;
            while (($pos = strpos($haystack, $prefix, $offset)) !== false) {
                // Capture the token: from $prefix start to next whitespace / < / > / " / ' / &
                $end = $pos;
                $len = strlen($haystack);
                while ($end < $len && !in_array($haystack[$end], [' ', "\t", "\n", "\r", '<', '>', '"', "'", '&', ';', ')'], true)) {
                    $end++;
                }
                $token = substr($haystack, $pos, $end - $pos);
                if (strlen($token) > strlen($prefix)) { // must be more than just the prefix
                    $found[$token] = true;
                }
                $offset = $end;
            }
        }
        return array_keys($found);
    }

    private static function hash(string $value): string
    {
        return hash('sha256', $value);
    }

    private static function ensureTaint(string $value, string $initialMark = ''): string
    {
        $hash = self::hash($value);
        if (isset(self::$registry[$hash])) {
            return self::$registry[$hash];
        }

        $taintId   = self::uuid();
        $marksJson = $initialMark ? json_encode([$initialMark]) : '[]';

        self::$pdo->prepare(
            'INSERT OR IGNORE INTO taints
             (taint_id, taint_type, value_hash, value_len, marks_json,
              first_seen_request_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        )->execute([
            $taintId, 'string', $hash, strlen($value),
            $marksJson, self::$requestId, self::now(),
        ]);

        // Always resolve to the canonical taint_id for this hash (cross-request safe)
        $row = self::$pdo->prepare('SELECT taint_id FROM taints WHERE value_hash = ? LIMIT 1');
        $row->execute([$hash]);
        $canonical = $row->fetchColumn();
        $taintId = $canonical ?: $taintId;

        self::$registry[$hash] = $taintId;
        return $taintId;
    }

    private static function ensureNode(
        string $fqn,
        string $file,
        int    $line,
        string $nodeType,
        string $sinkContext = 'NONE'
    ): string {
        $nodeId = hash('sha256', $fqn . ':' . $file . ':' . $line);
        self::$pdo->prepare(
            'INSERT OR IGNORE INTO nodes
             (node_id, node_type, fqn, file_path, line_no, sink_context)
             VALUES (?, ?, ?, ?, ?, ?)'
        )->execute([$nodeId, $nodeType, $fqn, $file, $line, $sinkContext]);
        return $nodeId;
    }

    private static function emitEvent(
        string $eventType,
        string $nodeId,
        string $taintId,
        string $fqn,
        string $file,
        int    $line,
        array  $extra = []
    ): string {
        $eventId = self::uuid();
        $seq     = ++self::$seqNo;
        $payload = $extra ? json_encode($extra, JSON_UNESCAPED_SLASHES) : null;

        self::$pdo->prepare(
            'INSERT INTO events
             (event_id, run_id, request_id, trace_nonce, event_type, node_id,
              taint_id, function_fqn, file_path, line_no, seq_no, ts, event_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        )->execute([
            $eventId, self::$runId, self::$requestId, self::$traceNonce,
            $eventType, $nodeId, $taintId, $fqn, $file, $line, $seq,
            self::now(), $payload,
        ]);

        return $eventId;
    }

    private static function uuid(): string
    {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }

    private static function now(): string
    {
        return (new \DateTimeImmutable())->format('Y-m-d\TH:i:s.u\Z');
    }
}
