<?php
declare(strict_types=1);

/**
 * Lineage assembler: reads runtime_trace.db, joins taint events by value_hash
 * across requests, and writes appmap_v1.db with complete flow chains.
 *
 * Usage:
 *   php assemble.php \
 *     --trace  /path/to/runtime_trace.db \
 *     --output /path/to/appmap_v1.db
 */

$opts = getopt('', ['trace:', 'output:']);
$traceDb  = $opts['trace']  ?? getenv('BOOYAH_TRACE_DB')  ?: '/Users/mhleihel/Desktop/Booyah/results/runtime_trace.db';
$outputDb = $opts['output'] ?? getenv('BOOYAH_APPMAP_DB') ?: '/Users/mhleihel/Desktop/Booyah/results/appmap_v1.db';

if (!file_exists($traceDb)) {
    fwrite(STDERR, "trace DB not found: $traceDb\n");
    exit(1);
}

$trace  = new PDO("sqlite:$traceDb");
$trace->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$trace->exec('PRAGMA journal_mode = WAL');

// ── Build output DB ───────────────────────────────────────────────────────────

if (file_exists($outputDb)) {
    unlink($outputDb);
}
$out = new PDO("sqlite:$outputDb");
$out->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$out->exec('PRAGMA journal_mode = WAL');
$out->exec('PRAGMA synchronous = NORMAL');

$out->exec(<<<SQL
CREATE TABLE chains (
    chain_id           TEXT PRIMARY KEY,
    value_hash         TEXT NOT NULL,
    write_request_id   TEXT,
    read_request_id    TEXT,
    source_fqn         TEXT,
    write_fqn          TEXT,
    read_fqn           TEXT,
    transform_fqn      TEXT,
    sink_fqn           TEXT,
    has_source         INTEGER NOT NULL DEFAULT 0,
    has_write          INTEGER NOT NULL DEFAULT 0,
    has_read           INTEGER NOT NULL DEFAULT 0,
    has_transform      INTEGER NOT NULL DEFAULT 0,
    has_sink           INTEGER NOT NULL DEFAULT 0,
    hops_json          TEXT,
    created_at         TEXT NOT NULL
);
CREATE INDEX chains_value_hash ON chains (value_hash);
SQL);

$out->exec(<<<SQL
CREATE TABLE chain_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id         TEXT NOT NULL REFERENCES chains(chain_id),
    event_id         TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    function_fqn     TEXT,
    file_path        TEXT,
    line_no          INTEGER,
    request_id       TEXT,
    ts               TEXT,
    event_json       TEXT
);
CREATE INDEX ce_chain ON chain_events (chain_id);
SQL);

// ── Load all taints grouped by value_hash ─────────────────────────────────────

echo "Loading taints...\n";

$hashToTaints = [];
$stmt = $trace->query('SELECT taint_id, value_hash, parent_taint_id FROM taints ORDER BY created_at');
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $hashToTaints[$row['value_hash']][] = $row['taint_id'];
}

echo "Distinct value_hashes: " . count($hashToTaints) . "\n";

// ── Load events indexed by taint_id ──────────────────────────────────────────

echo "Loading events...\n";

$taintEvents = [];
$stmt = $trace->query(
    'SELECT event_id, event_type, taint_id, function_fqn, file_path, line_no, request_id, ts, event_json
     FROM events ORDER BY ts, seq_no'
);
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $taintEvents[$row['taint_id']][] = $row;
}

// ── Assemble chains ───────────────────────────────────────────────────────────

echo "Assembling chains...\n";

$out->beginTransaction();
$insertChain = $out->prepare(
    'INSERT INTO chains
     (chain_id, value_hash, write_request_id, read_request_id,
      source_fqn, write_fqn, read_fqn, transform_fqn, sink_fqn,
      has_source, has_write, has_read, has_transform, has_sink,
      hops_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
);
$insertEvent = $out->prepare(
    'INSERT INTO chain_events
     (chain_id, event_id, event_type, function_fqn, file_path, line_no, request_id, ts, event_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
);

$chainCount = 0;

foreach ($hashToTaints as $valueHash => $taintIds) {
    // Gather all events for all taints with this value_hash
    $allEvents = [];
    foreach ($taintIds as $taintId) {
        foreach ($taintEvents[$taintId] ?? [] as $evt) {
            $allEvents[] = $evt;
        }
    }

    if (empty($allEvents)) {
        continue;
    }

    // Sort by timestamp
    usort($allEvents, fn($a, $b) => strcmp($a['ts'], $b['ts']));

    // Index event types
    $byType = [];
    foreach ($allEvents as $evt) {
        $byType[$evt['event_type']][] = $evt;
    }

    // Only record chains that have at least SOURCE or BOUNDARY_WRITE
    if (!isset($byType['SOURCE']) && !isset($byType['BOUNDARY_WRITE'])) {
        continue;
    }

    // Identify write and read requests
    $writeReqId = null;
    $readReqId  = null;
    if (!empty($byType['BOUNDARY_WRITE'])) {
        $writeReqId = $byType['BOUNDARY_WRITE'][0]['request_id'];
    }
    if (!empty($byType['BOUNDARY_READ'])) {
        $readReqId = $byType['BOUNDARY_READ'][0]['request_id'];
    } elseif (!empty($byType['SINK'])) {
        // If no explicit BOUNDARY_READ, use the request that has the SINK
        $readReqId = $byType['SINK'][0]['request_id'];
    }

    // Extract most-qualified (longest) FQN for each stage to prefer full namespaced names
    $longestFqn = function(array $events): ?string {
        $best = null;
        foreach ($events as $e) {
            $fqn = $e['function_fqn'] ?? null;
            if ($fqn !== null && (strlen($fqn) > strlen((string)$best))) $best = $fqn;
        }
        return $best;
    };
    $sourceFqn    = $longestFqn($byType['SOURCE']        ?? []);
    $writeFqn     = $longestFqn($byType['BOUNDARY_WRITE'] ?? []);
    $readFqn      = $longestFqn($byType['BOUNDARY_READ']  ?? []);
    $transformFqn = $longestFqn($byType['TRANSFORM']      ?? []);
    $sinkFqn      = $longestFqn($byType['SINK']           ?? []);

    // Build ordered hops list
    $hops = [];
    $orderMap = [
        'SOURCE'         => 1,
        'CALL_ENTER'     => 2,
        'BOUNDARY_WRITE' => 3,
        'BOUNDARY_READ'  => 4,
        'CALL_EXIT'      => 5,
        'TRANSFORM'      => 6,
        'SINK'           => 7,
    ];
    foreach ($allEvents as $evt) {
        $hops[] = [
            'type'    => $evt['event_type'],
            'fqn'     => $evt['function_fqn'],
            'request' => substr($evt['request_id'], 0, 8),
            'ts'      => $evt['ts'],
        ];
    }

    $chainId = sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000, mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff));

    $insertChain->execute([
        $chainId, $valueHash,
        $writeReqId, $readReqId,
        $sourceFqn, $writeFqn, $readFqn, $transformFqn, $sinkFqn,
        isset($byType['SOURCE'])         ? 1 : 0,
        isset($byType['BOUNDARY_WRITE']) ? 1 : 0,
        isset($byType['BOUNDARY_READ'])  ? 1 : 0,
        isset($byType['TRANSFORM'])      ? 1 : 0,
        isset($byType['SINK'])           ? 1 : 0,
        json_encode($hops, JSON_UNESCAPED_SLASHES),
        (new DateTimeImmutable())->format('Y-m-d\TH:i:s.u\Z'),
    ]);

    foreach ($allEvents as $evt) {
        $insertEvent->execute([
            $chainId, $evt['event_id'], $evt['event_type'],
            $evt['function_fqn'], $evt['file_path'], $evt['line_no'],
            $evt['request_id'], $evt['ts'], $evt['event_json'],
        ]);
    }

    $chainCount++;
}

$out->commit();

// ── Print summary ─────────────────────────────────────────────────────────────

echo "\n=== Lineage Assembly Complete ===\n";
echo "Chains assembled: $chainCount\n";

$fullChains = $out->query(
    'SELECT COUNT(*) FROM chains WHERE has_source=1 AND has_write=1 AND has_sink=1'
)->fetchColumn();
$withSink = $out->query(
    'SELECT COUNT(*) FROM chains WHERE has_sink=1'
)->fetchColumn();
$withWrite = $out->query(
    'SELECT COUNT(*) FROM chains WHERE has_write=1'
)->fetchColumn();
$withTransform = $out->query(
    'SELECT COUNT(*) FROM chains WHERE has_transform=1'
)->fetchColumn();

echo "  With SINK:            $withSink\n";
echo "  With BOUNDARY_WRITE:  $withWrite\n";
echo "  With TRANSFORM:       $withTransform\n";
echo "  Full (src+write+sink): $fullChains\n";
echo "\nOutput: $outputDb\n";

// Show sample chain details
echo "\n=== Sample Chains ===\n";
$samples = $out->query(
    'SELECT chain_id, has_source, has_write, has_read, has_transform, has_sink,
            source_fqn, write_fqn, transform_fqn, sink_fqn
     FROM chains WHERE has_sink=1 LIMIT 3'
);
foreach ($samples->fetchAll(PDO::FETCH_ASSOC) as $c) {
    echo 'Chain: ' . substr($c['chain_id'], 0, 8) . "\n";
    echo '  source    → ' . ($c['source_fqn']    ?? '-') . "\n";
    echo '  write     → ' . ($c['write_fqn']     ?? '-') . "\n";
    echo '  transform → ' . ($c['transform_fqn'] ?? '-') . "\n";
    echo '  sink      → ' . ($c['sink_fqn']      ?? '-') . "\n";
    echo '  flags: src=' . $c['has_source'] . ' write=' . $c['has_write']
        . ' read=' . $c['has_read'] . ' xform=' . $c['has_transform']
        . ' sink=' . $c['has_sink'] . "\n";
}
