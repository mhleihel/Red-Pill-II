<?php
declare(strict_types=1);

/**
 * Tainted review crawl script.
 *
 * 1. Submits one tainted review per product (via HTTP POST)
 * 2. Approves all pending reviews directly in DB
 * 3. Exercises every read path that could render review data:
 *    - /review/product/listAjax/id/{product_id}/
 *    - /catalog/product/view/id/{product_id}/
 *    - /review/product/view/id/{review_id}/
 * 4. Prints a summary of events recorded per path
 */

$base      = getenv('MAGENTO_BASE_URL') ?: 'http://localhost:8082';
$traceDb   = getenv('BOOYAH_TRACE_DB')  ?: '/var/booyah/results/runtime_trace.db';
$mysqlHost = "127.0.0.1";
$mysqlDb   = 'magento';
$mysqlUser = 'magento';
$mysqlPass = 'magento';

$products = [1, 2, 3, 4, 5];

// ── Helpers ───────────────────────────────────────────────────────────────────

function get(string $url): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_HTTPHEADER     => ['X-Requested-With: XMLHttpRequest'],
        CURLOPT_COOKIEFILE     => '/tmp/booyah_crawl_cookies.txt',
        CURLOPT_COOKIEJAR      => '/tmp/booyah_crawl_cookies.txt',
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ['code' => $code, 'body' => $body];
}

function post(string $url, array $fields): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query($fields),
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_COOKIEFILE     => '/tmp/booyah_crawl_cookies.txt',
        CURLOPT_COOKIEJAR      => '/tmp/booyah_crawl_cookies.txt',
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ['code' => $code, 'body' => $body];
}

function eventsAfter(PDO $db, string $since): array
{
    $stmt = $db->prepare(
        "SELECT event_type, COUNT(*) c FROM events WHERE ts > ? GROUP BY event_type"
    );
    $stmt->execute([$since]);
    return $stmt->fetchAll(PDO::FETCH_KEY_PAIR);
}

function now(): string
{
    return (new DateTimeImmutable())->format('Y-m-d\TH:i:s.u\Z');
}

// ── Connect to trace DB ───────────────────────────────────────────────────────

$pdo = new PDO("sqlite:$traceDb");
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$mysql = new PDO("mysql:host=$mysqlHost;port=3307;dbname=$mysqlDb", $mysqlUser, $mysqlPass);

// ── Get form keys per product (needed for review POST) ───────────────────────

echo "=== Phase 1: Fetch form keys ===\n";

$formKeys = [];
foreach ($products as $pid) {
    $r = get("$base/catalog/product/view/id/$pid/");
    if (preg_match('/form_key.*?value=["\']([a-zA-Z0-9]+)["\']/', $r['body'], $m)) {
        $formKeys[$pid] = $m[1];
        echo "  product $pid: form_key={$m[1]}\n";
    } else {
        // Try alternate pattern
        if (preg_match('/"form_key":"([a-zA-Z0-9]+)"/', $r['body'], $m)) {
            $formKeys[$pid] = $m[1];
            echo "  product $pid: form_key={$m[1]} (json)\n";
        } else {
            echo "  product $pid: no form_key found (HTTP {$r['code']})\n";
        }
    }
}

// ── Phase 2: Submit tainted reviews ──────────────────────────────────────────

echo "\n=== Phase 2: Submit tainted reviews ===\n";

$submittedReviews = [];
$runTag = substr(md5((string)time()), 0, 8);

foreach ($products as $pid) {
    $tag      = "bSRC_CRAWL_{$runTag}_P{$pid}";
    $before   = now();
    $formKey  = $formKeys[$pid] ?? '';

    $r = post("$base/review/product/post/id/$pid/", [
        'form_key' => $formKey,
        'nickname' => $tag,
        'title'    => "{$tag}_TITLE",
        'detail'   => "{$tag}_DETAIL submitted via crawl",
        'ratings'  => [],
    ]);

    sleep(1); // let DB write settle

    $after = eventsAfter($pdo, $before);
    $total = array_sum($after);
    echo "  product $pid: POST {$r['code']} | events: $total (" . json_encode($after) . ")\n";

    // Find the review_id that was just created
    $stmt = $mysql->prepare(
        "SELECT r.review_id FROM review r
         JOIN review_detail rd ON r.review_id = rd.review_id
         WHERE rd.nickname = ? LIMIT 1"
    );
    $stmt->execute([$tag]);
    $reviewId = $stmt->fetchColumn();
    if ($reviewId) {
        $submittedReviews[$pid] = ['review_id' => $reviewId, 'tag' => $tag];
        echo "    → review_id=$reviewId\n";
    }
}

// ── Phase 3: Approve all pending tainted reviews ─────────────────────────────

echo "\n=== Phase 3: Approve reviews ===\n";

$mysql->exec(
    "UPDATE review r
     JOIN review_detail rd ON r.review_id = rd.review_id
     SET r.status_id = 1
     WHERE (rd.nickname LIKE 'bSRC_%' OR rd.nickname LIKE 'BSYH%')
       AND r.status_id != 1"
);
// Ensure store association
$mysql->exec(
    "INSERT IGNORE INTO review_store (review_id, store_id)
     SELECT r.review_id, 1 FROM review r
     JOIN review_detail rd ON r.review_id = rd.review_id
     WHERE (rd.nickname LIKE 'bSRC_%' OR rd.nickname LIKE 'BSYH%')"
);
echo "  All tainted reviews set to approved + store 1\n";

// Refresh review summary counts
foreach ($products as $pid) {
    $mysql->exec(
        "INSERT INTO review_entity_summary (entity_pk_value, entity_type, reviews_count, rating_summary, store_id)
         SELECT $pid, 1,
           (SELECT COUNT(*) FROM review r JOIN review_store rs ON r.review_id=rs.review_id WHERE r.entity_pk_value=$pid AND r.status_id=1 AND rs.store_id=1),
           0, 1
         ON DUPLICATE KEY UPDATE
           reviews_count = VALUES(reviews_count)"
    );
}
echo "  review_entity_summary refreshed\n";

// Flush Magento cache so product pages reload review counts
sleep(1);

// ── Phase 4: Trigger read paths ───────────────────────────────────────────────

echo "\n=== Phase 4: Read paths ===\n";

$readPaths = [];

// a. listAjax per product
foreach ($products as $pid) {
    $readPaths[] = ['label' => "listAjax product $pid", 'url' => "$base/review/product/listAjax/id/$pid/"];
}

// b. Product view page per product (renders review summary block)
foreach ($products as $pid) {
    $readPaths[] = ['label' => "product view $pid", 'url' => "$base/catalog/product/view/id/$pid/"];
}

// c. Individual review view pages for submitted reviews
foreach ($submittedReviews as $pid => $info) {
    $readPaths[] = ['label' => "review view {$info['review_id']}", 'url' => "$base/review/product/view/id/{$info['review_id']}/"];
}

foreach ($readPaths as $path) {
    $before = now();
    $r = get($path['url']);
    sleep(2); // wait for shutdown function to finalize request
    $after  = eventsAfter($pdo, $before);
    $total  = array_sum($after);
    // Count taint markers in response
    $taintHits = preg_match_all('/bSRC_|BSYH/', $r['body']);
    echo sprintf("  %-30s HTTP %d | taint_hits: %2d | events: %2d %s\n",
        $path['label'], $r['code'], $taintHits, $total,
        $total > 0 ? json_encode($after) : '');
}

// ── Summary ───────────────────────────────────────────────────────────────────

echo "\n=== DB Totals ===\n";
$totals = $pdo->query("SELECT event_type, COUNT(*) c FROM events GROUP BY event_type ORDER BY c DESC")->fetchAll(PDO::FETCH_KEY_PAIR);
foreach ($totals as $type => $cnt) {
    echo "  $type: $cnt\n";
}
echo "  TOTAL: " . array_sum($totals) . "\n";
