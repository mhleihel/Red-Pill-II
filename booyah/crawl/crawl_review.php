<?php
declare(strict_types=1);

$base      = 'http://localhost:8082';
$cookieJar = '/tmp/booyah_review_cookies.txt';
$traceDb   = '/Users/mhleihel/Desktop/Booyah/results/runtime_trace.db';
$mysqlDsn  = 'mysql:host=127.0.0.1;port=3307;dbname=magento';
$mysql     = new PDO($mysqlDsn, 'magento', 'magento');

@unlink($cookieJar);

$tag = 'bSRC_REV_' . substr(md5((string)time()), 0, 6);

function req(string $method, string $url, array $post = []): array
{
    global $cookieJar;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_COOKIEFILE     => $cookieJar,
        CURLOPT_COOKIEJAR      => $cookieJar,
    ]);
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    }
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ['code' => $code, 'body' => (string)$body];
}

function extractFormKey(string $html): string
{
    if (preg_match('/var FORM_KEY\s*=\s*["\']([a-zA-Z0-9]+)["\']/', $html, $m)) return $m[1];
    if (preg_match('/form_key.*?value=["\']([a-zA-Z0-9]+)["\']/', $html, $m)) return $m[1];
    return '';
}

function dbHits(string $traceDb, string $hash): int
{
    $out = shell_exec("sqlite3 $traceDb \"SELECT COUNT(*) FROM events e JOIN taints t ON e.taint_id=t.taint_id WHERE t.value_hash='$hash';\"");
    return (int)trim((string)$out);
}

// ── Preflight ─────────────────────────────────────────────────────────────────
echo "=== Preflight ===\n";
$pfTag  = 'bSRC_PREFLIGHT_' . time();
$pfHash = hash('sha256', $pfTag);
req('GET', "$base/?q=$pfTag");
sleep(2);
$hits = dbHits($traceDb, $pfHash);
echo "  tag=$pfTag hits=$hits\n";
if ($hits === 0) {
    echo "  ABORT: tracer not writing to DB\n";
    exit(1);
}
echo "  PREFLIGHT PASS\n\n";

// ── Step 1: Load product page ─────────────────────────────────────────────────
echo "=== Step 1: Load product page ===\n";
// Product 2 (booyah-secure-phone) has a url_rewrite entry
$prodId  = 2;
$prodUrl = "$base/booyah-secure-phone.html";
$r = req('GET', $prodUrl);
$formKey = extractFormKey($r['body']);
echo "  HTTP {$r['code']} form_key=$formKey\n";
if (!$formKey) { echo "  ABORT: no form_key\n"; exit(1); }

// ── Step 2: POST tainted review ───────────────────────────────────────────────
echo "\n=== Step 2: POST tainted review ===\n";
$r = req('POST', "$base/review/product/post/id/$prodId/", [
    'form_key'   => $formKey,
    'product_id' => $prodId,
    'ratings[4]' => '5',
    'nickname'   => "{$tag}_NICK",
    'title'      => "{$tag}_TITLE",
    'detail'     => "{$tag}_DETAIL tainted body",
]);
echo "  HTTP {$r['code']}\n";
sleep(2);

// ── Step 3: Approve review so it appears on the product page ─────────────────
echo "\n=== Step 3: Approve review ===\n";
$reviewId = $mysql->query(
    "SELECT review_id FROM review_detail WHERE nickname LIKE '{$tag}%' LIMIT 1"
)->fetchColumn();
if (!$reviewId) {
    echo "  WARNING: review not found in DB — read path will miss it\n";
} else {
    $mysql->exec("UPDATE review SET status_id=1 WHERE review_id=$reviewId");
    $mysql->exec("UPDATE review_entity_summary SET reviews_count=reviews_count+1 WHERE entity_pk_value=$prodId");
    echo "  review_id=$reviewId approved\n";
}
sleep(1);

// ── Step 4a: GET product page (triggers summary block) ───────────────────────
echo "\n=== Step 4a: GET product page ===\n";
$r = req('GET', $prodUrl);
echo "  HTTP {$r['code']}\n";

// ── Step 4b: GET review AJAX endpoint — actual read path ──────────────────────
echo "\n=== Step 4b: GET review AJAX (read path) ===\n";
$r = req('GET', "$base/review/product/listAjax/id/$prodId/");
$htmlHits = preg_match_all('/bSRC_REV_/', $r['body']);
echo "  HTTP {$r['code']} | taint_in_html: $htmlHits\n";
if ($htmlHits === 0) {
    echo "  NOTE: tag not in first page — checking all pages\n";
    $r2 = req('GET', "$base/review/product/listAjax/id/$prodId/?p=2");
    $htmlHits2 = preg_match_all('/bSRC_REV_/', $r2['body']);
    echo "  page2 hits: $htmlHits2\n";
}

// ── Step 5: DB event summary ──────────────────────────────────────────────────
echo "\n=== DB event counts ===\n";
echo shell_exec("sqlite3 $traceDb 'SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY 2 DESC'") ?: "  (no output)\n";

// ── Step 6: Cleanup ───────────────────────────────────────────────────────────
if ($reviewId) {
    $mysql->exec("DELETE FROM review WHERE review_id=$reviewId");
    $mysql->exec("DELETE FROM review_detail WHERE review_id=$reviewId");
}

echo "\nTag: $tag\n";
