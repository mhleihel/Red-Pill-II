<?php
declare(strict_types=1);
/**
 * Gap closure crawl — targets 3 remaining high-risk confirmed gaps:
 *   1. Catalog/Block/Navigation.php        → GET category page
 *   2. Catalog/Helper/Category.php         → GET category page (same request)
 *   3. Catalog/Modifier/CustomOptions.php  → create option, GET product edit, delete
 *
 * CreateDefaultPages.php is a setup patch — NOT a runtime path, marked out_of_scope_runtime.
 */

$base      = 'http://localhost:8082';
$adminBase = "$base/admin";
$cookieJar = '/tmp/booyah_gap_cookies.txt';
$traceDb   = '/Users/mhleihel/Desktop/Booyah/results/runtime_trace.db';
$mysqlDsn  = 'mysql:host=127.0.0.1;port=3307;dbname=magento';
$mysql     = new PDO($mysqlDsn, 'magento', 'magento');
$user      = 'booyah_crawl';
$pass      = 'Booyah1234!';

@unlink($cookieJar);
$tag = 'bSRC_GAP_' . substr(md5((string)time()), 0, 6);

function req(string $method, string $url, array $post = []): array
{
    global $cookieJar;
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_FOLLOWLOCATION=>true,
        CURLOPT_TIMEOUT=>30, CURLOPT_COOKIEFILE=>$cookieJar, CURLOPT_COOKIEJAR=>$cookieJar]);
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

function dbHits(string $db, string $hash): int
{
    return (int)trim((string)shell_exec("sqlite3 $db \"SELECT COUNT(*) FROM events e JOIN taints t ON e.taint_id=t.taint_id WHERE t.value_hash='$hash';\""));
}

// ── Preflight ─────────────────────────────────────────────────────────────────
echo "=== Preflight ===\n";
$pfTag = 'bSRC_PREFLIGHT_' . time();
req('GET', "$base/?q=$pfTag");
sleep(2);
$hits = dbHits($traceDb, hash('sha256', $pfTag));
if ($hits === 0) { echo "  ABORT: tracer not writing to DB\n"; exit(1); }
echo "  PREFLIGHT PASS\n\n";

// ── Gap 1+2: Category page — exercises Navigation block + Category helper ─────
echo "=== Gap 1+2: Category page (Navigation + Category helper) ===\n";
foreach (['booyah-electronics.html','booyah-clothing.html','booyah-books.html'] as $cat) {
    $r = req('GET', "$base/$cat");
    echo "  GET $cat → HTTP {$r['code']}\n";
}
sleep(1);

// ── Admin login for gap 3 ─────────────────────────────────────────────────────
echo "\n=== Admin login ===\n";
$r = req('GET', "$adminBase/admin/auth/login/");
$fk = extractFormKey($r['body']);
req('POST', "$adminBase/admin/auth/login/post/", ['login[username]'=>$user,'login[password]'=>$pass,'form_key'=>$fk]);
$dash = req('GET', "$adminBase/admin/dashboard/");
$fk = extractFormKey($dash['body']) ?: $fk;
echo "  form_key=$fk\n";

// ── Gap 3: CustomOptions.php — inject custom option, GET product edit, delete ──
echo "\n=== Gap 3: CustomOptions (product edit with custom option) ===\n";
$prodId = 2;

// Inject a tainted custom option directly via MySQL
$mysql->exec("INSERT INTO catalog_product_option
    (product_id, type, is_require, sku, max_characters, sort_order)
    VALUES ($prodId, 'field', 0, '{$tag}_OPT_SKU', 255, 1)");
$optionId = $mysql->lastInsertId();

// Option title (store 0)
$mysql->exec("INSERT INTO catalog_product_option_title (option_id, store_id, title)
    VALUES ($optionId, 0, '{$tag}_OPT_TITLE')");

echo "  Injected option_id=$optionId title={$tag}_OPT_TITLE\n";

// GET product edit — triggers CustomOptions modifier to load and render options
$r = req('GET', "$adminBase/catalog/product/edit/id/$prodId/");
$htmlHits = preg_match_all('/bSRC_GAP_/', $r['body']);
echo "  GET product edit → HTTP {$r['code']} | taint_in_html: $htmlHits\n";
sleep(1);

// Cleanup
$mysql->exec("DELETE FROM catalog_product_option_title WHERE option_id=$optionId");
$mysql->exec("DELETE FROM catalog_product_option WHERE option_id=$optionId");
echo "  option cleaned up\n";

// ── DB summary ────────────────────────────────────────────────────────────────
echo "\n=== DB event counts ===\n";
echo shell_exec("sqlite3 $traceDb 'SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY 2 DESC'") ?: "  (no output)\n";
echo "\nTag: $tag\n";
