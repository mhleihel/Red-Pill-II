<?php
declare(strict_types=1);

/**
 * Admin crawl — exercises write+read paths for top STATIC_ONLY modules:
 *   Catalog, Customer, CMS, Sales, Backend
 *
 * Flow per module:
 *   1. POST tainted value to an admin form (write path)
 *   2. GET the list/view page that renders it (read path)
 *   3. Clean up (delete) to keep the store tidy
 */

$base      = 'http://localhost:8082';
$adminBase = "$base/admin";
$user      = 'booyah_crawl';
$pass      = 'Booyah1234!';
$traceDb   = '/Users/mhleihel/Desktop/Booyah/results/runtime_trace.db';
$mysqlDsn  = 'mysql:host=127.0.0.1;port=3307;dbname=magento';
$cookieJar = '/tmp/booyah_admin_cookies.txt';

@unlink($cookieJar);

$pdo   = null; // read totals at end via sqlite3 CLI to avoid WAL version conflicts
$mysql = new PDO($mysqlDsn, 'magento', 'magento');

$runTag = 'bSRC_ADM_' . substr(md5((string)time()), 0, 6);

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function req(string $method, string $url, array $post = [], array $extraHeaders = []): array
{
    global $cookieJar;
    $ch = curl_init($url);
    $headers = array_merge(['X-Requested-With: XMLHttpRequest'], $extraHeaders);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_COOKIEFILE     => $cookieJar,
        CURLOPT_COOKIEJAR      => $cookieJar,
        CURLOPT_HTTPHEADER     => $headers,
    ]);
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    }
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $final = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);
    return ['code' => $code, 'body' => (string)$body, 'url' => $final];
}

function extractFormKey(string $html): string
{
    if (preg_match('/var FORM_KEY\s*=\s*["\']([a-zA-Z0-9]+)["\']/', $html, $m)) return $m[1];
    if (preg_match('/form_key.*?value=["\']([a-zA-Z0-9]+)["\']/', $html, $m)) return $m[1];
    if (preg_match('/"form_key"\s*:\s*"([a-zA-Z0-9]+)"/', $html, $m)) return $m[1];
    return '';
}

function ts(): string { return (new DateTimeImmutable())->format('Y-m-d\TH:i:s.u\Z'); }

function report(string $label, int $code, int $taintHits): void
{
    printf("  %-40s HTTP %d | taint_hits: %2d\n", $label, $code, $taintHits);
}

// ── Step 1: Admin login ───────────────────────────────────────────────────────

echo "=== Admin Login ===\n";
$loginPage = req('GET', "$adminBase/admin/auth/login/");
$formKey   = extractFormKey($loginPage['body']);
echo "  form_key: $formKey\n";

$loginResp = req('POST', "$adminBase/admin/auth/login/post/", [
    'login[username]' => $user,
    'login[password]' => $pass,
    'form_key'        => $formKey,
]);
$loggedIn = str_contains($loginResp['url'], '/dashboard') || str_contains($loginResp['body'], 'dashboard');
echo "  Login: HTTP {$loginResp['code']} → {$loginResp['url']}\n";
if (!$loggedIn) {
    echo "  WARNING: login may have failed\n";
}

// Re-fetch dashboard to get a valid form_key for subsequent requests
$dash    = req('GET', "$adminBase/admin/dashboard/");
$formKey = extractFormKey($dash['body']) ?: $formKey;
echo "  Active form_key: $formKey\n\n";

// ── Module: CMS Pages ─────────────────────────────────────────────────────────

echo "=== CMS Pages ===\n";

$r = req('POST', "$adminBase/cms/page/save/", [
    'form_key'      => $formKey,
    'title'         => "{$runTag}_CMS_TITLE",
    'identifier'    => strtolower($runTag) . '-cms',
    'content'       => "<p>{$runTag}_CMS_CONTENT tainted body</p>",
    'is_active'     => '1',
    'stores[]'      => '0',
    'page_layout'   => '1column',
    'content_heading' => "{$runTag}_CMS_HEADING",
]);
sleep(2);
report('cms/page/save POST', $r['code'], preg_match_all('/bSRC_ADM/', $r['body']));

// Find the page we just created
$cmsId = $mysql->query("SELECT page_id FROM cms_page WHERE title LIKE '{$runTag}%' LIMIT 1")->fetchColumn();
if ($cmsId) {
    $r = req('GET', "$adminBase/cms/page/edit/page_id/$cmsId/");
    sleep(2);
    $hits = preg_match_all('/bSRC_ADM/', $r['body']);
    report('cms/page/edit GET', $r['code'], $hits);

    // Clean up
    req('POST', "$adminBase/cms/page/delete/page_id/$cmsId/", ['form_key' => $formKey]);
}

// ── Module: Catalog — Product attribute ──────────────────────────────────────

echo "\n=== Catalog ===\n";

// Inject tainted name into an existing product via MySQL (product save POST fails
// due to Magento validation requiring complete attribute set), then read it back.
$prodId = $mysql->query("SELECT entity_id FROM catalog_product_entity LIMIT 1")->fetchColumn();
$nameAttrId = 73; // eav_attribute.attribute_id for 'name' on catalog_product
$origName = $mysql->query(
    "SELECT value FROM catalog_product_entity_varchar WHERE entity_id=$prodId AND attribute_id=$nameAttrId AND store_id=0 LIMIT 1"
)->fetchColumn();
$mysql->exec(
    "UPDATE catalog_product_entity_varchar SET value='{$runTag}_PROD_NAME'
     WHERE entity_id=$prodId AND attribute_id=$nameAttrId AND store_id=0"
);
echo "  product $prodId name injected (orig: $origName)\n";

if ($prodId) {
    $r = req('GET', "$adminBase/catalog/product/edit/id/$prodId/");
    sleep(2);
    report('catalog/product/edit GET', $r['code'], preg_match_all('/bSRC_ADM/', $r['body']));
    // Restore original name
    $mysql->exec(
        "UPDATE catalog_product_entity_varchar SET value='$origName'
         WHERE entity_id=$prodId AND attribute_id=$nameAttrId AND store_id=0"
    );
    echo "  product $prodId name restored\n";
}

// ── Module: Customer ─────────────────────────────────────────────────────────
// NOTE: admin customer/save triggers a welcome email which fails when SMTP is
// not configured (HTTP 500). Insert directly via MySQL to still exercise the
// Customer model read path (admin edit GET).

echo "\n=== Customer ===\n";

$custEmail = strtolower($runTag) . '@booyah-crawl.local';
$mysql->exec(
    "INSERT INTO customer_entity
     (website_id, store_id, group_id, email, is_active, firstname, lastname, created_at, updated_at)
     VALUES (1, 1, 1, '$custEmail', 1,
             '{$runTag}_CUST_FIRST', '{$runTag}_CUST_LAST',
             NOW(), NOW())"
);
$custId = $mysql->lastInsertId();
// Also write EAV varchar rows so the values are visible on the admin edit form
// attribute_id: 5=firstname, 7=lastname
foreach ([5 => "{$runTag}_CUST_FIRST", 7 => "{$runTag}_CUST_LAST"] as $attrId => $val) {
    $mysql->exec(
        "INSERT INTO customer_entity_varchar (attribute_id, entity_id, value)
         VALUES ($attrId, $custId, '$val')"
    );
}
echo "  customer direct insert: entity_id=$custId\n";

if ($custId) {
    $r = req('GET', "$adminBase/customer/index/edit/id/$custId/");
    sleep(2);
    report('customer/index/edit GET', $r['code'], preg_match_all('/bSRC_ADM/', $r['body']));
    $mysql->exec("DELETE FROM customer_entity WHERE entity_id=$custId");
    $mysql->exec("DELETE FROM customer_entity_varchar WHERE entity_id=$custId");
}

// ── Module: Review (admin path) ───────────────────────────────────────────────

echo "\n=== Review (admin) ===\n";

$r = req('GET', "$adminBase/review/product/index/");
sleep(2);
$hits = preg_match_all('/bSRC_/', $r['body']);
report('review/product/index GET', $r['code'], $hits);

// ── Module: Backend — Global search ──────────────────────────────────────────

echo "\n=== Backend global search ===\n";

$r = req('GET', "$adminBase/admin/index/globalSearch/?query={$runTag}");
sleep(2);
report('admin/index/globalSearch GET', $r['code'], preg_match_all('/bSRC_ADM/', $r['body']));

// ── Final DB summary ──────────────────────────────────────────────────────────

echo "\n=== DB Totals (via sqlite3 CLI) ===\n";
$out = shell_exec("sqlite3 $traceDb 'SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY 2 DESC'");
echo $out ?: "  (no output)\n";
