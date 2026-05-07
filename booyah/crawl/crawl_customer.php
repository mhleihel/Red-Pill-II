<?php
declare(strict_types=1);

/**
 * Customer component crawl.
 *
 * Paths exercised:
 *   F1  Frontend registration  → Model/Customer, Ajax/Login, Section/Load
 *   F2  Frontend address edit  → Address/AbstractAddress, Address/Street, Widget/Dob
 *   F3  Frontend account view  → Show/Customer, Newsletter/Subscriptions
 *   A1  Admin customer list    → Listing/Columns
 *   A2  Admin customer view    → Show/Customer, AbstractAddress
 *   A3  Admin customer edit    → Address/Edit, Backend/Store
 *
 * Taint strategy: inject bSRC_ values into firstname, lastname, company, street,
 * dob fields so GenericModelPlugin fires SOURCE events, then read them back to
 * produce SINK events.
 */

$base       = 'http://localhost:8082';
$adminBase  = "$base/admin";
$cookieJar  = '/tmp/booyah_customer_cookies.txt';
$adminJar   = '/tmp/booyah_customer_admin_cookies.txt';
$traceDb    = '/Users/mhleihel/Desktop/Booyah/results/runtime_trace.db';
$mysqlDsn   = 'mysql:host=127.0.0.1;port=3307;dbname=magento';
$mysql      = new PDO($mysqlDsn, 'magento', 'magento');
$adminUser  = 'booyah_crawl';
$adminPass  = 'Booyah1234!';

@unlink($cookieJar);
@unlink($adminJar);

$tag = 'bSRC_CUST_' . substr(md5((string)time()), 0, 6);
echo "Tag: $tag\n\n";

function req(string $method, string $url, array $post = [], string $jar = ''): array
{
    global $cookieJar;
    $jar = $jar ?: $cookieJar;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_COOKIEFILE     => $jar,
        CURLOPT_COOKIEJAR      => $jar,
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

function dbHits(string $db, string $hash): int
{
    $out = shell_exec("sqlite3 $db \"SELECT COUNT(*) FROM events e JOIN taints t ON e.taint_id=t.taint_id WHERE t.value_hash='$hash';\"");
    return (int)trim((string)$out);
}

// ── Preflight ─────────────────────────────────────────────────────────────────
echo "=== Preflight ===\n";
$pfTag  = 'bSRC_PREFLIGHT_' . time();
$pfHash = hash('sha256', $pfTag);
req('GET', "$base/?q=$pfTag");
sleep(2);
if (dbHits($traceDb, $pfHash) === 0) { echo "  ABORT: tracer not writing to DB\n"; exit(1); }
echo "  PREFLIGHT PASS\n\n";

// ── F1: Frontend registration with tainted fields ────────────────────────────
echo "=== F1: Frontend registration ===\n";
$r    = req('GET', "$base/customer/account/create/");
$fk   = extractFormKey($r['body']);
$email = strtolower($tag) . '@booyah.local';

$r = req('POST', "$base/customer/account/createpost/", [
    'form_key'             => $fk,
    'firstname'            => "{$tag}_FIRST",
    'lastname'             => "{$tag}_LAST",
    'email'                => $email,
    'password'             => 'Booyah1234!',
    'password_confirmation'=> 'Booyah1234!',
]);
echo "  POST registration → HTTP {$r['code']}\n";
sleep(1);

$custId = $mysql->query("SELECT entity_id FROM customer_entity WHERE email='$email' LIMIT 1")->fetchColumn();
echo "  customer_id=$custId\n";

// ── F2: Frontend — add address (exercises AbstractAddress, Street, Dob) ───────
echo "\n=== F2: Frontend address add ===\n";
$r  = req('GET', "$base/customer/address/new/");
$fk = extractFormKey($r['body']);

$r = req('POST', "$base/customer/address/formPost/", [
    'form_key'   => $fk,
    'firstname'  => "{$tag}_ADDR_FIRST",
    'lastname'   => "{$tag}_ADDR_LAST",
    'company'    => "{$tag}_COMPANY",
    'street[]'   => "{$tag}_STREET1",
    'city'       => "{$tag}_CITY",
    'region_id'  => '12',   // California
    'postcode'   => '90210',
    'country_id' => 'US',
    'telephone'  => '555-{$tag}',
]);
echo "  POST address → HTTP {$r['code']}\n";
sleep(1);

$addrId = $mysql->query("SELECT entity_id FROM customer_address_entity WHERE parent_id=$custId ORDER BY entity_id DESC LIMIT 1")->fetchColumn();
echo "  address_id=$addrId\n";

// ── F3: Frontend account pages ────────────────────────────────────────────────
echo "\n=== F3: Frontend account view ===\n";
foreach ([
    "$base/customer/account/",
    "$base/customer/address/index/",
    "$base/newsletter/manage/",
] as $url) {
    $r = req('GET', $url);
    $hits = substr_count($r['body'], $tag);
    echo "  GET $url → HTTP {$r['code']} | taint_in_html: $hits\n";
}
sleep(1);

// Section load (used by AJAX customer data refresh)
$r = req('GET', "$base/customer/section/load/?sections=customer%2Caddress&update_section_id=false&_=1");
echo "  GET section/load → HTTP {$r['code']}\n";
sleep(1);

// ── Admin login ───────────────────────────────────────────────────────────────
echo "\n=== Admin login ===\n";
$r  = req('GET', "$adminBase/admin/auth/login/", [], $adminJar);
$fk = extractFormKey($r['body']);
req('POST', "$adminBase/admin/auth/login/post/", [
    'login[username]' => $adminUser,
    'login[password]' => $adminPass,
    'form_key'        => $fk,
], $adminJar);
$dash = req('GET', "$adminBase/admin/dashboard/", [], $adminJar);
$fk   = extractFormKey($dash['body']) ?: $fk;
echo "  form_key=$fk\n";

// ── A1: Admin customer list (Listing/Columns) ─────────────────────────────────
echo "\n=== A1: Admin customer list ===\n";
$r = req('GET', "$adminBase/customer/index/", [], $adminJar);
$hits = substr_count($r['body'], $tag);
echo "  GET customer list → HTTP {$r['code']} | taint_in_html: $hits\n";

// AJAX grid (the actual data rendered in the grid)
$r = req('GET', "$adminBase/customer/index/grid/", [], $adminJar);
$hits = substr_count($r['body'], $tag);
echo "  GET customer grid → HTTP {$r['code']} | taint_in_html: $hits\n";
sleep(1);

// ── A2: Admin customer view ────────────────────────────────────────────────────
echo "\n=== A2: Admin customer view ===\n";
if ($custId) {
    $r    = req('GET', "$adminBase/customer/index/edit/id/$custId/", [], $adminJar);
    $hits = substr_count($r['body'], $tag);
    echo "  GET customer edit → HTTP {$r['code']} | taint_in_html: $hits\n";
    sleep(1);

    // Address tab (exercises AbstractAddress, Address/Edit)
    $r    = req('GET', "$adminBase/customer/address/index/parent_id/$custId/", [], $adminJar);
    $hits = substr_count($r['body'], $tag);
    echo "  GET address tab → HTTP {$r['code']} | taint_in_html: $hits\n";
}
sleep(1);

// ── A3: Admin customer with existing tainted address (entity_id=1, alice) ─────
echo "\n=== A3: Admin view alice (pre-tainted address) ===\n";
$r    = req('GET', "$adminBase/customer/index/edit/id/1/", [], $adminJar);
$hits = substr_count($r['body'], 'bSRC');
echo "  GET alice edit → HTTP {$r['code']} | taint_in_html: $hits\n";
sleep(1);

// ── DB summary ────────────────────────────────────────────────────────────────
echo "\n=== DB event counts ===\n";
echo shell_exec("sqlite3 $traceDb 'SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY 2 DESC'") ?: "  (none)\n";

// ── Cleanup ───────────────────────────────────────────────────────────────────
if ($custId) {
    // Delete test customer (address cascades via FK)
    $mysql->exec("DELETE FROM customer_address_entity WHERE parent_id=$custId");
    $mysql->exec("DELETE FROM customer_entity WHERE entity_id=$custId");
    echo "\nTest customer cleaned up (id=$custId)\n";
}

echo "\nTag: $tag\n";
