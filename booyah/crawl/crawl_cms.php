<?php
declare(strict_types=1);

$base      = 'http://localhost:8082';
$adminBase = "$base/admin";
$cookieJar = '/tmp/booyah_cms_cookies.txt';
$traceDb   = '/Users/mhleihel/Desktop/Booyah/results/runtime_trace.db';
$mysqlDsn  = 'mysql:host=127.0.0.1;port=3307;dbname=magento';
$mysql     = new PDO($mysqlDsn, 'magento', 'magento');
$user      = 'booyah_crawl';
$pass      = 'Booyah1234!';

@unlink($cookieJar);

$tag = 'bSRC_CMS_' . substr(md5((string)time()), 0, 6);

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
echo "  hits=$hits\n";
if ($hits === 0) { echo "  ABORT: tracer not writing to DB\n"; exit(1); }
echo "  PREFLIGHT PASS\n\n";

// ── Step 1: Admin login ───────────────────────────────────────────────────────
echo "=== Step 1: Admin login ===\n";
$r = req('GET', "$adminBase/admin/auth/login/");
$formKey = extractFormKey($r['body']);
$r = req('POST', "$adminBase/admin/auth/login/post/", [
    'login[username]' => $user, 'login[password]' => $pass, 'form_key' => $formKey,
]);
$dash = req('GET', "$adminBase/admin/dashboard/");
$formKey = extractFormKey($dash['body']) ?: $formKey;
echo "  form_key=$formKey\n";

// ── Step 2: POST tainted CMS page (source path) ───────────────────────────────
echo "\n=== Step 2: POST tainted CMS page ===\n";
$slug = strtolower(str_replace('_', '-', $tag));
$r = req('POST', "$adminBase/cms/page/save/", [
    'form_key'        => $formKey,
    'title'           => "{$tag}_TITLE",
    'identifier'      => $slug,
    'content'         => "<p>{$tag}_CONTENT tainted body</p>",
    'is_active'       => '1',
    'stores[]'        => '0',
    'page_layout'     => '1column',
    'content_heading' => "{$tag}_HEADING",
]);
echo "  HTTP {$r['code']}\n";
sleep(2);

$pageId = $mysql->query("SELECT page_id FROM cms_page WHERE title LIKE '{$tag}%' LIMIT 1")->fetchColumn();
echo "  page_id=$pageId identifier=$slug\n";

// ── Step 3: GET frontend CMS page (read/render path) ──────────────────────────
echo "\n=== Step 3: GET frontend CMS page (render path) ===\n";
$r = req('GET', "$base/$slug");
$htmlHits = preg_match_all('/bSRC_CMS_/', $r['body']);
echo "  HTTP {$r['code']} | taint_in_html: $htmlHits\n";

// ── Step 4: DB summary ────────────────────────────────────────────────────────
echo "\n=== DB event counts ===\n";
echo shell_exec("sqlite3 $traceDb 'SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY 2 DESC'") ?: "  (no output)\n";

// ── Step 5: Cleanup ───────────────────────────────────────────────────────────
if ($pageId) {
    req('POST', "$adminBase/cms/page/delete/page_id/$pageId/", ['form_key' => $formKey]);
}

echo "\nTag: $tag\n";
