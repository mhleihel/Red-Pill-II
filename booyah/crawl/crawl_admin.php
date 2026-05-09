<?php
declare(strict_types=1);

/**
 * Booyah Admin Crawl
 *
 * Exercises write paths as a logged-in Magento admin.
 * Form-based admin requests → SetRoleObserver tags them as role=admin.
 * REST API admin calls → JWT utypid=2 detection in RequestTaintPlugin → role=admin.
 *
 * Lineages:
 *   ADMIN-1  CMS page save         → cms_page.{title,content,meta_keywords}
 *   ADMIN-2  CMS block save        → cms_block.{title,content}
 *   ADMIN-3  Product create (REST) → catalog_product_entity_varchar.{name,description}
 *   ADMIN-4  Category create       → catalog_category_entity_varchar.{name,description}
 *   ADMIN-5  Customer edit (admin) → customer_entity.{firstname,lastname}
 *   ADMIN-6  Order comment         → sales_order_status_history.comment
 *
 * ACL coverage: run once as full admin (all paths), then repeat restricted-role
 *   paths with admin_catalog (products/categories) and admin_content (CMS) users.
 *
 * Run: php booyah/crawl/crawl_admin.php
 */

$base      = 'http://localhost:8082';
$adminBase = "$base/admin";
$jar       = '/tmp/booyah_admin_cookies.txt';
$mysqlDsn  = 'mysql:host=127.0.0.1;port=3307;dbname=magento';
$pdo       = new PDO($mysqlDsn, 'magento', 'magento', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

// Admin accounts — each run exercises a different role scope
$accounts = [
    ['user' => 'admin',        'pass' => 'Booyah1!', 'scope' => 'full'],
    ['user' => 'admin_content','pass' => 'Booyah1!', 'scope' => 'cms'],
    ['user' => 'admin_catalog','pass' => 'Booyah1!', 'scope' => 'catalog'],
];

$runId = trim(shell_exec(
    "docker exec magento2-248-p4-php-1 bash -c 'echo \$BOOYAH_RUN_ID' 2>/dev/null"
) ?: 'run-full-20260507');

// ── Helpers ───────────────────────────────────────────────────────────────────

function req(string $method, string $url, array $post = [], array $headers = []): array
{
    global $jar;
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_COOKIEJAR      => $jar,
        CURLOPT_COOKIEFILE     => $jar,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_HEADER         => true,
        CURLOPT_HTTPHEADER     => array_merge(['Accept: text/html'], $headers),
    ]);
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    }
    $raw  = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $eff  = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $hlen = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    return ['code' => $code, 'body' => substr($raw, $hlen), 'url' => $eff];
}

function reqJson(string $method, string $url, array $body = [], array $headers = []): array
{
    global $jar;
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_COOKIEJAR      => $jar,
        CURLOPT_COOKIEFILE     => $jar,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_HEADER         => true,
        CURLOPT_HTTPHEADER     => array_merge(
            ['Content-Type: application/json', 'Accept: application/json'],
            $headers
        ),
        CURLOPT_CUSTOMREQUEST  => $method,
    ]);
    if (!empty($body)) curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
    $raw  = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hlen = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    return ['code' => $code, 'body' => substr($raw, $hlen)];
}

function formKey(string $html): string
{
    if (preg_match('/<input[^>]*name="form_key"[^>]*value="([^"]+)"/', $html, $m)) return $m[1];
    if (preg_match('/<input[^>]*value="([^"]+)"[^>]*name="form_key"/', $html, $m)) return $m[1];
    if (preg_match('/var FORM_KEY\s*=\s*["\']([^"\']+)["\']/', $html, $m)) return $m[1];
    if (preg_match('/"form_key"\s*:\s*"([^"]+)"/', $html, $m)) return $m[1];
    return '';
}

function pass(string $label, string $detail = ''): void
{
    echo "  [OK]  $label" . ($detail ? " — $detail" : '') . "\n";
}

function fail(string $label, string $detail = ''): void
{
    echo "  [FAIL] $label" . ($detail ? " — $detail" : '') . "\n";
}

function adminLogin(string $base, string $user, string $pass): string
{
    global $jar;
    @unlink($jar);
    $loginPage = req('GET', "$base/admin/admin/auth/login");
    $fk        = formKey($loginPage['body']);
    $resp      = req('POST', "$base/admin/admin/auth/login/post", [
        'login[username]' => $user,
        'login[password]' => $pass,
        'form_key'        => $fk,
    ]);
    // Get fresh form_key from dashboard
    $dash = req('GET', "$base/admin/admin/dashboard");
    $fk2  = formKey($dash['body']);
    $loggedIn = str_contains($resp['url'], 'dashboard') || str_contains($dash['body'], 'Dashboard');
    echo "  Login [$user] → " . ($loggedIn ? 'OK' : 'FAILED') . " (form_key=$fk2)\n";
    return $fk2 ?: $fk;
}

// ── Reset passwords for restricted admin accounts ─────────────────────────────

echo "=== Setup: reset restricted admin passwords ===\n";
foreach (['admin_content', 'admin_catalog'] as $u) {
    shell_exec(
        "docker exec magento2-248-p4-php-1 php /var/www/html/bin/magento admin:user:create" .
        " --admin-user=$u --admin-password=Booyah1!" .
        " --admin-email=$u@booyah.local --admin-firstname=$u --admin-lastname=Crawl 2>/dev/null"
    );
    echo "  Password reset for $u\n";
}

// ── Find a placed order to comment on ────────────────────────────────────────

$orderId = (int)$pdo->query(
    "SELECT entity_id FROM sales_order WHERE status NOT IN ('canceled') ORDER BY entity_id DESC LIMIT 1"
)->fetchColumn();
echo "  Target order_id for comments: $orderId\n\n";

// ── Run each admin account ─────────────────────────────────────────────────────

foreach ($accounts as $acct) {
    $user  = $acct['user'];
    $scope = $acct['scope'];
    $tag   = 'bSRC_ADM_' . strtoupper(substr($scope, 0, 3)) . '_' . substr(md5(uniqid('', true)), 0, 6);

    echo "=== Admin account: $user (scope=$scope) tag=$tag ===\n";

    // Get admin bearer token for REST calls (JWT utypid=2 → role=admin)
    $tokenResp = reqJson('POST', "$base/rest/V1/integration/admin/token",
        ['username' => $user, 'password' => 'Booyah1!']);
    $adminToken = trim($tokenResp['body'], '"');
    $authHdr    = "Authorization: Bearer $adminToken";

    // Form-based login for HTML admin interface
    $fk = adminLogin($base, $user, 'Booyah1!');

    // ── ADMIN-1: CMS page save (form, role=admin via adminhtml routing) ───────

    if (in_array($scope, ['full', 'cms'])) {
        echo "\n  [ADMIN-1] CMS page save\n";
        $newPage = req('GET', "$base/admin/cms/page/new");
        $fk2     = formKey($newPage['body']) ?: $fk;
        $r = req('POST', "$base/admin/cms/page/save", [
            'form_key'        => $fk2,
            'title'           => $tag . '_CMS_TITLE',
            'identifier'      => strtolower($tag) . '-page',
            'content'         => '<p>' . $tag . '_CMS_CONTENT</p>',
            'content_heading' => $tag . '_CMS_HEADING',
            'meta_keywords'   => $tag . '_CMS_META',
            'is_active'       => '1',
            'stores[]'        => '0',
            'page_layout'     => '1column',
        ]);
        echo "    POST → HTTP {$r['code']} → {$r['url']}\n";
        $stmt = $pdo->prepare("SELECT page_id FROM cms_page WHERE title LIKE ? LIMIT 1");
        $stmt->execute([$tag . '%']);
        $pageId = $stmt->fetchColumn();
        $pageId ? pass("cms_page written", "page_id=$pageId")
                : fail("cms_page not found");
    }

    // ── ADMIN-2: CMS block save (form) ───────────────────────────────────────

    if (in_array($scope, ['full', 'cms'])) {
        echo "\n  [ADMIN-2] CMS block save\n";
        $newBlk = req('GET', "$base/admin/cms/block/new");
        $fk2    = formKey($newBlk['body']) ?: $fk;
        $r = req('POST', "$base/admin/cms/block/save", [
            'form_key'   => $fk2,
            'title'      => $tag . '_BLK_TITLE',
            'identifier' => strtolower($tag) . '-block',
            'content'    => '<p>' . $tag . '_BLK_CONTENT</p>',
            'is_active'  => '1',
            'stores[]'   => '0',
        ]);
        echo "    POST → HTTP {$r['code']}\n";
        $stmt = $pdo->prepare("SELECT block_id FROM cms_block WHERE title LIKE ? LIMIT 1");
        $stmt->execute([$tag . '%']);
        $blkId = $stmt->fetchColumn();
        $blkId ? pass("cms_block written", "block_id=$blkId")
               : fail("cms_block not found");
    }

    // ── ADMIN-3: Product create via REST (role=admin via JWT detection) ───────

    if (in_array($scope, ['full', 'catalog'])) {
        echo "\n  [ADMIN-3] Product create (REST)\n";
        $sku = strtolower($tag) . '-prod';
        $r   = reqJson('POST', "$base/rest/V1/products", [
            'product' => [
                'sku'              => $sku,
                'name'             => $tag . '_PROD_NAME',
                'attribute_set_id' => 4,
                'price'            => 1.00,
                'status'           => 1,
                'visibility'       => 4,
                'type_id'          => 'simple',
                'weight'           => 1.0,
                'custom_attributes'=> [
                    ['attribute_code' => 'description',       'value' => $tag . '_PROD_DESC'],
                    ['attribute_code' => 'short_description', 'value' => $tag . '_PROD_SHORT'],
                    ['attribute_code' => 'meta_title',        'value' => $tag . '_PROD_META'],
                ],
                'extension_attributes' => ['website_ids' => [1], 'stock_item' => ['qty' => 10, 'is_in_stock' => true]],
            ]
        ], [$authHdr]);
        echo "    POST → HTTP {$r['code']}\n";
        $prod = json_decode($r['body'], true);
        $prodId = $prod['id'] ?? null;
        $prodId ? pass("Product created via REST", "product_id=$prodId sku=$sku")
                : fail("Product create failed", substr($r['body'], 0, 150));
    }

    // ── ADMIN-4: Category create via REST ─────────────────────────────────────

    if (in_array($scope, ['full', 'catalog'])) {
        echo "\n  [ADMIN-4] Category create (REST)\n";
        $r = reqJson('POST', "$base/rest/V1/categories", [
            'category' => [
                'name'             => $tag . '_CAT_NAME',
                'parent_id'        => 2,
                'is_active'        => true,
                'custom_attributes'=> [
                    ['attribute_code' => 'description',    'value' => $tag . '_CAT_DESC'],
                    ['attribute_code' => 'meta_keywords',  'value' => $tag . '_CAT_META'],
                ],
            ]
        ], [$authHdr]);
        echo "    POST → HTTP {$r['code']}\n";
        $cat = json_decode($r['body'], true);
        $catId = $cat['id'] ?? null;
        $catId ? pass("Category created", "category_id=$catId")
               : fail("Category create failed", substr($r['body'], 0, 100));
    }

    // ── ADMIN-5: Customer edit via admin form ─────────────────────────────────

    if (in_array($scope, ['full'])) {
        echo "\n  [ADMIN-5] Customer edit (admin form)\n";
        // Find a customer to edit (the crawl customer or the first available)
        $editCustId = (int)$pdo->query(
            "SELECT entity_id FROM customer_entity ORDER BY entity_id DESC LIMIT 1"
        )->fetchColumn();
        if ($editCustId) {
            $editPage = req('GET', "$base/admin/customer/index/edit/id/$editCustId");
            $fk2      = formKey($editPage['body']) ?: $fk;
            $r = req('POST', "$base/admin/customer/index/save", [
                'form_key'                              => $fk2,
                'customer[entity_id]'                   => (string)$editCustId,
                'customer[firstname]'                   => $tag . '_CFIRST',
                'customer[lastname]'                    => $tag . '_CLAST',
                'customer[website_id]'                  => '1',
                'customer[group_id]'                    => '1',
                'customer[store_id]'                    => '1',
                'customer[email]'                       => $pdo->query(
                    "SELECT email FROM customer_entity WHERE entity_id=$editCustId"
                )->fetchColumn(),
            ]);
            echo "    POST → HTTP {$r['code']}\n";
            $stmt = $pdo->prepare(
                "SELECT entity_id FROM customer_entity WHERE entity_id=? AND firstname LIKE ? LIMIT 1"
            );
            $stmt->execute([$editCustId, $tag . '%']);
            $stmt->fetchColumn()
                ? pass("customer_entity updated via admin", "entity_id=$editCustId")
                : fail("customer_entity not updated");
        } else {
            fail("No customer to edit");
        }
    }

    // ── ADMIN-6: Order comment ────────────────────────────────────────────────

    if (in_array($scope, ['full']) && $orderId > 0) {
        echo "\n  [ADMIN-6] Order comment\n";
        $orderStatus = $pdo->query(
            "SELECT status FROM sales_order WHERE entity_id=$orderId"
        )->fetchColumn() ?: 'pending';
        $r = reqJson('POST', "$base/rest/V1/orders/$orderId/comments", [
            'statusHistory' => [
                'comment'             => $tag . '_ORDER_COMMENT',
                'is_customer_notified'=> 0,
                'is_visible_on_front' => 1,
                'status'              => $orderStatus,
            ]
        ], [$authHdr]);
        echo "    POST → HTTP {$r['code']}\n";
        $stmt = $pdo->prepare(
            "SELECT entity_id FROM sales_order_status_history WHERE comment LIKE ? LIMIT 1"
        );
        $stmt->execute([$tag . '%']);
        $histId = $stmt->fetchColumn();
        $histId ? pass("sales_order_status_history written", "entity_id=$histId")
                : fail("sales_order_status_history not found");
    }

    echo "\n";
}

// ── Summary ───────────────────────────────────────────────────────────────────

echo "=== MySQL taint event counts (run_id=$runId) ===\n";
$rows = $pdo->query(
    "SELECT db_table, COUNT(*) as cnt FROM booyah_taint_map
     WHERE run_id='$runId' GROUP BY db_table ORDER BY cnt DESC"
)->fetchAll(PDO::FETCH_ASSOC);
foreach ($rows as $r) printf("  %-40s %d\n", $r['db_table'], $r['cnt']);

echo "\n=== Role distribution (run_id=$runId) ===\n";
$rows = $pdo->query(
    "SELECT COALESCE(role,'(null)') as role, COUNT(*) as cnt, COUNT(DISTINCT request_id) as reqs
     FROM booyah_taint_map WHERE run_id='$runId'
     GROUP BY role ORDER BY cnt DESC"
)->fetchAll(PDO::FETCH_ASSOC);
foreach ($rows as $r) printf("  %-20s events=%-6d requests=%d\n", $r['role'], $r['cnt'], $r['reqs']);

echo "\nDone.\n";
