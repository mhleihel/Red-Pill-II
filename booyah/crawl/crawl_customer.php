<?php
declare(strict_types=1);

/**
 * Booyah Authenticated Customer Crawl
 *
 * Exercises write paths as a logged-in frontend customer.
 * SetRoleObserver tags form-based requests as role=authenticated.
 * REST API calls (checkout, gift message) use JWT detection in RequestTaintPlugin.
 *
 * Lineages:
 *   AUTH-1  Account registration  → customer_entity.{firstname,lastname,email}
 *   AUTH-2  Account edit          → customer_entity.{firstname,lastname}
 *   AUTH-3  Address save          → customer_address_entity.{firstname,lastname,street}
 *   AUTH-4  Product review        → review_detail.{nickname,title,detail}
 *   AUTH-5  Newsletter subscribe  → newsletter_subscriber.subscriber_email
 *   AUTH-6  Logged-in checkout    → quote_address, sales_order_address
 *   AUTH-7  Gift message (cart)   → gift_message.{sender,recipient,message}
 *
 * Run: php booyah/crawl/crawl_customer.php
 */

$base     = 'http://localhost:8082';
$jar      = '/tmp/booyah_customer_cookies.txt';
$mysqlDsn = 'mysql:host=127.0.0.1;port=3307;dbname=magento';
$pdo      = new PDO($mysqlDsn, 'magento', 'magento', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

@unlink($jar);

$tag   = 'bSRC_AUTH_' . substr(md5(uniqid('', true)), 0, 8);
$runId = trim(shell_exec(
    "docker exec magento2-248-p4-php-1 bash -c 'echo \$BOOYAH_RUN_ID' 2>/dev/null"
) ?: 'run-full-20260507');

echo "Tag:    $tag\nRunId:  $runId\n\n";

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
        CURLOPT_HTTPHEADER     => array_merge(['Accept: text/html,application/xhtml+xml'], $headers),
    ]);
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    }
    $raw  = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hlen = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    return ['code' => $code, 'body' => substr($raw, $hlen), 'headers' => substr($raw, 0, $hlen)];
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
    ]);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    if (!empty($body)) curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
    $raw  = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hlen = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    return ['code' => $code, 'body' => substr($raw, $hlen)];
}

function formKey(string $html): string
{
    // Magento renders: <input name="form_key" type="hidden" value="XXX" />
    // Attribute order varies — match name and value independently within the same input tag
    if (preg_match('/<input[^>]*name="form_key"[^>]*value="([^"]+)"/', $html, $m)) return $m[1];
    if (preg_match('/<input[^>]*value="([^"]+)"[^>]*name="form_key"/', $html, $m)) return $m[1];
    if (preg_match('/var FORM_KEY\s*=\s*["\']([^"\']+)["\']/', $html, $m)) return $m[1];
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

// ── Preflight ─────────────────────────────────────────────────────────────────

echo "=== Preflight ===\n";
$twoHoursAgo = time() - 7200;
$recent = (int)$pdo->query(
    "SELECT COUNT(*) FROM booyah_taint_map WHERE run_id='$runId' AND ts > $twoHoursAgo"
)->fetchColumn();
$recent > 0 ? pass("Tracer active", "$recent recent events") : fail("No recent tracer events");

// ── AUTH-1: Account registration ──────────────────────────────────────────────

echo "\n=== AUTH-1: Account registration ===\n";
$regPage = req('GET', "$base/customer/account/create");
$fk      = formKey($regPage['body']);
$email   = strtolower($tag) . '@booyah.test';

req('POST', "$base/customer/account/createpost", [
    'form_key'             => $fk,
    'firstname'            => $tag . '_FIRST',
    'lastname'             => $tag . '_LAST',
    'email'                => $email,
    'password'             => 'Booyah1!',
    'password_confirmation'=> 'Booyah1!',
]);
$stmt = $pdo->prepare("SELECT entity_id FROM customer_entity WHERE email=? LIMIT 1");
$stmt->execute([$email]);
$custId = $stmt->fetchColumn();
if ($custId) {
    pass("customer_entity created", "entity_id=$custId email=$email");
} else {
    fail("customer_entity not found");
}

// ── AUTH-2: Account edit ──────────────────────────────────────────────────────

echo "\n=== AUTH-2: Account edit ===\n";
$editPage = req('GET', "$base/customer/account/edit");
$fk       = formKey($editPage['body']);
req('POST', "$base/customer/account/editPost", [
    'form_key'  => $fk,
    'firstname' => $tag . '_EDIT_FIRST',
    'lastname'  => $tag . '_EDIT_LAST',
    'email'     => $email,
]);
$stmt = $pdo->prepare(
    "SELECT entity_id FROM customer_entity WHERE firstname LIKE ? LIMIT 1"
);
$stmt->execute([$tag . '_EDIT%']);
$custId = $stmt->fetchColumn() ?: $custId;
pass("Account edit submitted");

// ── AUTH-3: Address save ──────────────────────────────────────────────────────

echo "\n=== AUTH-3: Address save ===\n";
$addrPage = req('GET', "$base/customer/address/new");
$fk       = formKey($addrPage['body']);
req('POST', "$base/customer/address/formPost", [
    'form_key'   => $fk,
    'firstname'  => $tag . '_AFIRST',
    'lastname'   => $tag . '_ALAST',
    'company'    => '',
    'telephone'  => '5555550100',
    'street[]'   => $tag . '_STREET',
    'city'       => 'San Francisco',
    'region_id'  => '12',
    'postcode'   => '94105',
    'country_id' => 'US',
]);
$stmt = $pdo->prepare(
    "SELECT entity_id FROM customer_address_entity WHERE firstname LIKE ? LIMIT 1"
);
$stmt->execute([$tag . '%']);
$addrId = $stmt->fetchColumn();
if ($addrId) {
    pass("customer_address_entity written", "entity_id=$addrId");
} else {
    fail("customer_address_entity not found");
}

// ── AUTH-4: Product review ────────────────────────────────────────────────────

echo "\n=== AUTH-4: Product review ===\n";
$prodPage = req('GET', "$base/catalog/product/view/id/2");
$fk       = formKey($prodPage['body']);
req('POST', "$base/review/product/post", [
    'form_key'   => $fk,
    'id'         => '2',
    'ratings[4]' => '14',
    'nickname'   => $tag . '_NICK',
    'title'      => $tag . '_TITLE',
    'detail'     => $tag . '_DETAIL',
]);
$stmt = $pdo->prepare("SELECT review_id FROM review_detail WHERE nickname LIKE ? LIMIT 1");
$stmt->execute([$tag . '%']);
$rvId = $stmt->fetchColumn();
if ($rvId) pass("review_detail written", "review_id=$rvId");
else fail("review_detail not found");

// ── AUTH-5: Newsletter subscribe ──────────────────────────────────────────────

echo "\n=== AUTH-5: Newsletter subscribe ===\n";
$subPage = req('GET', "$base/newsletter/manage");
$fk      = formKey($subPage['body']);
req('POST', "$base/newsletter/manage/save", [
    'form_key'      => $fk,
    'is_subscribed' => '1',
]);
$stmt = $pdo->prepare(
    "SELECT subscriber_id FROM newsletter_subscriber WHERE subscriber_email=? LIMIT 1"
);
$stmt->execute([$email]);
if ($stmt->fetchColumn()) pass("newsletter_subscriber confirmed");
else fail("newsletter_subscriber not found");

// ── AUTH-6 + AUTH-7: Logged-in checkout + gift message ───────────────────────

echo "\n=== AUTH-6+7: Logged-in checkout + gift message ===\n";

// Get customer bearer token (JWT utypid=3 → authenticated role in RequestTaintPlugin)
$tokenResp = reqJson('POST', "$base/rest/V1/integration/customer/token",
    ['username' => $email, 'password' => 'Booyah1!']);
$token = trim($tokenResp['body'], '"');
$auth  = "Authorization: Bearer $token";

// Create cart
$cartResp = reqJson('POST', "$base/rest/V1/carts/mine", [], [$auth]);
$cartId   = json_decode($cartResp['body'], true);
echo "  Cart ID: $cartId (HTTP {$cartResp['code']})\n";

if (is_int($cartId) && $cartId > 0) {
    // Add product
    reqJson('POST', "$base/rest/V1/carts/mine/items", [
        'cartItem' => ['sku' => 'BOOYAH-PHONE-001', 'qty' => 1, 'quote_id' => $cartId]
    ], [$auth]);

    $addr = [
        'region' => 'California', 'region_id' => 12, 'region_code' => 'CA',
        'country_id' => 'US', 'street' => [$tag . '_COST'],
        'postcode' => '94105', 'city' => 'San Francisco',
        'firstname' => $tag . '_COFIRST', 'lastname' => $tag . '_COLAST',
        'email' => $email, 'telephone' => '5555550102',
    ];

    reqJson('POST', "$base/rest/V1/carts/mine/estimate-shipping-methods",
        ['address' => $addr], [$auth]);
    reqJson('POST', "$base/rest/V1/carts/mine/shipping-information", [
        'addressInformation' => [
            'shipping_address' => $addr, 'billing_address' => $addr,
            'shipping_carrier_code' => 'flatrate', 'shipping_method_code' => 'flatrate',
        ]
    ], [$auth]);

    // Gift message
    $giftResp = reqJson('POST', "$base/rest/V1/carts/mine/gift-message", [
        'giftMessage' => [
            'recipient' => $tag . 'GIFTRECIP', 'sender' => $tag . 'GIFTSENDER',
            'message'   => $tag . 'GIFTMSG',  'customer_id' => 0, 'gift_message_id' => 0,
        ]
    ], [$auth]);
    echo "  Gift message → HTTP {$giftResp['code']}\n";

    // Place order
    $orderResp = reqJson('POST', "$base/rest/V1/carts/mine/payment-information", [
        'email' => $email, 'paymentMethod' => ['method' => 'checkmo'],
        'billingAddress' => $addr,
    ], [$auth]);
    $orderId = json_decode($orderResp['body'], true);
    echo "  Place order → HTTP {$orderResp['code']}\n";
    if ((is_int($orderId) || (is_string($orderId) && is_numeric($orderId))) && (int)$orderId > 0) {
        $orderId = (int)$orderId;
        pass("Order placed", "order_id=$orderId");
        $stmt = $pdo->prepare(
            "SELECT entity_id FROM sales_order_address WHERE parent_id=? AND firstname LIKE ? LIMIT 1"
        );
        $stmt->execute([$orderId, $tag . '%']);
        $aId = $stmt->fetchColumn();
        $aId ? pass("sales_order_address written", "entity_id=$aId")
             : fail("sales_order_address not found");
    } else {
        fail("Order not placed", substr($orderResp['body'], 0, 150));
    }
} else {
    fail("Cart creation failed", "response: " . substr($cartResp['body'], 0, 100));
}

// ── Summary ───────────────────────────────────────────────────────────────────

echo "\n=== MySQL taint event counts (run_id=$runId) ===\n";
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

echo "\nTag: $tag\nDone.\n";
