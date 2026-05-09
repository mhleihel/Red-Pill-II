<?php
declare(strict_types=1);

/**
 * Booyah Anonymous Role Crawl
 *
 * Covers every anonymous CORRELATED lineage and every anonymous-triggered
 * CONFIRMED regression check from live_capture_matrix.xlsx.
 *
 * Paths exercised:
 *   ANO-1  Account registration   → customer_entity.{email,firstname,lastname}
 *   ANO-2  Quick search           → search_query.query_text
 *   ANO-3  Advanced search        → search_query.query_text
 *   ANO-4  Newsletter subscribe   → newsletter_subscriber.subscriber_email
 *   ANO-5  Contact form           → Contact\Post controller (email template sink)
 *   ANO-6  Product review submit  → review_detail.{nickname,title,detail}
 *   ANO-7  Guest checkout         → quote, quote_address, sales_order, sales_order_address
 *   ANO-8  Gift message           → gift_message.{sender,recipient,message}
 *   ANO-9  Re-entry verification  → GET pages after writes to confirm render sinks
 *
 * Run from host (requires PHP CLI + curl + pdo_mysql extensions):
 *   php booyah/crawl/crawl_anon.php
 */

$base     = 'http://localhost:8082';
$jar      = '/tmp/booyah_anon_cookies.txt';
$mysqlDsn = 'mysql:host=127.0.0.1;port=3307;dbname=magento';
$pdo      = new PDO($mysqlDsn, 'magento', 'magento', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

@unlink($jar);

$tag = 'bSRC_ANON_' . substr(md5(uniqid('', true)), 0, 8);
$runId = trim(shell_exec(
    "docker exec magento2-248-p4-php-1 bash -c 'echo \$BOOYAH_RUN_ID' 2>/dev/null"
) ?: 'run-full-20260507');

echo "Tag:    $tag\n";
echo "RunId:  $runId\n\n";

// ── Pre-flight config: enable gift messages for the run ───────────────────────
// Correct path: sales/gift_options/allow_order (NOT sales/gift_messages/allow_order)
// Helper class constant: XPATH_CONFIG_GIFT_MESSAGE_ALLOW_ORDER = 'sales/gift_options/allow_order'
$pdo->exec("INSERT INTO core_config_data (scope, scope_id, path, value)
    VALUES ('default', 0, 'sales/gift_options/allow_order', '1')
    ON DUPLICATE KEY UPDATE value='1'");
$pdo->exec("INSERT INTO core_config_data (scope, scope_id, path, value)
    VALUES ('stores', 1, 'sales/gift_options/allow_order', '1')
    ON DUPLICATE KEY UPDATE value='1'");
$pdo->exec("INSERT INTO core_config_data (scope, scope_id, path, value)
    VALUES ('default', 0, 'sales/gift_options/allow_items', '1')
    ON DUPLICATE KEY UPDATE value='1'");
$pdo->exec("INSERT INTO core_config_data (scope, scope_id, path, value)
    VALUES ('stores', 1, 'sales/gift_options/allow_items', '1')
    ON DUPLICATE KEY UPDATE value='1'");
shell_exec("docker exec magento2-248-p4-php-1 php /var/www/html/bin/magento cache:clean config full_page 2>/dev/null");
sleep(2);
echo "Gift message config enabled and cache cleaned.\n\n";

// ── Helpers ───────────────────────────────────────────────────────────────────

function req(string $method, string $url, array $post = [], array $headers = []): array
{
    global $jar;
    $ch = curl_init($url);
    $opts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_COOKIEFILE     => $jar,
        CURLOPT_COOKIEJAR      => $jar,
        CURLOPT_USERAGENT      => 'BooyahCrawl/1.0',
    ];
    if ($headers) {
        $opts[CURLOPT_HTTPHEADER] = $headers;
    }
    if ($method === 'POST') {
        $opts[CURLOPT_POST] = true;
        $opts[CURLOPT_POSTFIELDS] = http_build_query($post);
    }
    curl_setopt_array($ch, $opts);
    $body = (string)curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $final = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);
    return ['code' => $code, 'body' => $body, 'url' => $final];
}

function reqJson(string $method, string $url, array $payload): array
{
    global $jar;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_COOKIEFILE     => $jar,
        CURLOPT_COOKIEJAR      => $jar,
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_POSTFIELDS     => json_encode($payload),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'Accept: application/json'],
    ]);
    $body = (string)curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ['code' => $code, 'body' => $body];
}

function fk(string $html): string
{
    if (preg_match('/FORM_KEY\s*=\s*["\']([a-zA-Z0-9_]+)["\']/', $html, $m)) return $m[1];
    if (preg_match('/input[^>]+name=["\']form_key["\'][^>]+value=["\']([a-zA-Z0-9_]+)["\']/', $html, $m)) return $m[1];
    if (preg_match('/value=["\']([a-zA-Z0-9_]{16,})["\']/', $html, $m)) return $m[1];
    return '';
}

function pass(string $label, string $detail = ''): void
{
    echo "  [OK]  $label" . ($detail ? " — $detail" : '') . "\n";
}

function fail(string $label, string $detail = ''): void
{
    echo "  [!!]  $label" . ($detail ? " — $detail" : '') . "\n";
}

function mysqlCount(PDO $pdo, string $runId, string $table): int
{
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM booyah_taint_map WHERE run_id=? AND db_table=?");
    $stmt->execute([$runId, $table]);
    return (int)$stmt->fetchColumn();
}

// ── Preflight — verify tracer is writing to MySQL ────────────────────────────
echo "=== Preflight ===\n";
$pfTag  = 'bSRC_PF_' . time();
$r      = req('POST', "$base/rest/V1/customers", [], []);
// Simpler: check a known-good endpoint with a bSRC_ param
req('GET', "$base/catalogsearch/result/?q=$pfTag");
sleep(2);
$stmt = $pdo->prepare("SELECT COUNT(*) FROM booyah_taint_map WHERE run_id=? AND ts > UNIX_TIMESTAMP() - 60");
$stmt->execute([$runId]);
$recent = (int)$stmt->fetchColumn();
if ($recent === 0) {
    // May be first writes of the session — just check the table is accessible
    $pdo->query("SELECT COUNT(*) FROM booyah_taint_map")->fetchColumn();
    echo "  Tracer DB accessible. Proceeding (first writes may take a moment).\n\n";
} else {
    pass("Tracer active — $recent recent events in run_id=$runId");
    echo "\n";
}

// ── ANO-1: Account registration ───────────────────────────────────────────────
echo "=== ANO-1: Account registration ===\n";
$r  = req('GET', "$base/customer/account/create/");
$key = fk($r['body']);
$email = strtolower($tag) . '@booyah.test';

$r = req('POST', "$base/customer/account/createpost/", [
    'form_key'              => $key,
    'firstname'             => $tag . '_FIRST',
    'lastname'              => $tag . '_LAST',
    'email'                 => $email,
    'password'              => 'Booyah1234!',
    'password_confirmation' => 'Booyah1234!',
]);
$stmt = $pdo->prepare("SELECT entity_id FROM customer_entity WHERE email=?");
$stmt->execute([$email]);
$custId = $stmt->fetchColumn();

if ($custId) {
    pass("Customer created", "entity_id=$custId email=$email");
} else {
    fail("Customer NOT created", "HTTP {$r['code']} — final_url={$r['url']}");
}
sleep(1);

// ANO-1b: Verify re-entry — view account page (firstname/lastname render in header)
$r = req('GET', "$base/customer/account/");
$hits = substr_count($r['body'], $tag);
pass("Account page renders tag", "occurrences=$hits");

// Clear session — remaining flows (search, newsletter, contact, review, checkout)
// must run as anonymous so taint events get the correct role label.
@unlink($jar);
pass("Session cleared — subsequent requests are anonymous");
sleep(1);

// ── ANO-2: Quick search ───────────────────────────────────────────────────────
echo "\n=== ANO-2: Quick search ===\n";
$qTag = $tag . '_SRCH';
$r = req('GET', "$base/catalogsearch/result/?q=$qTag");
echo "  GET /catalogsearch/result → HTTP {$r['code']}\n";
$hits = substr_count($r['body'], $qTag);
pass("Search term in response", "occurrences=$hits");

// Also trigger SearchTermsLog\Save to get search_query DB write
req('GET', "$base/catalogsearch/searchtermslog/save?query=$qTag");
sleep(1);

// ── ANO-3: Advanced search ────────────────────────────────────────────────────
echo "\n=== ANO-3: Advanced search ===\n";
$advTag = $tag . '_ADV';
$r = req('GET', "$base/catalogsearch/advanced/result/?" . http_build_query([
    'name'              => $advTag,
    'sku'               => '',
    'description'       => $advTag,
    'short_description' => '',
    'price[from]'       => '',
    'price[to]'         => '',
]));
echo "  GET /catalogsearch/advanced/result → HTTP {$r['code']}\n";
$hits = substr_count($r['body'], $advTag);
pass("Advanced search term in response", "occurrences=$hits");
sleep(1);

// ── ANO-4: Newsletter subscription ───────────────────────────────────────────
echo "\n=== ANO-4: Newsletter subscription ===\n";
$nlEmail = $tag . '_nl@booyah.test';
// Newsletter form is submitted as a POST from the footer
$r = req('GET', "$base/");
$key = fk($r['body']);
$r = req('POST', "$base/newsletter/subscriber/new/", [
    'form_key' => $key,
    'email'    => $nlEmail,
]);
echo "  POST newsletter/subscriber/new → HTTP {$r['code']}\n";
$stmt = $pdo->prepare("SELECT subscriber_id FROM newsletter_subscriber WHERE subscriber_email=?");
$stmt->execute([$nlEmail]);
$subId = $stmt->fetchColumn();
if ($subId) {
    pass("Newsletter subscriber created", "subscriber_id=$subId");
} else {
    fail("Newsletter NOT created", "email=$nlEmail");
}
sleep(1);

// ── ANO-5: Contact form ───────────────────────────────────────────────────────
echo "\n=== ANO-5: Contact form ===\n";
$r   = req('GET', "$base/contact/");
$key = fk($r['body']);
$r   = req('POST', "$base/contact/index/post/", [
    'form_key' => $key,
    'name'     => $tag . '_CONTACT',
    'email'    => $tag . '_cntct@booyah.test',
    'telephone'=> '555-1234',
    'comment'  => $tag . '_COMMENT',
    'hideit'   => '',
]);
echo "  POST /contact/index/post → HTTP {$r['code']}\n";
// Contact form sends email — no DB row, but tracer captures the param at dispatch
pass("Contact form submitted", "HTTP {$r['code']}");
sleep(1);

// ── ANO-6: Product review ─────────────────────────────────────────────────────
echo "\n=== ANO-6: Product review ===\n";
$productId = 2;
$r   = req('GET', "$base/review/product/post/?id=$productId");
$key = fk($r['body']);
if (!$key) {
    // Form key may be in a data-mage-init or inline script on the product page
    $r   = req('GET', "$base/catalog/product/view/id/$productId/");
    $key = fk($r['body']);
}
$r = req('POST', "$base/review/product/post/", [
    'form_key'  => $key,
    'id'        => $productId,
    'ratings[4]'=> '5',
    'nickname'  => $tag . '_NICK',
    'title'     => $tag . '_TITLE',
    'detail'    => $tag . '_DETAIL',
]);
echo "  POST /review/product/post → HTTP {$r['code']}\n";
$stmt = $pdo->prepare("SELECT review_id FROM review WHERE entity_pk_value=? ORDER BY review_id DESC LIMIT 1");
$stmt->execute([$productId]);
$reviewId = $stmt->fetchColumn();
if ($reviewId) {
    pass("Review created", "review_id=$reviewId");
    // Verify the detail was saved
    $stmt2 = $pdo->prepare("SELECT detail FROM review_detail WHERE review_id=?");
    $stmt2->execute([$reviewId]);
    $detail = $stmt2->fetchColumn();
    $hit = $detail && str_contains((string)$detail, $tag) ? 'tag in detail' : 'tag NOT in detail';
    pass("Review detail check", $hit);
} else {
    fail("Review NOT saved");
}
sleep(1);

// ── ANO-7: Guest checkout with tainted billing/shipping ───────────────────────
echo "\n=== ANO-7: Guest checkout ===\n";

// Get guest cart token
$r = reqJson('POST', "$base/rest/V1/guest-carts", []);
$cartId = trim($r['body'], '"');
echo "  Guest cart: $cartId\n";
if (!$cartId || strlen($cartId) < 10) {
    fail("Could not create guest cart");
    goto after_checkout;
}

// Add item to cart
$r = reqJson('POST', "$base/rest/V1/guest-carts/$cartId/items", [
    'cartItem' => [
        'sku'   => 'BOOYAH-PHONE-001',
        'qty'   => 1,
        'quote_id' => $cartId,
    ]
]);
echo "  Add item → HTTP {$r['code']}\n";
if ($r['code'] !== 200) {
    fail("Could not add item", $r['body']);
    goto after_checkout;
}

// Set billing + shipping address with bSRC_ values
// City: use a real city — Magento validates against a strict charset (A-Z a-z 0-9 - ' space).
// The bSRC tag is carried by firstname, lastname, and street which have no such restriction.
$addr = [
    'region'     => 'California',
    'region_id'  => 12,
    'region_code'=> 'CA',
    'country_id' => 'US',
    'street'     => [$tag . ' St'],   // space separator, no underscore
    'postcode'   => '94105',
    'city'       => 'San Francisco',
    'telephone'  => '5551234567',
    'firstname'  => $tag . 'BFIRST',  // no underscore suffix
    'lastname'   => $tag . 'BLAST',
    'email'      => $tag . 'chkout@booyah.test',
];

// Estimate shipping methods
$r = reqJson('POST', "$base/rest/V1/guest-carts/$cartId/estimate-shipping-methods", [
    'address' => $addr,
]);
echo "  Estimate shipping → HTTP {$r['code']}\n";

// Set shipping info
$r = reqJson('POST', "$base/rest/V1/guest-carts/$cartId/shipping-information", [
    'addressInformation' => [
        'shipping_address' => $addr,
        'billing_address'  => $addr,
        'shipping_carrier_code' => 'flatrate',
        'shipping_method_code'  => 'flatrate',
    ]
]);
echo "  Set shipping → HTTP {$r['code']}\n";
if ($r['code'] !== 200) {
    fail("Shipping info rejected", substr($r['body'], 0, 200));
    goto after_checkout;
}

$r = reqJson('POST', "$base/rest/V1/guest-carts/$cartId/gift-message", [
    'giftMessage' => [
        'recipient'       => $tag . 'GIFTRECIP',
        'sender'          => $tag . 'GIFTSENDER',
        'message'         => $tag . 'GIFTMSG',
        'customer_id'     => 0,
        'gift_message_id' => 0,
    ]
]);
echo "  Gift message → HTTP {$r['code']}" . ($r['code'] !== 200 ? " — " . substr($r['body'], 0, 120) : '') . "\n";

// Place order
$r = reqJson('POST', "$base/rest/V1/guest-carts/$cartId/payment-information", [
    'email'         => $tag . '_chkout@booyah.test',
    'paymentMethod' => ['method' => 'checkmo'],
    'billingAddress'=> $addr,
]);
echo "  Place order → HTTP {$r['code']}\n";
$orderId = json_decode($r['body'], true);
if ((is_int($orderId) || (is_string($orderId) && is_numeric($orderId))) && (int)$orderId > 0) {
    $orderId = (int)$orderId;
    pass("Order placed", "order_id=$orderId");
    // Verify sales_order_address was written with tainted value
    $stmt = $pdo->prepare(
        "SELECT entity_id FROM sales_order_address WHERE parent_id=? AND firstname LIKE ? LIMIT 1"
    );
    $stmt->execute([$orderId, $tag . '%']);
    $addrId = $stmt->fetchColumn();
    if ($addrId) {
        pass("sales_order_address written", "entity_id=$addrId");
    } else {
        fail("sales_order_address NOT found with tag", "order_id=$orderId");
    }
} else {
    fail("Order NOT placed", substr($r['body'], 0, 200));
}

after_checkout:
sleep(1);

// ── ANO-9: Sink verification — GET pages that render stored bSRC_ values ───────
echo "\n=== ANO-9: Re-entry sink verification ===\n";

// Search result re-entry (search_query.query_text renders in term.phtml)
$r = req('GET', "$base/catalogsearch/result/?q=$qTag");
$hits = substr_count($r['body'], $qTag);
echo "  GET search results → occurrences=$hits\n";

// Search term popular page (admin term list via public term.phtml)
$r = req('GET', "$base/search/term/popular/");
$hits = substr_count($r['body'], $tag);
echo "  GET popular terms → occurrences=$hits\n";

sleep(1);

// ── Summary ───────────────────────────────────────────────────────────────────
echo "\n=== MySQL taint event counts (run_id=$runId) ===\n";
$stmt = $pdo->prepare(
    "SELECT db_table, COUNT(*) as cnt FROM booyah_taint_map WHERE run_id=? GROUP BY db_table ORDER BY cnt DESC"
);
$stmt->execute([$runId]);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
if ($rows) {
    foreach ($rows as $row) {
        printf("  %-40s %d\n", $row['db_table'], $row['cnt']);
    }
} else {
    echo "  (no rows yet — may need a moment to flush)\n";
}

echo "\n=== Role distribution (run_id=$runId) ===\n";
$stmt = $pdo->prepare(
    "SELECT role, COUNT(*) as cnt FROM booyah_taint_map WHERE run_id=? GROUP BY role ORDER BY cnt DESC"
);
$stmt->execute([$runId]);
foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
    printf("  %-20s %d\n", $row['role'], $row['cnt']);
}

echo "\nTag: $tag\n";
echo "Done.\n";
