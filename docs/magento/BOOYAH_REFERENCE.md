# Booyah — Application Reference

## Infrastructure

| Item | Value |
|---|---|
| Magento URL | http://localhost:8082 |
| Admin Panel | http://localhost:8082/admin |
| Store 1 Frontend | http://localhost:8082/ |
| Store 2 Frontend | http://localhost:8082/?___store=store2 |
| PHP container | magento2-248-p4-php-1 |
| Nginx container | magento2-248-p4-nginx-1 |
| DB container | magento2-248-p4-db-1 |
| DB host (external) | 127.0.0.1:3307 |
| DB user/pass | magento / magento |
| DB name | magento |
| Taint enabled env | BOOYAH_TAINT_ENABLED=1 (set in php container) |
| Trace DB | results/runtime_trace.db |
| Booyah DB | results/booyah.db |

---

## Admin Accounts

| Username | Password | Role | Scope |
|---|---|---|---|
| admin | Admin@Booyah1 | Administrators (full access) | Both stores |
| booyah_crawl | Crawl@Booyah1 | Administrators (full access) | Both stores |
| admin_sales | Sales@Booyah1 | SalesRole | Store 1 logical |
| admin_catalog | Catalog@Booyah1 | CatalogRole | Store 1 logical |
| admin_customers | Customers@Booyah1 | CustomersRole | Store 1 logical |
| admin_marketing | Marketing@Booyah1 | MarketingRole | Store 1 logical |
| admin_content | Content@Booyah1 | ContentRole | Store 1 logical |
| admin_reports | Reports@Booyah1 | ReportsRole | Store 1 logical |
| admin_stores | Stores@Booyah1 | StoresRole | Store 1 logical |
| admin_system | System@Booyah1 | SystemRole | Store 1 logical |
| store2_sales | Sales2@Booyah1 | SalesRole | Store 2 logical |
| store2_catalog | Catalog2@Booyah1 | CatalogRole | Store 2 logical |
| store2_customers | Customers2@Booyah1 | CustomersRole | Store 2 logical |
| store2_marketing | Marketing2@Booyah1 | MarketingRole | Store 2 logical |
| store2_content | Content2@Booyah1 | ContentRole | Store 2 logical |
| store2_reports | Reports2@Booyah1 | ReportsRole | Store 2 logical |
| store2_stores | Stores2@Booyah1 | StoresRole | Store 2 logical |
| store2_system | System2@Booyah1 | SystemRole | Store 2 logical |

> CE has no per-website admin scope enforcement. Account separation is logical only — all admin accounts can technically access all areas.

---

## Customer Accounts

### Store 1

| Email | Password | Name | Customer ID |
|---|---|---|---|
| alice@booyah.local | Alice@Booyah1 | Alice Booyah | 1 |
| bob@booyah.local | Bob@Booyah1 | Bob Booyah | 2 |

### Store 2

| Email | Password | Name | Notes |
|---|---|---|---|
| carol@booyah.local | Carol@Booyah1 | Carol Booyah | Store 2 customer |
| dave@booyah.local | Dave@Booyah1 | Dave Booyah | Store 2 customer |

---

## Store Structure

| Website | Website Code | Store Group | Store View | Store Code | ID |
|---|---|---|---|---|---|
| Main Website | base | Main Website Store | Default Store View | default | 1 |
| Website 2 | website2 | Store Group 2 | Store 2 | store2 | 2 |

---

## Products

### Store 1 (website_id=1)

| Product ID | SKU | Name | Category |
|---|---|---|---|
| 2 | BOOYAH-PHONE-001 | Booyah Phone | id=3 (Booyah Electronics) |
| 3 | BOOYAH-HOODIE-001 | Booyah Hoodie | id=4 (Booyah Clothing) |
| 4 | BOOYAH-BOOK-001 | Booyah Book | id=5 (Booyah Books) |
| 5 | BOOYAH-CABLE-001 | Booyah Cable | id=3 (Booyah Electronics) |
| 7 | BOOYAH-LAPTOP-001 | Booyah Laptop | id=3 (Booyah Electronics) |

### Store 2 (website_id=2)

| Product ID | SKU | Name | Notes |
|---|---|---|---|
| 8 | BSYH-S2-LAPTOP-001 | S2 Laptop | Store 2 product |
| 9 | BSYH-S2-PHONE-002 | S2 Phone | Store 2 product |
| 10 | BSYH-S2-USB-003 | S2 USB Hub | Store 2 product |

---

## Categories (Store 1)

| ID | Name |
|---|---|
| 3 | Booyah Electronics |
| 4 | Booyah Clothing |
| 5 | Booyah Books |

---

## Orders

| Order ID | Customer | Store | Notes |
|---|---|---|---|
| 1 | alice@booyah.local | Store 1 | Seed order |
| 2 | alice@booyah.local | Store 1 | Seed order |
| 3 | alice@booyah.local | Store 1 | Seed order |
| 4 | alice@booyah.local | Store 1 | Seed order |
| 5 | alice@booyah.local | Store 1 | Seed order |

---

## CMS Pages

| ID | Identifier | Title |
|---|---|---|
| 1 | no-route | 404 Not Found |
| 2 | home | Home Page |
| 3 | enable-cookies | Enable Cookies |
| 4 | privacy-policy-cookie-restriction-mode | Privacy Policy |

---

## Customer Groups

| ID | Name |
|---|---|
| 0 | NOT LOGGED IN |
| 1 | General |
| 2 | Wholesale |
| 3 | Retailer |

---

## Taint Tokens

| Context | Prefix | Purpose |
|---|---|---|
| Store 1 all roles | `bSRC_` | Standard Store 1 taint |
| Store 2 all roles | `bS2C_` | Store 2 taint — any bS2C in Store 1 response = leak |
| Generic | `BSYH` | Recognized by Probe.php as taint |

---

## Key API Endpoints

```
# Admin login
POST http://localhost:8082/admin/admin/auth/login/

# REST API base
http://localhost:8082/rest/V1/

# Store 2 context (append to any frontend URL)
?___store=store2

# Admin store context (append to any admin URL)
?___store=store2
```

---

## Database Quick Access

```bash
# Runtime trace
sqlite3 results/runtime_trace.db

# Booyah correlation DB
sqlite3 results/booyah.db

# MySQL via docker
docker exec -it magento2-248-p4-db-1 mysql -u magento -pmagento magento

# PHP bootstrap in container
docker exec magento2-248-p4-php-1 php -r "
require '/var/www/html/app/bootstrap.php';
\$om = \Magento\Framework\App\Bootstrap::create(BP,[])->getObjectManager();
\$om->get('\Magento\Framework\App\State')->setAreaCode('adminhtml');
// ... your code
"
```

---

## Trace Job

```bash
# Full 6-phase run
python3 -m booyah.crawl.trace_job \
    --magento-url http://localhost:8082 \
    --booyah-db results/booyah.db \
    --trace-db results/runtime_trace.db \
    --magento-db-host 127.0.0.1 --magento-db-port 3307 \
    --magento-db-user magento --magento-db-pass magento \
    --magento-db-name magento

# Single phase
python3 -m booyah.crawl.trace_job --phases 1

# Extract lineages only (no crawl)
python3 -m booyah.correlate.runtime_lineages \
    --trace results/runtime_trace.db \
    --booyah results/booyah.db
```

---

## Result Queries

```sql
-- Cross-store contamination check
SELECT route_url, taint_id FROM playbook_results
WHERE store_code='default' AND taint_id LIKE 'bS2C%';

-- Proven taint flows by store
SELECT store_code, COUNT(*) FROM playbook_results WHERE proven=1 GROUP BY store_code;

-- Runtime lineages
SELECT source_fn, sink_fn, occurrence_count FROM runtime_lineages ORDER BY occurrence_count DESC;

-- Reflected XSS candidates
SELECT role, route_url, taint_id FROM playbook_results WHERE taint_reflected=1;

-- Stored XSS candidates
SELECT role, route_url, taint_id FROM playbook_results WHERE taint_in_db=1;
```
