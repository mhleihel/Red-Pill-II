# Booyah — Real XSS Data Flow Mapping

## What was wrong with the previous approach
Pattern matching on YAML lists is not data flow analysis. Entity-level taint is not variable-level taint. This plan replaces all of that with three concrete, deterministic layers that each independently discover flows, and a fourth layer that confirms them at runtime.

---

## Four-Layer Architecture

```
Layer 1: CodeQL          — inter-procedural, variable-level, structural (not named) sources/sinks
Layer 2: Joern           — independent CPG-based taint, cross-validates CodeQL
Layer 3: PHP Instrumentation — deterministic AST transform, observes actual runtime data flow
Layer 4: ZAP + Playwright — exercises the live app, triggers instrumented paths

Correlation engine: CONFIRMED = L1∩L2∩L3, SUSPECTED = L1∩L2 only, GAP = L3 only
Storage: Neo4j (full graph) + SQLite (pipeline state)
```

---

## How This Solves the Three Problems

**1. No hardcoded function names.**
CodeQL defines sources as *structural types*: any expression whose type implements `Psr\Http\Message\ServerRequestInterface`, `Magento\Framework\App\RequestInterface`, or any class reachable from the framework's HTTP boundary. A new PHP app requires identifying one interface, not a YAML list.

**2. Custom logic and intermediate transforms.**
CodeQL's inter-procedural taint tracking follows data through every function body including custom wrappers. If `myEscape($x)` is called, CodeQL analyzes its body. If it returns a sanitized value, the path ends; if it passes `$x` through, the taint continues. Same for Joern. The instrumentation layer OBSERVES this at runtime regardless.

**3. All paths between sources and sinks.**
CodeQL produces complete variable-level path evidence: every assignment, every function call, every return from source to sink. Joern produces the same independently. The instrumentation layer captures actual runtime paths that static analysis may miss (dynamic dispatch, eval, string-built function calls).

---

## Prerequisites (what needs to be installed)

| Tool | State | Action |
|---|---|---|
| CodeQL CLI 2.25.2 | ✓ installed | Download PHP extractor bundle separately |
| PHP 8.4.17 | ✓ installed | — |
| Playwright (npx) | ✓ installed | — |
| Java 21 | ✗ absent | `brew install openjdk@21` |
| Joern | ✗ absent | Download release after Java |
| OWASP ZAP | ✗ absent | `brew install --cask owasp-zap` |
| nikic/php-parser | ✗ absent | `composer require nikic/php-parser` in instrumentation subproject |
| Xdebug | ✗ absent | Not needed — replaced by AST instrumentation |
| Magento vendor/ | ✗ empty | `composer install` (needs running PHP + MySQL stack, deferred to Layer 3) |

---

## Layer 1: CodeQL

### Setup
The brew-installed CodeQL has no PHP extractor. The PHP extractor ships in the full "CodeQL bundle" available at `https://github.com/github/codeql-action/releases`. Download `codeql-bundle-osx64.tar.gz` (or arm64 variant), extract alongside or replace the brew install. The bundle includes all language extractors including PHP.

Alternatively: `codeql pack download codeql/php-all` fetches the PHP QL library; the extractor is in the bundle.

### Database build
```bash
codeql database create \
  /Users/mhleihel/Desktop/Booyah/codeql_dbs/magento \
  --language=php \
  --source-root=/Users/mhleihel/Desktop/magento2-2.4.8-p4 \
  --threads=0 \
  --overwrite
```
`--threads=0` = use all cores. Expected time: 10–30 min for 25,782 files.

### Queries to run

**Standard library queries (run all three — different taint classes):**
```bash
codeql query run \
  --database=/Users/mhleihel/Desktop/Booyah/codeql_dbs/magento \
  --output=results/codeql_reflected_xss.bqrs \
  codeql/php-queries:Security/CWE-079/ReflectedXss.ql

codeql query run \
  --database=... --output=results/codeql_stored_xss.bqrs \
  codeql/php-queries:Security/CWE-079/StoredXss.ql
```

**Custom Magento-specific source extension (one .ql file we write):**
Extend CodeQL's `RemoteFlowSource` to add:
- `Magento\Framework\App\RequestInterface::getParam()`
- `Magento\Framework\App\RequestInterface::getParams()`
- `Magento\Framework\App\RequestInterface::getPost()`
- `Magento\Framework\App\RequestInterface::getQuery()`
- Any method on a class that implements `RequestInterface` (handles custom subclasses)
This is written once in QL and covers every class that implements the interface, including third-party and custom subclasses.

**Custom sink extension:**
Extend CodeQL's `HtmlInjectionSink` / `JsInjectionSink` to add:
- `Magento\Framework\View\Element\AbstractBlock::_toHtml()` output
- Any return value from a `Block::toHtml()` call that reaches HTTP response

### Output processing
```bash
codeql bqrs decode results/codeql_reflected_xss.bqrs \
  --format=sarif-latest \
  --output=results/codeql_xss.sarif
```
SARIF format: each finding has `locations[]` (full path: source → intermediate nodes → sink) with file + line + snippet for every step.

### What CodeQL gives us
- Complete inter-procedural paths through the full call graph
- Tracks through: assignments, function calls, returns, array indexing, string concatenation
- Does NOT require knowing Magento's function names — queries target interfaces and types
- Reproducible: same source = same results

---

## Layer 2: Joern

### Setup
```bash
brew install openjdk@21
export JAVA_HOME=$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home

# Download Joern release (https://github.com/joernio/joern/releases)
# As of 2025, Joern 2.x has PHP support via php2cpg frontend
curl -L https://github.com/joernio/joern/releases/latest/download/joern-cli.zip -o joern-cli.zip
unzip joern-cli.zip -d /opt/joern
export PATH=/opt/joern/joern-cli:$PATH
```

**Important caveat on Joern PHP support:** Joern's PHP frontend (`php2cpg`) exists in the main distribution as of 2024. It uses nikic/php-parser to produce the AST and maps it to Joern's CPG schema. It is less battle-tested than Joern's Java/JavaScript support. It will work for finding paths through standard PHP patterns. Complex Magento DI patterns (virtual types, plugins, interceptors) will be partially resolved. This is why we run it as a cross-validator against CodeQL, not as the sole source of truth.

### CPG build
```bash
joern-parse \
  --language php \
  --output /Users/mhleihel/Desktop/Booyah/joern_cpg/magento.bin \
  /Users/mhleihel/Desktop/magento2-2.4.8-p4
```

### Queries (Joern query language — Scala DSL)
Write `booyah/joern/xss_taint.sc`:
```scala
// Find all paths from HTTP input sources to output sinks
val sources = cpg.call
  .name("getParam|getParams|getPost|getQuery|getContent")
  .l

val sinks = cpg.call
  .name("echo|print|printf|sprintf")
  .l ++ cpg.call.name("escapeHtml|escapeHtmlAttr").l

// Taint tracking: which sinks are reachable from sources?
val flows = sink.reachableByFlows(source).l
flows.map(_.elements.map(_.code).mkString(" -> ")).foreach(println)
```
Run: `joern --script booyah/joern/xss_taint.sc --param cpgFile=magento.bin`

### Output
Export findings to JSON via Joern's built-in export. Store in `results/joern_xss.json`.

---

## Layer 3: PHP AST Instrumentation

This layer is pure deterministic code. It does not require knowing function names in advance. It instruments the source at AST level and collects real runtime data flow.

### What it does
Using `nikic/php-parser` (PHP library, pure PHP, no extension):
1. Parse every PHP file → AST
2. Walk the AST and insert trace calls at:
   - **Every assignment where RHS contains a method call on a request-like object** (detected by: method name is one of `getParam/getPost/getQuery/getContent/getHeader` OR object type is known request class — determined by a type inference pass that reads Magento's `di.xml` to resolve virtual types)
   - **Every function/method entry point that is a Controller::execute()** (route handler boundary)
   - **Every echo, print, <?=, and template variable output**
   - **Every function call that takes a string parameter and returns a string** (potential transform — these are logged with input/output values)
3. Write instrumented copy to `/Users/mhleihel/Desktop/Booyah/instrumented/`

### The trace call inserted at sources
```php
// Before: $name = $this->getRequest()->getParam('name');
// After:
$name = $this->getRequest()->getParam('name');
\Booyah\Tracer::source($name, 'name', 'get_param', __FILE__, __LINE__, \Booyah\Tracer::requestId());
```

### The trace call inserted at sinks
```php
// Before: echo $this->escapeHtml($block->getName());
// After:
\Booyah\Tracer::sink($this->escapeHtml($block->getName()), 'echo', __FILE__, __LINE__, \Booyah\Tracer::requestId());
echo $this->escapeHtml($block->getName());
```

### The trace call inserted at transforms
```php
// Before: $clean = $this->escapeHtml($dirty);
// After:
$clean = $this->escapeHtml($dirty);
\Booyah\Tracer::transform($dirty, $clean, 'escapeHtml', __FILE__, __LINE__, \Booyah\Tracer::requestId());
```

### The Tracer class
`\Booyah\Tracer` is a PHP class (autoloaded via Composer) that:
- Assigns a UUID per HTTP request
- Logs to a structured JSON file (`/var/log/booyah_trace.json`) or directly to SQLite
- Each log entry: `{request_id, type: source|sink|transform, function, file, line, value_hash, value_truncated, timestamp}`
- Uses value *hashing* (SHA-256 of value) to track identity through transforms without storing sensitive data

### Why value hashing works
When source value hash H appears in a sink log entry → the value reached that sink. When `transform($in_hash, $out_hash)` is logged, we learn whether `$in_hash == $out_hash` (no change), `$out_hash` is new (sanitized), or both are tracked. This gives us a complete data flow graph from real execution without storing PII.

### Instrumentation script
`booyah/instrumentor/instrument.php`:
- Accepts `--source-root` and `--output-root`
- Reads Magento's `etc/di.xml` to build a type map (virtual types → concrete classes)
- Instruments all PHP files
- Writes `instrumented/` directory with same structure as source
- Writes `instrumented/manifest.json`: list of {original_file, instrumented_file, injection_points[]}
- Deterministic: same source + same config = same output

---

## Layer 4: Dynamic Execution + Crawling

Requires a running Magento instance. Two sub-phases:

### 4a: Static route discovery (no running app needed)
Before starting the app, extract the full route map from source:
- Parse all `etc/frontend/routes.xml` and `etc/adminhtml/routes.xml` files → extract module/frontName mappings
- Find all classes matching `*/Controller/*/` with an `execute()` method → these are the concrete actions
- Cross-reference: each `{frontName}/{controller}/{action}` route → `{Module}\Controller\{Path}\{Action}::execute()`
- This gives the complete static route inventory

Script: `booyah/routes/extract_routes.py` — reads XML and PHP files, outputs `routes.json`:
```json
[
  {"url": "/catalog/product/view", "module": "Magento_Catalog",
   "controller": "Magento\\Catalog\\Controller\\Product\\View",
   "method": "execute", "area": "frontend", "params": ["id", "category"]}
]
```
No running app needed. Deterministic.

### 4b: Crawl + trace (running app required)
For this phase, Magento must be running (needs MySQL, Redis, PHP-FPM). This is deferred until the user sets up the stack. When ready:

**ZAP spider:**
```bash
# Start ZAP in daemon mode
zap.sh -daemon -port 8090 -config api.key=booyah

# Seed the spider with all discovered routes from routes.json
python3 booyah/crawl/zap_seed.py --routes routes.json --zap-url http://localhost:8090

# Run the spider
curl "http://localhost:8090/JSON/spider/action/scan/?url=http://localhost:8082&apikey=booyah"

# Run active XSS scanner on crawled URLs
curl "http://localhost:8090/JSON/ascan/action/scan/?url=http://localhost:8082&apikey=booyah&scanpolicyname=XSS"
```

**Playwright crawler (for JS-rendered pages and auth flows):**
`booyah/crawl/playwright_crawl.js`:
- Authenticates to Magento frontend and admin
- Visits every route from `routes.json`
- Fills input fields with instrumented payloads (tagged values: `booyah_SRC_001`, etc.)
- Logs all network responses
- Runs headless Chromium via Playwright

**PHP instrumentation trace collection:**
While ZAP + Playwright run, the instrumented Magento instance writes to `booyah_trace.db`. After the crawl, collect traces.

---

## Correlation Engine

`booyah/correlate/correlate.py`:

**Input:**
- `codeql_xss.sarif` — CodeQL findings with full path evidence
- `joern_xss.json` — Joern findings
- `booyah_trace.db` — runtime trace from instrumented crawl
- `routes.json` — complete static route inventory
- `zap_alerts.json` — ZAP confirmed XSS alerts

**Correlation logic:**

For each CodeQL finding:
1. Does Joern have a finding on the same sink (file + line ± 3)?  → cross-validated
2. Does the runtime trace show the source → sink value hash path?  → runtime confirmed
3. Does ZAP report an active XSS alert on the URL that triggers this controller? → exploitable confirmed

**Classification:**
| Label | Condition |
|---|---|
| `CONFIRMED_EXPLOITABLE` | CodeQL + Joern + runtime trace + ZAP alert |
| `CONFIRMED` | CodeQL + Joern + runtime trace |
| `STATIC_CONFIRMED` | CodeQL + Joern, no runtime (path may be dead code or untriggered) |
| `CODEQL_ONLY` | CodeQL found it, Joern did not — investigate |
| `JOERN_ONLY` | Joern found it, CodeQL did not — investigate |
| `RUNTIME_ONLY` | Instrumentation found source→sink, static missed — static coverage gap |
| `ZAP_UNMATCHED` | ZAP confirmed XSS, no static path — likely dynamic eval or header injection |

**Coverage metrics:**
- Routes: `len(crawled_routes) / len(static_routes_inventory)`
- Static paths confirmed at runtime: `CONFIRMED / (CONFIRMED + STATIC_CONFIRMED)`
- Sinks reached: `sinks_in_any_confirmed_path / total_sinks_in_codebase`
- Controller entry points exercised: `controllers_with_runtime_trace / total_controllers`

---

## Neo4j Graph Model

All results from all layers stored in one graph. Nodes:
- `(:Route {url, module, controller, area})`
- `(:Function {fqn, file, line})`
- `(:Source {type, file, line, expression})`
- `(:Sink {type, context, file, line, expression})`
- `(:Sanitizer {function, covers_context, file, line})`
- `(:TaintPath {id, classification, confidence, tool})`
- `(:RuntimeTrace {request_id, source_hash, sink_hash, confirmed})`

Relationships:
- `(:Route)-[:DISPATCHES]->(:Function)`
- `(:Function)-[:CALLS]->(:Function)`
- `(:TaintPath)-[:FROM]->(:Source)`
- `(:TaintPath)-[:TO]->(:Sink)`
- `(:TaintPath)-[:THROUGH]->(:Function)` (every hop)
- `(:TaintPath)-[:CONFIRMED_BY]->(:RuntimeTrace)`
- `(:TaintPath)-[:SANITIZED_BY]->(:Sanitizer)`

Sample query — all unprotected paths reachable from frontend routes:
```cypher
MATCH (r:Route {area:'frontend'})-[:DISPATCHES*1..5]->(f:Function)
      <-[:THROUGH|FROM]-(p:TaintPath {classification:'CONFIRMED_EXPLOITABLE'})
      -[:TO]->(s:Sink)
RETURN r.url, s.file, s.line, p.confidence
ORDER BY p.confidence DESC
```

---

## Implementation Order

1. **Install tools** (Java → Joern → ZAP) — all brew/download commands
2. **Download CodeQL PHP bundle** — replaces the brew-only version
3. **Build CodeQL database** — run once, reuse
4. **Write + run CodeQL custom queries** — custom source/sink QL extensions
5. **Build Joern CPG** — run once
6. **Write + run Joern taint queries** — Scala DSL script
7. **Write instrumentation engine** (nikic/php-parser) — `instrument.php`
8. **Write `Booyah\Tracer` PHP class** — the runtime collector
9. **Write route extractor** (`extract_routes.py`) — static route inventory from XML + PHP
10. **Write ZAP seeder + Playwright crawler** — after Magento instance is running
11. **Write correlation engine** (`correlate.py`) — merge all four layers
12. **Write Neo4j loader** — import correlation results
13. **Write coverage report** — final metrics

Steps 1–9 and 11–13 do not require a running Magento instance.
Step 10 requires it.

---

## Reproducibility on Other PHP Apps

To apply this to a new PHP application:
1. **CodeQL**: Write one `.ql` file that extends `RemoteFlowSource` with the new app's request interface/class. Everything else reuses the standard query library.
2. **Joern**: Update method names in the taint query script to match the new framework's request methods.
3. **Instrumentation**: Update the type map config (which class is the request object). The AST transformation code is unchanged.
4. **Route extractor**: Write one parser for the new framework's routing config (e.g., Laravel's `routes/web.php`, Symfony's `config/routes.yaml`). The rest is unchanged.
5. **Crawler + ZAP**: Unchanged — they operate on the running HTTP application regardless of framework.

The only per-framework work is steps 1, 2, 4 — and these are small, well-defined files.
