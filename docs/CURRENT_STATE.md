# Current State — 2026-05-04

## Completed

### Layer 1: Joern CPG taint analysis
- CPG built from `app/`, `lib/`, `setup/src/` (vendor excluded)
- CPG size: 77 MB (`joern_cpg/magento_app.bin` — not committed, too large)
- **72 taint flows found** → `results/joern_xss.json` (382 KB)
- All 1st order (HTTP input → direct output)
- Top sources: `$this->getRequest()->getParam()` (63/72 flows)
- Top sinks: `toHtml` (36), `getLayout` (20), `createBlock` (5)
- Path lengths: 4–93 steps
- Unique sink files: 30, unique source files: 29

### Layer 2: Psalm taint analysis
- Scanned 23,205 files (app/ + lib/ + setup/src/ + generated/)
- `setup:di:compile` run inside Docker to generate 3,647 PHP files first
- **29 findings** → `results/psalm_taint.json` (361 KB)
- All in `lib/internal/Magento/Framework/`
- Breakdown: TaintedHtml (12), TaintedTextWithQuotes (6), TaintedSSRF (5), TaintedExtract (1), TaintedCallable (1), TaintedFile (1), TaintedUnserialize (1), TaintedCookie (1), TaintedInclude (1)
- Runtime: ~90 min, PHP 8.4, --threads=1, 9 GB peak RAM

### Layer 3: Static route extraction
- **945 routes** extracted → `results/routes.json` (401 KB)
- 508 frontend, 435 adminhtml, 2 unknown area
- Each route has: URL, area, controller FQN, file path, params

### Infrastructure
- Magento 2.4.8-p4 running at http://localhost:8082/ (Docker)
- Admin: http://localhost:8082/admin/
- 1 admin + 2 customers + 8 restricted admin accounts created
- DI compilation complete (generated/ has 3,647 files)

## Pending

### Correlation engine
- `booyah/correlate/correlate.py` — written, not yet run
- Needs: Psalm output + Joern output + routes (all available)
- Produces: `results/correlated_findings.json` with STATIC_CONFIRMED classification

### Graph loading
- Schema designed (see `docs/SCHEMA.md`)
- `booyah/graph/neo4j_loader.py` — scaffolding exists, not yet run
- Neo4j: needs to be started locally
- SQLite: schema written, DB not yet created

### PHP runtime instrumentation (Layer 4)
- Design complete (see `docs/ARCHITECTURE_PLAN.md`)
- `booyah/instrumentor/` directory exists but `instrument.php` and `Booyah\Tracer` class not yet written
- Blocks: runtime trace collection, 2nd order lineage confirmation

### Crawl (Layer 5)
- ZAP: installed at `/Applications/ZAP.app`, needs daemon launch
- Playwright: v1.59.1 installed
- `booyah/crawl/zap_seed.py`: written
- `booyah/crawl/playwright_crawl.js`: written
- Blocks: HTTP-level route confirmation, ZAP active scan alerts
- Prerequisite: data seeder (products/categories/orders) not yet built

### Bubble Analysis
- Design complete (see `docs/BUBBLE_ANALYSIS.md`)
- Implementation: not started
- Requires: populated graph store

## Known tool failures

See `results/tool_failures.jsonl` for full log. Summary:
- Joern: php2cpg binary missing (fixed: extracted from .zip)
- Joern: overflowdb import incompatibility (fixed: removed import)
- Joern: traversal exhaustion with `val` (fixed: changed to `def`)
- Psalm: amphp crash with --threads>1 on macOS PHP 8.4 (fixed: --threads=1)
- Psalm: generated/ not in projectFiles (fixed: added to psalm.xml)
- Psalm: ProductExtensionInterface missing (fixed: ran setup:di:compile)
