# Red Pill II — Booyah

A deterministic, multi-layer data flow mapping tool for PHP applications, targeting Magento 2.4.8-p4.

## What this is

Booyah builds a complete **sanitization map** of a PHP application — every source, every hop, every sink, every lineage — with role and execution context at each edge. It is not a vulnerability scanner. Vulnerabilities are found separately via **Bubble Analysis** run against the completed map.

## Core concepts

| Term | Definition |
|---|---|
| **Source** | Where user-controlled data enters (HTTP param, cookie, header, DB read, session read, cache read) |
| **Hop** | One function-boundary crossing where tainted data moves from one location to the next |
| **Lineage** | The ordered set of hops from a Source to a Sink — the complete data flow path |
| **Sink** | Where data is output/executed/stored (HTML output, JS block, URL, DB write, file, unserialize, include) |
| **Order** | 1st = HTTP input → direct output; 2nd = input → persistence write → persistence read → output; 3rd+ = further persistence boundaries crossed |
| **Context** | Role (anonymous/customer/admin/ACL) + execution type (URL, HTML_BODY, HTML_ATTR, JS_STRING, JS_BLOCK, SQL, FILE, PHP_EVAL) at each hop |

## Bubble Analysis

Run after the map is complete:

- **Forward**: Walk source → sink, recording what sanitization is applied at each hop and what contexts it covers
- **Backward**: Walk sink → source, computing what protection the sink context requires, and what each hop's sanitization provides toward that requirement
- **Intersection**: `required_protection - applied_protection = gap`. Every gap is a candidate for manual review.

## Architecture

```
Layer 1: Joern CPG taint analysis     → results/joern_xss.json     (72 flows, 1st order)
Layer 2: Psalm taint analysis         → results/psalm_taint.json    (29 findings, 1st order)
Layer 3: Static route extraction      → results/routes.json          (945 routes)
Layer 4: PHP AST instrumentation      → runtime trace DB             (all orders, runtime-confirmed)
Layer 5: ZAP + Playwright crawl       → ZAP alerts + reflection log  (HTTP-level confirmation)
Correlation engine                    → results/correlated_findings.json
Graph store                           → Neo4j + SQLite
```

## Current state (as of 2026-05-04)

- Layers 1, 2, 3 complete
- Layer 4 (PHP instrumentation): design complete, implementation pending
- Layer 5 (crawl): ZAP installed, Playwright installed, scripts written, not yet run
- Correlation engine: written, not yet run against current data
- Neo4j: not yet loaded
- SQLite: schema designed, not yet populated

## Failure handling

See [docs/FAILURE_HANDLING.md](docs/FAILURE_HANDLING.md) — every operation has explicit success criteria, named gap types, and a conservative default (absence of evidence is never evidence of safety).

## Setup

```bash
pip install -e .
```

Requires:
- Python 3.11+
- PHP 8.3+ (for instrumentation pass)
- Java 21 (for Joern)
- Neo4j 5.x (for graph loading)
- ZAP 2.x (`/Applications/ZAP.app`)
- Playwright (`npx playwright`)
- Running Magento 2.4.8-p4 instance (see `CREDENTIALS.md` — not committed)

## Repository structure

```
booyah/           Python package (pipeline, correlation, graph, instrumentation)
results/          Output from completed analysis layers (JSON)
joern_cpg/        Joern build logs (binary excluded — too large)
booyah/joern/     Joern taint query scripts (Scala)
docs/             Design documents, schemas, plans
tests/            Unit and integration tests
```
