# Sanitization Map — Graph Schema

## Neo4j Node Types

### Source
Where user-controlled data enters the application.

```cypher
(:Source {
  id:               String,   // unique: "{tool}:{file}:{line}"
  type:             String,   // HTTP_PARAM | HTTP_COOKIE | HTTP_HEADER | HTTP_BODY |
                              // DB_READ | SESSION_READ | CACHE_READ | FILE_READ | QUEUE_MESSAGE
  name:             String,   // param/key/column name
  file:             String,   // relative path from source root
  line:             Integer,
  order:            Integer,  // 1 = HTTP boundary, 2 = from persistence, 3+ = further
  route_url:        String,   // URL that triggers this source (null if not route-linked)
  roles_required:   [String], // ["anonymous"] | ["customer"] | ["admin"] | ["acl:Magento_Sales::sales"] | ...
  http_methods:     [String], // ["GET"] | ["POST"] | ["GET","POST"] | ...
  area:             String,   // "frontend" | "adminhtml" | "webapi_rest" | "webapi_soap" | "graphql"
  tool:             String    // "joern" | "psalm" | "static_extracted" | "runtime"
})
```

### Hop
One function-boundary crossing where tainted data moves from one code location to the next.

```cypher
(:Hop {
  id:                     String,   // unique
  function:               String,   // fully-qualified function/method name
  file:                   String,
  line:                   Integer,
  code:                   String,   // code snippet (truncated to 200 chars)
  hop_index:              Integer,  // position within the lineage (0-based)
  sanitizations:          [String], // [] | ["HTML_BODY"] | ["HTML_ATTR"] | ["JS_STRING"] |
                                    //     ["URL"] | ["CSS"] | ["SQL"] | ["JSON_ENCODE"] | ...
  encoding_state:         String,   // "RAW" | "HTML_ENCODED" | "URL_ENCODED" | "JSON_ENCODED" |
                                    //     "BASE64" | "SERIALIZED" | "UNKNOWN"
  execution_context:      String,   // "PHP" | "TEMPLATE" | "SQL" | "SHELL" | "HTTP"
  is_interceptor:         Boolean,  // true if this hop was inserted from generated interceptor
  confidence:             String,   // "measured" | "inferred" | "interpolated"
  tool:                   String
})
```

### Sink
Where data is output, executed, stored, or passed to a dangerous operation.

```cypher
(:Sink {
  id:                   String,
  type:                 String,   // HTML_BODY | HTML_ATTR | JS_STRING | JS_BLOCK |
                                  // URL | HTTP_HEADER | CSS |
                                  // DB_WRITE | SESSION_WRITE | CACHE_WRITE | FILE_WRITE |
                                  // PHP_EVAL | PHP_INCLUDE | PHP_UNSERIALIZE | PHP_CALLABLE |
                                  // EMAIL | SHELL_EXEC | SQL_QUERY
  file:                 String,
  line:                 Integer,
  code:                 String,
  order:                Integer,  // which order this sink belongs to
  is_intermediate:      Boolean,  // true = this sink is also a Source for a higher-order lineage
  execution_context:    String,   // "HTML" | "JS" | "URL" | "PHP" | "SQL" | "SHELL" | "HTTP"
  context_determined:   String,   // "DETERMINED" | "AMBIGUOUS" | "UNKNOWN"
  possible_contexts:    [String], // if AMBIGUOUS, all possible contexts
  required_protection:  [String], // what sanitization context(s) this sink requires
  tool:                 String
})
```

### Lineage
The complete ordered path from one Source to one Sink.

```cypher
(:Lineage {
  id:                     String,
  tool:                   String,   // "joern" | "psalm" | "static_extracted" | "runtime"
  order:                  Integer,  // 1 | 2 | 3+
  hop_count:              Integer,
  source_id:              String,
  sink_id:                String,
  has_sanitization:       Boolean,
  sanitization_contexts:  [String], // union of all sanitizations across all hops
  required_context:       String,   // from sink.required_protection
  gap:                    [String], // required_context - sanitization_contexts
  classification:         String,   // "CONFIRMED_EXPLOITABLE" | "CONFIRMED" | "STATIC_CONFIRMED" |
                                    // "PSALM_ONLY" | "JOERN_ONLY" | "RUNTIME_ONLY" | "ZAP_UNMATCHED"
  confidence:             Float,    // 0.0 - 1.0
  runtime_confirmed:      Boolean,
  zap_confirmed:          Boolean,
  coverage_gaps:          [String]  // named gaps: "INTERCEPTOR_GAP" | "ENCODING_STATE_UNKNOWN" |
                                    //             "TEMPLATE_CONTEXT_AMBIGUOUS" | "COVERAGE_GAP"
})
```

### Route
An HTTP entry point.

```cypher
(:Route {
  url:              String,   // e.g. "/catalog/product/view"
  area:             String,   // "frontend" | "adminhtml"
  roles_required:   [String],
  http_methods:     [String],
  controller_fqn:   String,   // e.g. "Magento\\Catalog\\Controller\\Product\\View"
  file:             String,
  verified:         Boolean,  // true = confirmed reachable by crawl
  reachability:     String    // "CONFIRMED" | "NOT_REACHABLE" | "COVERAGE_GAP" | "UNVERIFIED"
})
```

### Sanitizer
A function that provides protection for a specific context.

```cypher
(:Sanitizer {
  name:             String,   // e.g. "escapeHtml"
  fqn:              String,   // fully-qualified
  covers_context:   [String], // ["HTML_BODY"]
  strips:           [String], // what it removes/encodes
  source:           String    // "magento_escaper" | "php_builtin" | "custom"
})
```

### PersistenceBoundary
A persistence layer crossing that separates flow orders.

```cypher
(:PersistenceBoundary {
  id:               String,
  type:             String,   // "DB" | "SESSION" | "CACHE" | "FILE" | "QUEUE"
  identifier:       String,   // table name | session key | cache tag | file path pattern
  write_routes:     [String], // route URLs that write to this boundary
  read_routes:      [String]  // route URLs that read from this boundary
})
```

---

## Neo4j Relationships

```
(:Route)-[:HAS_SOURCE]->(:Source)

(:Source)-[:FIRST_HOP]->(:Hop)
(:Hop)-[:NEXT_HOP {index: Integer}]->(:Hop)
(:Hop)-[:TO_SINK]->(:Sink)

(:Lineage)-[:STARTS_AT]->(:Source)
(:Lineage)-[:ENDS_AT]->(:Sink)
(:Lineage)-[:CONTAINS {index: Integer}]->(:Hop)

(:Hop)-[:HAS_SANITIZER]->(:Sanitizer)
(:Hop)-[:CROSSES_BOUNDARY]->(:PersistenceBoundary)

// Multi-order: intermediate sink becomes next-order source
(:Sink)-[:IS_SOURCE_FOR {order: Integer}]->(:Source)

(:Route)-[:DISPATCHES_TO]->(:Source)
```

---

## SQLite Tables (mirror of Neo4j for flat queries)

```sql
CREATE TABLE sources (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  name TEXT,
  file TEXT,
  line INTEGER,
  flow_order INTEGER DEFAULT 1,
  route_url TEXT,
  roles_required TEXT,  -- JSON array
  http_methods TEXT,    -- JSON array
  area TEXT,
  tool TEXT
);

CREATE TABLE hops (
  id TEXT PRIMARY KEY,
  lineage_id TEXT NOT NULL,
  hop_index INTEGER NOT NULL,
  function TEXT,
  file TEXT,
  line INTEGER,
  code TEXT,
  sanitizations TEXT,   -- JSON array
  encoding_state TEXT DEFAULT 'RAW',
  execution_context TEXT,
  is_interceptor INTEGER DEFAULT 0,
  confidence TEXT DEFAULT 'measured',
  tool TEXT
);

CREATE TABLE sinks (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  file TEXT,
  line INTEGER,
  code TEXT,
  flow_order INTEGER DEFAULT 1,
  is_intermediate INTEGER DEFAULT 0,
  execution_context TEXT,
  context_determined TEXT DEFAULT 'UNKNOWN',
  possible_contexts TEXT,   -- JSON array
  required_protection TEXT, -- JSON array
  tool TEXT
);

CREATE TABLE lineages (
  id TEXT PRIMARY KEY,
  tool TEXT,
  flow_order INTEGER DEFAULT 1,
  hop_count INTEGER,
  source_id TEXT NOT NULL,
  sink_id TEXT NOT NULL,
  has_sanitization INTEGER DEFAULT 0,
  sanitization_contexts TEXT, -- JSON array
  required_context TEXT,
  gap TEXT,                   -- JSON array
  classification TEXT,
  confidence REAL,
  runtime_confirmed INTEGER DEFAULT 0,
  zap_confirmed INTEGER DEFAULT 0,
  coverage_gaps TEXT,         -- JSON array
  FOREIGN KEY (source_id) REFERENCES sources(id),
  FOREIGN KEY (sink_id) REFERENCES sinks(id)
);

CREATE TABLE routes (
  url TEXT PRIMARY KEY,
  area TEXT,
  roles_required TEXT,    -- JSON array
  http_methods TEXT,      -- JSON array
  controller_fqn TEXT,
  file TEXT,
  verified INTEGER DEFAULT 0,
  reachability TEXT DEFAULT 'UNVERIFIED'
);

CREATE TABLE sanitizers (
  name TEXT PRIMARY KEY,
  fqn TEXT,
  covers_context TEXT,  -- JSON array
  source TEXT
);

CREATE TABLE persistence_boundaries (
  id TEXT PRIMARY KEY,
  type TEXT,
  identifier TEXT,
  write_routes TEXT,    -- JSON array
  read_routes TEXT      -- JSON array
);

-- Indexes for common query patterns
CREATE INDEX idx_hops_lineage ON hops(lineage_id);
CREATE INDEX idx_lineages_source ON lineages(source_id);
CREATE INDEX idx_lineages_sink ON lineages(sink_id);
CREATE INDEX idx_lineages_order ON lineages(flow_order);
CREATE INDEX idx_lineages_classification ON lineages(classification);
CREATE INDEX idx_sinks_type ON sinks(type);
CREATE INDEX idx_sources_route ON sources(route_url);
```

---

## Sanitizer Catalog (Magento 2.x)

| Function | FQN | Covers |
|---|---|---|
| `escapeHtml` | `Magento\Framework\Escaper::escapeHtml` | HTML_BODY |
| `escapeHtmlAttr` | `Magento\Framework\Escaper::escapeHtmlAttr` | HTML_ATTR |
| `escapeJs` | `Magento\Framework\Escaper::escapeJs` | JS_STRING |
| `escapeUrl` | `Magento\Framework\Escaper::escapeUrl` | URL |
| `escapeCss` | `Magento\Framework\Escaper::escapeCss` | CSS |
| `htmlspecialchars` | PHP builtin | HTML_BODY |
| `htmlentities` | PHP builtin | HTML_BODY |
| `strip_tags` | PHP builtin | HTML_BODY (partial) |
| `urlencode` / `rawurlencode` | PHP builtin | URL |
| `json_encode` | PHP builtin | JSON_ENCODE (not JS_STRING — see note) |
| `intval` / `floatval` | PHP builtin | NUMERIC_ONLY |
| `preg_replace` (sanitizing pattern) | PHP builtin | CONTEXT_DEPENDENT |

> **Note on `json_encode`**: `json_encode` encodes for JSON structure but does NOT make a value safe in an inline JavaScript context without additional escaping of `</script>` sequences. Context = `JSON_ENCODE`, not `JS_STRING`.
