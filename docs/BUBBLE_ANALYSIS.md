# Bubble Analysis Design

## Overview

Bubble Analysis operates on the completed sanitization map. It does not modify the map — it produces a separate analysis output that references map nodes by ID.

Three passes, in order:

1. **Forward pass** — what protection is applied as data flows from source to sink
2. **Backward pass** — what protection is required given the sink's execution context
3. **Intersection** — where forward and backward meet; the gap between them

---

## Forward Pass

Walk every lineage from Source → Sink. At each Hop, record:
- What sanitizations were applied (`hop.sanitizations`)
- What encoding state the data is in after this hop (`hop.encoding_state`)
- Cumulative sanitization coverage so far (`union of all hop.sanitizations up to this point`)

Output per lineage:
```json
{
  "lineage_id": "L001",
  "order": 1,
  "forward_map": [
    {"hop_index": 0, "function": "getParam", "sanitizations": [], "encoding_state": "RAW", "cumulative": []},
    {"hop_index": 1, "function": "strtolower", "sanitizations": [], "encoding_state": "RAW", "cumulative": []},
    {"hop_index": 2, "function": "escapeHtml", "sanitizations": ["HTML_BODY"], "encoding_state": "HTML_ENCODED", "cumulative": ["HTML_BODY"]},
    {"hop_index": 3, "function": "echo", "sanitizations": [], "encoding_state": "HTML_ENCODED", "cumulative": ["HTML_BODY"]}
  ],
  "final_sanitization_state": ["HTML_BODY"]
}
```

---

## Backward Pass

Walk every lineage from Sink → Source. Starting at the sink's execution context:

1. At the Sink: determine what protection is **required** given `sink.type` and `sink.execution_context`
2. At each Hop (walking backward): determine what the cumulative forward sanitization covers vs what's required
3. At each Hop: compute what can still go wrong given the sink context and the protections that have NOT been applied

The "what can go wrong" set is determined by the sink context:

| Sink type | Required protection | What can go wrong without it |
|---|---|---|
| `HTML_BODY` | HTML_BODY | XSS via injected HTML tags |
| `HTML_ATTR` | HTML_ATTR | XSS via attribute breakout (`" onmouseover=`) |
| `JS_STRING` | JS_STRING | XSS via string termination (`'; alert(1)//`) |
| `JS_BLOCK` | JS_STRING + JSON_ENCODE | Script injection |
| `URL` | URL | Open redirect, parameter injection |
| `HTTP_HEADER` | URL + no newlines | Header injection, redirect |
| `DB_WRITE` | SQL (via prepared stmt) | SQL injection |
| `PHP_INCLUDE` | — (no encoding fixes this) | LFI/RFI |
| `PHP_UNSERIALIZE` | — (no encoding fixes this) | Object injection / RCE |
| `PHP_EVAL` | — (no encoding fixes this) | RCE |
| `PHP_CALLABLE` | — | RCE |
| `FILE_WRITE` | PATH_TRAVERSAL_CHECK | Path traversal |
| `EMAIL` | EMAIL_HEADER | Email header injection |
| `SHELL_EXEC` | SHELL_ESCAPE | Command injection |

Output per lineage (backward):
```json
{
  "lineage_id": "L001",
  "sink_type": "HTML_BODY",
  "required_protection": ["HTML_BODY"],
  "backward_map": [
    {
      "hop_index": 3,
      "remaining_required": ["HTML_BODY"],
      "what_can_go_wrong": ["XSS_HTML_TAG_INJECTION"],
      "note": "escapeHtml applied at this hop — gap closed here going backward"
    },
    {
      "hop_index": 2,
      "remaining_required": [],
      "what_can_go_wrong": [],
      "note": "protection satisfied"
    }
  ]
}
```

---

## Intersection

For each lineage, compare:
- `forward_map.final_sanitization_state` (what was applied)
- `sink.required_protection` (what was needed)

```
gap = required_protection - final_sanitization_state
surplus = final_sanitization_state - required_protection (wrong-context sanitization)
```

A **surplus** is not neutral — it means the applied sanitization covers a different context than what the sink needs. Example: `escapeHtml` applied at hop 2, but sink is `HTML_ATTR`. The HTML_BODY encoding doesn't satisfy HTML_ATTR context — a `"` character in the input will break out of an attribute even after escaping `<` and `>`.

Output per lineage:
```json
{
  "lineage_id": "L001",
  "gap": [],
  "surplus": [],
  "verdict": "PROTECTED",
  "notes": "escapeHtml covers HTML_BODY; sink is HTML_BODY — fully protected"
}

{
  "lineage_id": "L042",
  "gap": ["HTML_ATTR"],
  "surplus": ["HTML_BODY"],
  "verdict": "WRONG_CONTEXT",
  "notes": "escapeHtml applied, but sink is HTML_ATTR — insufficient; \" breakout possible"
}

{
  "lineage_id": "L017",
  "gap": ["HTML_BODY"],
  "surplus": [],
  "verdict": "UNPROTECTED",
  "notes": "No sanitization on any hop; sink is HTML_BODY"
}
```

---

## Multi-order Bubble Analysis

For 2nd+ order lineages, the analysis chains:

```
1st order lineage: Source₁ → Sink₁(DB_WRITE)
  Forward: what sanitization was applied before DB write?
  Backward: DB_WRITE sinks require SQL protection (prepared statements), not HTML protection

2nd order lineage: Source₂(DB_READ of same table) → Sink₂(HTML_BODY)
  Forward: what sanitization was applied after DB read?
  Backward: HTML_BODY requires HTML protection

Chained gap:
  If 1st order had no SQL injection risk (prepared statement used) — DB value is as-stored
  If 2nd order has no HTML protection on path from DB read → HTML output — XSS is possible
  This is stored XSS: the 1st order path is the storage vector, 2nd order is the execution vector
```

The intersection for a 2nd order finding reports both the storage context (1st order) and the execution context (2nd order) in the same output record.

---

## Output format

```json
{
  "bubble_analysis_version": "1.0",
  "generated_at": "ISO8601",
  "summary": {
    "total_lineages": 101,
    "protected": 12,
    "unprotected": 34,
    "wrong_context": 8,
    "gaps_with_interceptor_gap": 15,
    "gaps_with_unknown_context": 6
  },
  "findings": [
    {
      "lineage_id": "...",
      "order": 1,
      "source": {"file": "...", "line": 0, "type": "HTTP_PARAM", "route": "..."},
      "sink": {"file": "...", "line": 0, "type": "HTML_BODY"},
      "gap": ["HTML_BODY"],
      "surplus": [],
      "verdict": "UNPROTECTED",
      "roles_required": ["anonymous"],
      "execution_context": "HTML",
      "what_can_go_wrong": ["XSS_HTML_TAG_INJECTION"],
      "coverage_gaps": [],
      "confidence": 0.82
    }
  ]
}
```
