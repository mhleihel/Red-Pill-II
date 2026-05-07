# Red-Pill Vulnerability Catalog (Q&A)

## Question

Turn this into a single canonical “vuln catalog” JSON for Red-Pill (families → sink_kinds → required protections → contradiction rules), aligned to `schemas/redpill/family_contract.schema.json` and the Semgrep metadata fields.

## Answer

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-05-03T00:00:00-05:00",
  "generated_by": "canonical-vuln-catalog (assistant)",
  "families": [
    {
      "family": "xss",
      "version": "1.0",
      "sink_kinds": [
        "client_dom",
        "client_framework",
        "template_interpolation",
        "server_template",
        "server_response",
        "css_injection",
        "htmx_swap"
      ],
      "required_flag_rules": [
        { "when_context": "CTX_HTML_BODY", "requires_any": ["PR_ENC_HTML", "PR_SAN_HTML"] },
        { "when_context": "CTX_HTML_ATTR", "requires_any": ["PR_ENC_ATTR"] },
        { "when_context": "CTX_URL", "requires_any": ["PR_ENC_URL", "PR_VALIDATE_ALLOWLIST"] },
        { "when_context": "CTX_JS", "requires_any": ["PR_ENC_JS"] },
        { "when_context": "CTX_CSS", "requires_any": ["PR_VALIDATE_ALLOWLIST"] },
        { "when_context": "CTX_DOM_HTML", "requires_any": ["PR_SAN_HTML", "PR_ACTIVE_CONTENT_BLOCK"] },
        { "when_context": "CTX_TEMPLATE", "requires_any": ["PR_SAN_HTML", "PR_ACTIVE_CONTENT_BLOCK"] },
        { "when_context": "CTX_EMAIL_HTML", "requires_any": ["PR_ENC_HTML", "PR_SAN_HTML"] },
        { "when_context": "CTX_REPORT_HTML", "requires_any": ["PR_ENC_HTML", "PR_SAN_HTML"] }
      ],
      "boundary_escalations": [
        { "when_boundary": "BD_DB_READ", "adds_required": ["PR_REVALIDATE_REENTRY"] },
        { "when_boundary": "BD_CACHE_READ", "adds_required": ["PR_REVALIDATE_REENTRY"] },
        { "when_boundary": "BD_FILE_READ", "adds_required": ["PR_REVALIDATE_REENTRY"] },
        { "when_boundary": "BD_QUEUE_READ", "adds_required": ["PR_REVALIDATE_REENTRY"] }
      ],
      "contradiction_rules": [
        { "required": "PR_ENC_HTML", "contradicted_by": ["DG_CONTEXT_SHIFT", "DG_DECODE_AFTER_PROTECT", "DG_TRUST_BYPASS"] },
        { "required": "PR_ENC_ATTR", "contradicted_by": ["DG_CONTEXT_SHIFT", "DG_DECODE_AFTER_PROTECT", "DG_TRUST_BYPASS"] },
        { "required": "PR_ENC_URL", "contradicted_by": ["DG_CONTEXT_SHIFT", "DG_DECODE_AFTER_PROTECT", "DG_TRUST_BYPASS"] },
        { "required": "PR_ENC_JS", "contradicted_by": ["DG_CONTEXT_SHIFT", "DG_DECODE_AFTER_PROTECT", "DG_TRUST_BYPASS"] },
        { "required": "PR_SAN_HTML", "contradicted_by": ["DG_RAW_RENDER", "DG_TRUST_BYPASS"] },
        { "required": "PR_REVALIDATE_REENTRY", "contradicted_by": ["DG_REPLAYED_REFERENCE", "DG_UNSAFE_REENTRY"] }
      ]
    },
    {
      "family": "sqli",
      "version": "1.0",
      "sink_kinds": [
        "sql_query_execute",
        "sql_query_build"
      ],
      "required_flag_rules": [
        { "when_context": "CTX_QUERY", "requires_any": ["PR_PARAM_QUERY", "PR_VALIDATE_SCHEMA"] }
      ],
      "boundary_escalations": [
        { "when_boundary": "BD_DB_READ", "adds_required": ["PR_REVALIDATE_REENTRY"] }
      ],
      "contradiction_rules": [
        { "required": "PR_PARAM_QUERY", "contradicted_by": ["DG_UNPARAM_QUERY", "DG_TRUST_BYPASS"] },
        { "required": "PR_REVALIDATE_REENTRY", "contradicted_by": ["DG_REPLAYED_REFERENCE", "DG_UNSAFE_REENTRY"] }
      ]
    },
    {
      "family": "ssrf",
      "version": "1.0",
      "sink_kinds": [
        "http_request",
        "url_fetch",
        "dns_lookup",
        "proxy_forward"
      ],
      "required_flag_rules": [
        { "when_context": "CTX_NETWORK_TARGET", "requires_any": ["PR_TARGET_ALLOWLIST", "PR_VALIDATE_ALLOWLIST"] }
      ],
      "boundary_escalations": [
        { "when_boundary": "BD_EXTERNAL_NETWORK", "adds_required": ["PR_TARGET_ALLOWLIST"] }
      ],
      "contradiction_rules": [
        { "required": "PR_TARGET_ALLOWLIST", "contradicted_by": ["DG_SSRF_TARGET_CONTROL", "DG_CONTEXT_SHIFT"] },
        { "required": "PR_VALIDATE_ALLOWLIST", "contradicted_by": ["DG_SSRF_TARGET_CONTROL"] }
      ]
    },
    {
      "family": "file",
      "version": "1.0",
      "sink_kinds": [
        "file_read",
        "file_write",
        "static_file_serving",
        "streaming_response",
        "file_upload_publication"
      ],
      "required_flag_rules": [
        { "when_context": "CTX_PATH", "requires_any": ["PR_PATH_NORMALIZE", "PR_VALIDATE_ALLOWLIST"] },
        { "when_context": "CTX_FILE_PUBLICATION", "requires_any": ["PR_MIME_CHECK", "PR_ACTIVE_CONTENT_BLOCK"] }
      ],
      "boundary_escalations": [
        { "when_boundary": "BD_FILE_READ", "adds_required": ["PR_REVALIDATE_REENTRY"] }
      ],
      "contradiction_rules": [
        { "required": "PR_PATH_NORMALIZE", "contradicted_by": ["DG_PATH_TRAVERSAL_RISK"] },
        { "required": "PR_MIME_CHECK", "contradicted_by": ["DG_CONTEXT_SHIFT", "DG_REPLAYED_REFERENCE"] },
        { "required": "PR_ACTIVE_CONTENT_BLOCK", "contradicted_by": ["DG_CONTEXT_SHIFT", "DG_REPLAYED_REFERENCE"] }
      ]
    },
    {
      "family": "deserialize",
      "version": "1.0",
      "max_confidence": "medium",
      "sink_kinds": [
        "json_deserialize",
        "yaml_load",
        "pickle_load",
        "php_unserialize",
        "java_deserialize"
      ],
      "required_flag_rules": [
        { "when_context": "CTX_DESERIALIZE", "requires_any": ["PR_VALIDATE_SCHEMA", "PR_VALIDATE_ALLOWLIST"] }
      ],
      "boundary_escalations": [
        { "when_boundary": "BD_DESERIALIZE", "adds_required": ["PR_REVALIDATE_REENTRY"] }
      ],
      "contradiction_rules": [
        { "required": "PR_VALIDATE_SCHEMA", "contradicted_by": ["DG_UNSAFE_DESERIALIZE", "DG_TRUST_BYPASS"] },
        { "required": "PR_VALIDATE_ALLOWLIST", "contradicted_by": ["DG_UNSAFE_DESERIALIZE", "DG_TRUST_BYPASS"] }
      ]
    },
    {
      "family": "cmdi",
      "version": "1.0",
      "max_confidence": "high",
      "sink_kinds": [
        "process_spawn",
        "shell_exec",
        "eval_exec"
      ],
      "required_flag_rules": [
        { "when_context": "CTX_CMD", "requires_any": ["PR_ARGV_SAFE_SPAWN", "PR_CMD_ALLOWLIST", "PR_VALIDATE_ALLOWLIST"] }
      ],
      "boundary_escalations": [
        { "when_boundary": "BD_EXTERNAL_NETWORK", "adds_required": ["PR_VALIDATE_ALLOWLIST"] },
        { "when_boundary": "BD_FILE_READ", "adds_required": ["PR_REVALIDATE_REENTRY"] }
      ],
      "contradiction_rules": [
        { "required": "PR_ARGV_SAFE_SPAWN", "contradicted_by": ["DG_TRUST_BYPASS", "DG_CONTEXT_SHIFT"] },
        { "required": "PR_CMD_ALLOWLIST", "contradicted_by": ["DG_TRUST_BYPASS", "DG_CONTEXT_SHIFT"] }
      ]
    },
    {
      "family": "ldap",
      "version": "1.0",
      "max_confidence": "medium",
      "sink_kinds": [
        "ldap_search_filter",
        "ldap_query"
      ],
      "required_flag_rules": [
        { "when_context": "CTX_LDAP", "requires_any": ["PR_VALIDATE_SCHEMA", "PR_VALIDATE_ALLOWLIST"] }
      ],
      "boundary_escalations": [
        { "when_boundary": "BD_DB_READ", "adds_required": ["PR_REVALIDATE_REENTRY"] }
      ],
      "contradiction_rules": [
        { "required": "PR_VALIDATE_SCHEMA", "contradicted_by": ["DG_TRUST_BYPASS", "DG_CONTEXT_SHIFT"] }
      ]
    },
    {
      "family": "nosqli",
      "version": "1.0",
      "max_confidence": "high",
      "sink_kinds": [
        "nosql_query_object",
        "nosql_query_dsl"
      ],
      "required_flag_rules": [
        { "when_context": "CTX_NOSQL", "requires_any": ["PR_VALIDATE_SCHEMA", "PR_VALIDATE_ALLOWLIST"] }
      ],
      "boundary_escalations": [
        { "when_boundary": "BD_DB_READ", "adds_required": ["PR_REVALIDATE_REENTRY"] }
      ],
      "contradiction_rules": [
        { "required": "PR_VALIDATE_SCHEMA", "contradicted_by": ["DG_TRUST_BYPASS", "DG_CONTEXT_SHIFT"] },
        { "required": "PR_VALIDATE_ALLOWLIST", "contradicted_by": ["DG_TRUST_BYPASS"] }
      ]
    },
    {
      "family": "xxe",
      "version": "1.0",
      "max_confidence": "medium",
      "sink_kinds": [
        "xml_parse"
      ],
      "required_flag_rules": [
        { "when_context": "CTX_XML", "requires_any": ["PR_XML_DTD_DISABLED", "PR_VALIDATE_SCHEMA"] }
      ],
      "boundary_escalations": [
        { "when_boundary": "BD_EXTERNAL_NETWORK", "adds_required": ["PR_TARGET_ALLOWLIST"] },
        { "when_boundary": "BD_FILE_READ", "adds_required": ["PR_VALIDATE_ALLOWLIST"] }
      ],
      "contradiction_rules": [
        { "required": "PR_XML_DTD_DISABLED", "contradicted_by": ["DG_TRUST_BYPASS"] }
      ]
    },
    {
      "family": "header",
      "version": "1.0",
      "max_confidence": "high",
      "sink_kinds": [
        "response_header_set",
        "cookie_set"
      ],
      "required_flag_rules": [
        { "when_context": "CTX_HEADER", "requires_any": ["PR_VALIDATE_ALLOWLIST", "PR_VALIDATE_SCHEMA"] }
      ],
      "boundary_escalations": [],
      "contradiction_rules": [
        { "required": "PR_VALIDATE_ALLOWLIST", "contradicted_by": ["DG_TRUST_BYPASS", "DG_CONTEXT_SHIFT"] }
      ]
    },
    {
      "family": "redirect",
      "version": "1.0",
      "sink_kinds": [
        "url_navigation"
      ],
      "required_flag_rules": [
        { "when_context": "CTX_URL", "requires_any": ["PR_VALIDATE_ALLOWLIST", "PR_VALIDATE_SCHEMA"] }
      ],
      "boundary_escalations": [],
      "contradiction_rules": [
        { "required": "PR_VALIDATE_ALLOWLIST", "contradicted_by": ["DG_TRUST_BYPASS"] }
      ]
    }
  ],
  "semgrep_alignment": {
    "metadata_fields_used_today": [
      "red_pill_kind",
      "source_kind",
      "sink_kind",
      "protection_kind",
      "category",
      "render_context",
      "execution_context",
      "confidence",
      "frameworks"
    ],
    "known_semgrep_sink_kinds_today": [
      "client_dom",
      "client_framework",
      "css_injection",
      "htmx_swap",
      "server_response",
      "server_template",
      "server_template_injection",
      "static_file_serving|streaming_response",
      "template_interpolation",
      "url_navigation"
    ],
    "sink_kind_normalization": {
      "static_file_serving|streaming_response": ["static_file_serving", "streaming_response"]
    }
  }
}
```
