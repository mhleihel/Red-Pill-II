#!/usr/bin/env python3

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REFERENCE_DIR = REPO_ROOT / "reference"

INPUT_TYPES_FILENAME = "web_user_input_types_top_50.csv"
DIMENSIONS_FILENAME = "input_type_dimensions.csv"
OUTPUT_FILENAME = "Input_Validations.csv"

@dataclass(frozen=True)
class InputValidationPaths:
    input_types_csv: Path
    dimensions_csv: Path
    output_csv: Path


def resolve_paths(reference_dir: Path, output_path: str | None) -> InputValidationPaths:
    reference_dir = reference_dir.expanduser().resolve()
    input_types_csv = reference_dir / INPUT_TYPES_FILENAME
    dimensions_csv = reference_dir / DIMENSIONS_FILENAME
    output_csv = Path(output_path).expanduser().resolve() if output_path else (reference_dir / OUTPUT_FILENAME)
    return InputValidationPaths(
        input_types_csv=input_types_csv,
        dimensions_csv=dimensions_csv,
        output_csv=output_csv,
    )


TITLE_TAGS = {
    "Free-Text Field Values": {"text", "ui", "renderable"},
    "Selection Control Values": {"enum", "state", "ui"},
    "Action and Event Triggers": {"action", "workflow", "ui"},
    "Structured Scalar Inputs": {
        "scalar",
        "typed",
        "numeric",
        "temporal",
        "pattern",
        "text",
        "ui",
    },
    "HTTP Request Body Fields": {"payload", "body", "transport", "structured"},
    "URL Query Parameters": {"transport", "url", "query", "text", "scalar", "filter"},
    "Route and Path Parameters": {"transport", "url", "path", "id", "text"},
    "Hidden and Prepopulated Form Fields": {"payload", "body", "form", "state", "id"},
    "Search Filter Sort and Pagination State": {
        "filter",
        "query",
        "enum",
        "numeric",
        "temporal",
        "state",
    },
    "Cookie Values": {"transport", "cookie", "state", "token"},
    "Client-Side Stored Values": {"client_state", "state"},
    "Authentication Credential Inputs": {"auth", "secret", "token", "text", "ui"},
    "Consent and Preference Toggles": {"enum", "boolean", "state", "ui"},
    "User Profile and Account Settings": {"text", "enum", "state", "id", "ui"},
    "File Upload Content": {"file", "binary", "transport", "upload"},
    "File Metadata": {"file", "metadata", "text", "upload"},
    "HTTP Headers": {"transport", "header", "text"},
    "Rich Text and Markup Input": {"text", "rich_text", "markup", "renderable", "ui"},
    "Clipboard and Paste Input": {"text", "binary", "paste", "ui", "renderable"},
    "Date Time and Date-Range Inputs": {"temporal", "scalar", "ui"},
    "Numeric Threshold and Quantity Inputs": {"numeric", "scalar", "ui"},
    "Address and Location Inputs": {"text", "location", "structured", "ui"},
    "Payment and Checkout Fields": {
        "payment",
        "text",
        "numeric",
        "location",
        "workflow",
        "ui",
    },
    "Locale Language and Region Settings": {"locale", "enum", "text", "ui"},
    "Multi-Step Workflow State": {"workflow", "state", "action"},
    "Real-Time Message Payloads": {"realtime", "payload", "structured", "text"},
    "URL Fragment and Hash State": {"url", "fragment", "state", "client_state"},
    "Search Autocomplete Selections": {"enum", "id", "text", "lookup", "ui"},
    "Typeahead Hybrid Inputs": {"text", "enum", "id", "lookup", "ui"},
    "Drag-and-Drop and Reorder Input": {"action", "state", "numeric", "ui"},
    "Bulk Import Tabular Data": {"file", "tabular", "structured", "text", "upload"},
    "URL and Link Input Fields": {"url", "text", "ui"},
    "Query Builder and Advanced Filter Expressions": {
        "query_expression",
        "structured",
        "text",
        "ui",
    },
    "Notification and Contact Preference Inputs": {"enum", "state", "text", "ui"},
    "Verification and Recovery Code Inputs": {"token", "auth", "text", "ui"},
    "Invite Referral and Access Token Inputs": {"token", "auth", "url", "text", "ui"},
    "Saved View and Dashboard Configuration": {"client_state", "structured", "state"},
    "Accessibility and Personalization Settings": {"enum", "state", "text", "ui"},
    "Embedded Third-Party Widget Inputs": {"third_party", "payload", "structured", "body"},
    "CAPTCHA and Anti-Bot Responses": {"token", "challenge", "auth", "text", "ui"},
    "Media Capture Input": {"file", "media", "binary", "capture", "upload"},
    "Signature Drawing and Canvas Input": {
        "binary",
        "capture",
        "structured",
        "signature",
        "renderable",
        "ui",
    },
    "Geolocation and Place Selection Data": {"location", "numeric", "enum", "ui"},
    "Voice and Speech Input": {"file", "media", "text", "capture", "upload"},
    "Reaction Rating and Vote Inputs": {"enum", "numeric", "action", "ui"},
    "Comment and Review Payloads": {"text", "rich_text", "numeric", "renderable", "ui"},
    "Session Continuation and Draft Restore State": {
        "state",
        "client_state",
        "token",
        "workflow",
    },
    "Client-Generated Identifiers and Correlation Values": {
        "id",
        "token",
        "client_generated",
        "client_state",
    },
    "Offline and Deferred Sync Mutations": {
        "payload",
        "structured",
        "state",
        "realtime",
        "workflow",
        "body",
    },
    "Keyboard Shortcut Commands": {"action", "enum", "ui"},
}


BODY_LIKE_TITLES = {
    "HTTP Request Body Fields",
    "Hidden and Prepopulated Form Fields",
    "Real-Time Message Payloads",
    "Embedded Third-Party Widget Inputs",
    "Offline and Deferred Sync Mutations",
}

TEXT_SANITIZATION_CONTEXTUAL = {
    "Free-Text Field Values",
    "Clipboard and Paste Input",
}

RATE_LIMIT_CONTEXTUAL_TEXT = {
    "Free-Text Field Values",
    "Typeahead Hybrid Inputs",
    "Search Autocomplete Selections",
}

ORIGIN_CONTEXTUAL_FILTERS = {
    "Search Filter Sort and Pagination State",
    "URL Query Parameters",
    "Saved View and Dashboard Configuration",
}

ARCHIVE_SCAN_CORE = {
    "File Upload Content",
    "Bulk Import Tabular Data",
}

MALWARE_SCAN_CORE = {
    "File Upload Content",
    "Bulk Import Tabular Data",
}

MEDIA_VALIDATION_CORE = {
    "Media Capture Input",
    "Voice and Speech Input",
}

ANOMALY_CORE = {
    "Payment and Checkout Fields",
    "Authentication Credential Inputs",
    "File Upload Content",
    "Bulk Import Tabular Data",
    "Invite Referral and Access Token Inputs",
    "Comment and Review Payloads",
    "User Profile and Account Settings",
}

CLIENT_ID_CORE = {"Client-Generated Identifiers and Correlation Values"}
CLIENT_ID_CONTEXTUAL = {
    "Real-Time Message Payloads",
    "Offline and Deferred Sync Mutations",
    "Saved View and Dashboard Configuration",
}

CONCURRENCY_CORE = {
    "User Profile and Account Settings",
    "Drag-and-Drop and Reorder Input",
    "Saved View and Dashboard Configuration",
    "Multi-Step Workflow State",
    "Real-Time Message Payloads",
    "Offline and Deferred Sync Mutations",
}


def load_csv(path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def has(tags, *names):
    return any(name in tags for name in names)


def has_all(tags, *names):
    return all(name in tags for name in names)


def is_file_like(tags, title):
    return has(tags, "file", "upload") or title in ARCHIVE_SCAN_CORE


def is_media_like(tags):
    return has(tags, "media", "capture")


def applicability(input_title, tags, dim_id):
    if dim_id in {1, 2, 10, 15}:
        return "Core"

    if dim_id == 3:
        return "Contextual" if "action" in tags else "Core"

    if dim_id == 4:
        if has(tags, "enum", "boolean", "action", "state", "lookup", "locale"):
            return "Core"
        if input_title in {"URL Query Parameters", "HTTP Headers"}:
            return "Contextual"
        return None

    if dim_id == 5:
        if has(tags, "pattern", "url", "token", "auth", "location", "typed", "scalar", "id"):
            return "Core"
        if has(tags, "text", "header", "metadata"):
            return "Contextual"
        return None

    if dim_id == 6:
        if has(tags, "numeric", "temporal", "payment", "location"):
            return "Core"
        if is_file_like(tags, input_title) or is_media_like(tags):
            return "Contextual"
        return None

    if dim_id == 7:
        if input_title == "CAPTCHA and Anti-Bot Responses":
            return "Contextual"
        if has(tags, "text", "header", "metadata", "paste"):
            return "Core"
        if has(tags, "token") and input_title != "CAPTCHA and Anti-Bot Responses":
            return "Contextual"
        return None

    if dim_id == 8:
        if has(tags, "text", "url", "path", "token", "header", "location", "query_expression"):
            return "Core"
        if has(tags, "client_state", "state"):
            return "Contextual"
        return None

    if dim_id == 9:
        if has(tags, "payload", "structured", "tabular", "query_expression", "realtime", "client_state"):
            return "Core"
        return None

    if dim_id == 11:
        if has(tags, "payload", "structured", "query", "header", "cookie", "client_state", "body"):
            return "Core"
        return None

    if dim_id == 12:
        if has(tags, "structured", "payment", "location", "workflow", "temporal"):
            return "Core"
        if input_title in {
            "Free-Text Field Values",
            "User Profile and Account Settings",
            "Notification and Contact Preference Inputs",
        }:
            return "Contextual"
        return None

    if dim_id == 13:
        if input_title in {"HTTP Headers", "Cookie Values", "Client-Side Stored Values"}:
            return "Contextual"
        return "Core"

    if dim_id == 14:
        if has(tags, "action", "workflow", "payment", "auth", "challenge"):
            return "Core"
        if has(tags, "state", "payload", "token"):
            return "Contextual"
        return None

    if dim_id == 16:
        if has(tags, "id", "state", "file", "payment", "workflow", "client_state", "lookup", "path"):
            return "Core"
        if input_title in {"URL Query Parameters", "URL and Link Input Fields"}:
            return "Contextual"
        return None

    if dim_id == 17:
        if has(tags, "id", "lookup", "location", "path"):
            return "Core"
        if input_title in {"Selection Control Values", "Search Filter Sort and Pagination State"}:
            return "Contextual"
        return None

    if dim_id == 18:
        if has(tags, "transport", "payload", "file", "binary", "header", "token", "url", "rich_text", "tabular"):
            return "Core"
        if has(tags, "state", "action", "text"):
            return "Contextual"
        return None

    if dim_id == 19:
        if has(tags, "text", "header", "token", "id", "url", "metadata", "locale"):
            return "Core"
        return None

    if dim_id == 20:
        if has(tags, "text", "rich_text", "url", "id", "location", "metadata", "renderable"):
            return "Core"
        return None

    if dim_id == 21:
        if "temporal" in tags:
            return "Core"
        if input_title in {"Payment and Checkout Fields", "Multi-Step Workflow State"}:
            return "Contextual"
        return None

    if dim_id == 22:
        if has(tags, "locale", "location", "payment"):
            return "Core"
        if input_title in {
            "User Profile and Account Settings",
            "Notification and Contact Preference Inputs",
        }:
            return "Contextual"
        return None

    if dim_id == 23:
        if has(tags, "numeric", "payment", "location"):
            return "Core"
        return None

    if dim_id == 24:
        return "Core" if "url" in tags else None

    if dim_id == 25:
        if has(tags, "path", "metadata"):
            return "Core"
        if input_title in ARCHIVE_SCAN_CORE:
            return "Contextual"
        return None

    if dim_id == 26:
        return "Core" if "header" in tags else None

    if dim_id == 27:
        if input_title in BODY_LIKE_TITLES:
            return "Core"
        return None

    if dim_id == 28:
        if has(tags, "cookie", "client_state"):
            return "Core"
        return None

    if dim_id == 29:
        if has(tags, "action", "workflow", "payment", "auth", "challenge"):
            return "Core"
        if input_title in BODY_LIKE_TITLES or "cookie" in tags:
            return "Contextual"
        return None

    if dim_id == 30:
        if has(tags, "token", "cookie"):
            return "Core"
        if "auth" in tags:
            return "Contextual"
        return None

    if dim_id == 31:
        if has(tags, "token", "challenge"):
            return "Core"
        if has(tags, "auth", "workflow", "state", "payment", "client_state"):
            return "Contextual"
        return None

    if dim_id == 32:
        if has(tags, "action", "workflow", "payment", "realtime") or input_title in BODY_LIKE_TITLES:
            return "Core"
        if has(tags, "auth", "transport", "third_party"):
            return "Contextual"
        return None

    if dim_id == 33:
        if has(tags, "auth", "action", "query", "file", "realtime"):
            return "Core"
        if input_title in RATE_LIMIT_CONTEXTUAL_TEXT or input_title in {
            "Comment and Review Payloads",
            "Reaction Rating and Vote Inputs",
        }:
            return "Contextual"
        return None

    if dim_id == 34:
        if input_title in {"Authentication Credential Inputs", "Comment and Review Payloads", "Reaction Rating and Vote Inputs"}:
            return "Core"
        if input_title == "CAPTCHA and Anti-Bot Responses":
            return None
        if has(tags, "action", "payment", "auth"):
            return "Contextual"
        return None

    if dim_id == 35:
        if has(tags, "query", "filter", "query_expression"):
            return "Core"
        if input_title in {"Free-Text Field Values", "Search Autocomplete Selections", "Typeahead Hybrid Inputs"}:
            return "Contextual"
        return None

    if dim_id == 36:
        if has(tags, "rich_text", "markup"):
            return "Core"
        if input_title in TEXT_SANITIZATION_CONTEXTUAL or "renderable" in tags:
            return "Contextual"
        return None

    if dim_id == 37:
        if has(tags, "tabular"):
            return "Core"
        if has(tags, "text", "rich_text", "metadata", "location"):
            return "Contextual"
        return None

    if dim_id == 38:
        if is_file_like(tags, input_title) or is_media_like(tags):
            return "Core"
        return None

    if dim_id == 39:
        if is_file_like(tags, input_title) or is_media_like(tags):
            return "Core"
        return None

    if dim_id == 40:
        if is_file_like(tags, input_title) or is_media_like(tags):
            return "Core"
        return None

    if dim_id == 41:
        if input_title in ARCHIVE_SCAN_CORE:
            return "Core"
        return None

    if dim_id == 42:
        if input_title in MALWARE_SCAN_CORE:
            return "Core"
        if input_title == "File Metadata":
            return "Contextual"
        return None

    if dim_id == 43:
        if input_title in MEDIA_VALIDATION_CORE:
            return "Core"
        if input_title in {"File Upload Content", "Signature Drawing and Canvas Input"}:
            return "Contextual"
        return None

    if dim_id == 44:
        if input_title in ARCHIVE_SCAN_CORE:
            return "Core"
        return None

    if dim_id == 45:
        if input_title in CLIENT_ID_CORE:
            return "Core"
        if input_title in CLIENT_ID_CONTEXTUAL:
            return "Contextual"
        return None

    if dim_id == 46:
        if input_title in CONCURRENCY_CORE:
            return "Core"
        if has(tags, "workflow", "state", "action"):
            return "Contextual"
        return None

    if dim_id == 47:
        if input_title in {"Embedded Third-Party Widget Inputs", "CAPTCHA and Anti-Bot Responses"}:
            return "Core"
        if input_title in ORIGIN_CONTEXTUAL_FILTERS or input_title == "Geolocation and Place Selection Data":
            return "Contextual"
        return None

    if dim_id == 48:
        if has(tags, "payload", "structured", "tabular", "realtime", "client_state", "body"):
            return "Core"
        if has(tags, "rich_text"):
            return "Contextual"
        return None

    if dim_id == 49:
        if "realtime" in tags:
            return "Core"
        if has(tags, "workflow", "state", "action"):
            return "Contextual"
        return None

    if dim_id == 50:
        if input_title in ANOMALY_CORE:
            return "Core"
        if has(tags, "auth", "payment", "file", "workflow"):
            return "Contextual"
        return None

    return None


def d15_example(input_title, tags):
    if "payment" in tags:
        return "server-side price, discount, tax, quantity, and cart-state checks"
    if input_title in {"File Upload Content", "Bulk Import Tabular Data"}:
        return "file size, type, magic-byte, malware, and parser checks"
    if input_title in {"URL Query Parameters", "Route and Path Parameters"}:
        return "allowlisted keys, route shape, referenced object visibility, and bound limits"
    if "rich_text" in tags:
        return "markup policy, length, render safety, and output encoding rules"
    if "token" in tags or input_title == "CAPTCHA and Anti-Bot Responses":
        return "signature, freshness, challenge binding, and replay protections"
    if "client_state" in tags or "state" in tags:
        return "ownership, freshness, concurrency, and workflow-state checks"
    if has(tags, "text", "ui"):
        return "length, format, Unicode, enum, and cross-field constraints"
    return "syntax, business-rule, and trust-boundary checks"


def validation_condition(input_title, tags, dim_id):
    title = input_title.lower()

    if dim_id == 1:
        return (
            f"Reject {title} when required data is missing, null, empty, or only whitespace "
            "after normalization; enforce conditional-required rules for the active workflow step."
        )
    if dim_id == 2:
        return (
            f"Parse {title} with strict server-side typing and reject silent coercion, mixed-type "
            "fallback, and parser repair behavior."
        )
    if dim_id == 3:
        if is_file_like(tags, input_title) or is_media_like(tags):
            return (
                f"Enforce explicit byte-size limits for {title} before buffering, scanning, parsing, "
                "or storage."
            )
        if input_title in {"URL Query Parameters", "Route and Path Parameters", "HTTP Headers"}:
            return (
                f"Cap per-value length, aggregate request size, and key count for {title} before routing "
                "or binding into application state."
            )
        return (
            f"Enforce min and max character length plus max byte length for {title} before persistence "
            "and downstream processing."
        )
    if dim_id == 4:
        return (
            f"Allow only explicitly enumerated values or commands for {title}; reject unknown, "
            "deprecated, duplicated, or case-shifted variants."
        )
    if dim_id == 5:
        return (
            f"Validate {title} against a formal pattern or parser for its domain format and reject "
            "partial matches or lenient recovery."
        )
    if dim_id == 6:
        if has(tags, "numeric", "payment"):
            return (
                f"Reject {title} outside defined numeric bounds, including negative, overflow, "
                "underflow, and precision-edge values."
            )
        if "temporal" in tags:
            return (
                f"Reject {title} outside allowed date or time windows and normalize timezone before comparison."
            )
        if is_file_like(tags, input_title) or is_media_like(tags):
            return (
                f"Reject {title} outside safe size, count, dimension, or duration bounds before expensive processing."
            )
        return f"Apply explicit lower and upper bounds to {title} and fail closed on out-of-range values."
    if dim_id == 7:
        return (
            f"Trim, normalize, or reject unsafe whitespace and delimiter variants in {title} so "
            "equivalent inputs cannot bypass matching or parsing logic."
        )
    if dim_id == 8:
        return (
            f"Canonicalize {title} once before validation and storage, including Unicode normalization, "
            "case policy, and decoding of equivalent encodings."
        )
    if dim_id == 9:
        return (
            f"Validate {title} against a strict schema with required keys, known field names, bounded "
            "nesting, and typed array or object members."
        )
    if dim_id == 10:
        return (
            f"Accept {title} only from its declared source location and reject shadow copies that arrive "
            "through a second channel with conflicting precedence."
        )
    if dim_id == 11:
        return (
            f"Reject unknown, duplicate, repeated, or shadow fields attached to {title} instead of silently "
            "ignoring, merging, or letting the last value win."
        )
    if dim_id == 12:
        return (
            f"Check {title} for logical agreement with related fields before commit, such as matching units, "
            "confirmation values, dependent choices, and referenced state."
        )
    if dim_id == 13:
        return (
            f"Apply domain-specific business rules to {title} after syntax checks pass, including policy, "
            "entitlement, quota, lifecycle, and pricing logic."
        )
    if dim_id == 14:
        return (
            f"Allow {title} only in the correct lifecycle step and reject stale, skipped, replayed, or "
            "out-of-order workflow transitions."
        )
    if dim_id == 15:
        return (
            f"Repeat every client-visible validation for {title} on the server, including {d15_example(input_title, tags)}, "
            "and never trust client assertions that a check already passed."
        )
    if dim_id == 16:
        return (
            f"Bind {title} to the authenticated user, tenant, and object scope so the caller cannot act on "
            "foreign, hidden, or cross-tenant resources."
        )
    if dim_id == 17:
        return (
            f"Verify every referenced identifier or selection carried by {title} exists, is active, and is "
            "visible to the current principal."
        )
    if dim_id == 18:
        return (
            f"Accept only expected encodings and representations for {title} and reject undecodable bytes, "
            "mixed encodings, or ambiguous serialization."
        )
    if dim_id == 19:
        return (
            f"Define a single case-sensitivity policy for {title}, canonicalize once, and compare only canonical values."
        )
    if dim_id == 20:
        return (
            f"Reject disallowed Unicode scripts, zero-width characters, bidi tricks, and confusable mixes in {title} "
            "unless explicitly permitted by policy."
        )
    if dim_id == 21:
        return (
            f"Normalize timezone and reject impossible, future, stale, or policy-violating temporal values carried by {title}."
        )
    if dim_id == 22:
        return (
            f"Ensure locale, language, region, address, currency, and tax assumptions in {title} are mutually consistent before use."
        )
    if dim_id == 23:
        return (
            f"Use fixed-precision parsing for {title}, cap decimal scale, and apply one rounding policy only at a controlled layer."
        )
    if dim_id == 24:
        return (
            f"Parse {title} with a URL library and allow only approved schemes, hosts, ports, redirects, and callback destinations."
        )
    if dim_id == 25:
        return (
            f"Normalize any path or filename information inside {title} and reject traversal segments, absolute paths, reserved names, "
            "and unsafe separators."
        )
    if dim_id == 26:
        return (
            f"Trust only allowlisted header names and canonical instances related to {title}; reject duplicates and client-supplied "
            "proxy semantics."
        )
    if dim_id == 27:
        return (
            f"Bind {title} to one body parser and one endpoint contract so content-type confusion, parser fallback, and field smuggling "
            "cannot occur."
        )
    if dim_id == 28:
        return (
            f"Treat client-stored forms of {title} as untrusted unless signed or re-derived server-side; enforce issuer, scope, and age."
        )
    if dim_id == 29:
        return (
            f"Require a valid session binding and anti-forgery proof before accepting state-changing uses of {title}."
        )
    if dim_id == 30:
        return (
            f"Verify signatures, checksums, issuer, audience, purpose, and tamper evidence before trusting token-like forms of {title}."
        )
    if dim_id == 31:
        return (
            f"Reject expired or overly old {title} and rotate one-time or sensitive values immediately after successful use."
        )
    if dim_id == 32:
        return (
            f"Require nonce, idempotency key, or one-time-use semantics for side-effecting {title} so replay cannot duplicate impact."
        )
    if dim_id == 33:
        return (
            f"Apply per-user, per-session, per-IP, and per-tenant rate and volume limits to {title} based on abuse cost and backend load."
        )
    if dim_id == 34:
        return (
            f"Add human-verification or bot-resistance controls to {title} when the action is economically valuable, spam-prone, or brute-forceable."
        )
    if dim_id == 35:
        return (
            f"Parse {title} with a bounded grammar, allow only approved operators and fields, and cap query cost before execution."
        )
    if dim_id == 36:
        return (
            f"Sanitize markup-bearing or rendered {title} to a strict allowlist of tags, attributes, styles, and URL schemes before storage or render."
        )
    if dim_id == 37:
        return (
            f"Neutralize spreadsheet formula prefixes in text coming from {title} if it may ever be exported to CSV or opened in spreadsheet tools."
        )
    if dim_id == 38:
        return (
            f"Require filename, declared MIME type, and detected magic bytes for {title} to agree before processing or storage."
        )
    if dim_id == 39:
        return (
            f"Cap bytes, pages, rows, dimensions, duration, and processing time for {title} before full parse or transformation."
        )
    if dim_id == 40:
        return (
            f"Fully parse {title} with strict parsers and reject partial, repair-mode, or warning-heavy parses."
        )
    if dim_id == 41:
        return (
            f"Inspect every extracted entry from {title} and reject traversal paths, symlinks, excessive file counts, and deep nesting."
        )
    if dim_id == 42:
        return (
            f"Scan {title} for active content, macros, scripts, malware signatures, and suspicious embedded objects before release or execution."
        )
    if dim_id == 43:
        return (
            f"Probe media characteristics in {title} and allow only approved codecs, dimensions, duration, channels, and frame rates."
        )
    if dim_id == 44:
        return (
            f"Reject {title} when compression ratio, archive nesting, or expanded size exceeds safe resource budgets."
        )
    if dim_id == 45:
        return (
            f"Require client-generated identifiers inside {title} to match the approved namespace and format, and never treat them as final authority."
        )
    if dim_id == 46:
        return (
            f"Require a current version, ETag, or optimistic-lock token before {title} can update mutable shared state."
        )
    if dim_id == 47:
        return (
            f"Accept {title} only from approved origins or providers and verify provenance signals such as signatures, trusted provider IDs, or signed view state."
        )
    if dim_id == 48:
        return (
            f"Use hardened parsers for {title} and disable dangerous entity expansion, object resurrection, excessive depth, and unsafe type binding."
        )
    if dim_id == 49:
        return (
            f"Require sequence or version markers on {title} and reject stale, duplicate, missing, or out-of-order messages."
        )
    if dim_id == 50:
        return (
            f"Score {title} for unusual combinations, impossible patterns, or risk outliers and route high-risk cases to secondary controls or review."
        )
    return ""


def enforcement_layer(input_title, tags, dim_id):
    if dim_id == 3:
        if is_file_like(tags, input_title) or is_media_like(tags):
            return "Upload Pipeline and Server"
        if input_title in {"URL Query Parameters", "Route and Path Parameters", "HTTP Headers", "Cookie Values"}:
            return "Gateway and Server"
        if has(tags, "client_state", "fragment"):
            return "Client and Server"
        return "Client and Server"

    if dim_id in {1, 4, 5, 6, 7, 8, 12, 13, 14, 15, 16, 17, 19, 20, 21, 22, 23, 46, 49, 50}:
        return "Server"

    if dim_id in {10, 11, 18, 24, 26, 27, 30, 47, 48}:
        return "Gateway and Server"

    if dim_id in {38, 39, 40, 41, 42, 43, 44}:
        if input_title == "Signature Drawing and Canvas Input":
            return "Client and Server"
        return "Upload Pipeline and Server"

    if dim_id in {28, 29, 31, 32, 34, 45}:
        return "Client and Server"

    if dim_id == 33:
        return "Gateway and Server"

    if dim_id in {36, 37}:
        return "Server and Render or Export Pipeline"

    if dim_id == 9:
        return "Gateway and Server"

    return "Server"


def failure_severity(dim_id):
    if dim_id in {38, 39, 40, 41, 42, 43, 44}:
        return "Upload Risk"
    if dim_id in {46, 49}:
        return "Consistency Conflict"
    if dim_id in {29, 30, 31, 32, 33, 34, 47, 50}:
        return "Security Control"
    return "Validation Error"


def escalation_threshold(dim_id):
    if dim_id in {38, 39, 40, 41, 42, 43, 44, 47}:
        return "Escalate on any failure"
    if dim_id in {46, 49}:
        return "Escalate after repeated stale or conflicting retries in a short window"
    if dim_id in {29, 30, 31, 32, 33, 34, 50}:
        return "Escalate after repeated failures or when the risk score crosses the security threshold"
    return "Return a user-visible validation error first; escalate only on repeated or patterned failures"


def fail_closed_action(dim_id):
    if dim_id in {38, 39, 40, 41, 42, 43, 44}:
        return "Reject or quarantine the upload, log the reason, and do not partially process the payload."
    if dim_id in {46, 49}:
        return "Reject as stale or conflicting, preserve the authoritative version, and require the client to refresh before retry."
    if dim_id in {29, 30, 31, 32, 33, 34, 47, 50}:
        return "Reject the request, record a security event, and escalate to throttling, challenge, or review if failures repeat or cluster."
    return "Fail closed with a validation error, log the event at normal validation severity, and avoid using the value downstream."


def generate(paths: InputValidationPaths) -> None:
    inputs = load_csv(paths.input_types_csv)
    dimensions = load_csv(paths.dimensions_csv)

    rows = []
    for input_row in inputs:
        input_rank = int(input_row["Rank"])
        input_title = input_row["Title"]
        tags = TITLE_TAGS[input_title]

        for dim_row in dimensions:
            dim_id = int(dim_row["Rank"])
            app = applicability(input_title, tags, dim_id)
            if not app:
                continue

            rows.append(
                {
                    "Matrix_Row_ID": f"I{input_rank:02d}_D{dim_id:02d}",
                    "Input_Rank": input_row["Rank"],
                    "Input_Type": input_title,
                    "Input_Presence": input_row["Typical Presence"],
                    "Validation_Rank": dim_row["Rank"],
                    "Validation_Dimension": dim_row["Dimension"],
                    "Dimension_Frequency": dim_row["Frequency"],
                    "Applicability": app,
                    "Validation_Condition": validation_condition(input_title, tags, dim_id),
                    "Primary_Enforcement_Layer": enforcement_layer(input_title, tags, dim_id),
                    "Failure_Severity": failure_severity(dim_id),
                    "Escalation_Threshold": escalation_threshold(dim_id),
                    "Fail_Closed_Action": fail_closed_action(dim_id),
                    "Risk_Reduced": dim_row["Risks_If_Skipped"],
                }
            )

    fieldnames = [
        "Matrix_Row_ID",
        "Input_Rank",
        "Input_Type",
        "Input_Presence",
        "Validation_Rank",
        "Validation_Dimension",
        "Dimension_Frequency",
        "Applicability",
        "Validation_Condition",
        "Primary_Enforcement_Layer",
        "Failure_Severity",
        "Escalation_Threshold",
        "Fail_Closed_Action",
        "Risk_Reduced",
    ]

    paths.output_csv.parent.mkdir(parents=True, exist_ok=True)
    with paths.output_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {paths.output_csv}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate Input_Validations.csv from the reference input catalogs."
    )
    parser.add_argument(
        "--reference-dir",
        default=str(DEFAULT_REFERENCE_DIR),
        help="Directory containing the source reference CSVs.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output CSV path for the generated validation matrix.",
    )
    args = parser.parse_args()

    paths = resolve_paths(Path(args.reference_dir), args.output)
    generate(paths)


if __name__ == "__main__":
    main()
