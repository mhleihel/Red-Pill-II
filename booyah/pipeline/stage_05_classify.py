from __future__ import annotations

import json
import re

from sqlalchemy import select

from booyah.db.models import DataSink, DataSource, Sanitizer, TaintFlow
from booyah.db.session import get_session

# Classification constants
PROTECTED = "protected"
PARTIAL = "partially_protected"
UNPROTECTED = "unprotected"

# Sanitizer categories considered safe per output context
_SAFE_FOR_CONTEXT: dict[str, set[str]] = {
    "html_body": {"html_encode", "type_cast"},
    "html_attribute": {"html_encode", "type_cast"},
    "js_string": {"js_encode", "type_cast"},
    "js_block": {"type_cast"},
    "url_param": {"url_encode", "type_cast"},
    "url_full": {"url_encode", "type_cast"},
    "file_system": set(),
    "header_value": {"html_encode", "type_cast"},
}

_PARTIAL_FOR_CONTEXT: dict[str, set[str]] = {
    "html_body": {"strip_tags"},
    "html_attribute": set(),
    "js_string": {"js_encode"},
    "js_block": set(),
    "url_param": {"html_encode"},
    "url_full": set(),
    "file_system": set(),
    "header_value": set(),
}

_ENT_QUOTES_RE = re.compile(r"ENT_QUOTES")


def _sanitizer_covers(san: Sanitizer, context: str) -> bool:
    covers = json.loads(san.covers_context)
    return context in covers


def classify_flow(flow: TaintFlow, sink: DataSink, sanitizers: list[Sanitizer]) -> tuple[str, str, str]:
    """
    Returns (classification, detail, confidence).
    """
    context = sink.output_context
    safe_cats = _SAFE_FOR_CONTEXT.get(context, set())
    partial_cats = _PARTIAL_FOR_CONTEXT.get(context, set())

    # Determine which sanitizers on the path actually cover this context
    covering = [s for s in sanitizers if _sanitizer_covers(s, context)]
    covering_cats = {s.sanitizer_category for s in covering}

    # --- Special case: htmlspecialchars/htmlentities without ENT_QUOTES for html_attribute ---
    if context == "html_attribute":
        ent_quotes_present = any(
            s.function_name in ("htmlspecialchars", "htmlentities")
            and _ENT_QUOTES_RE.search(s.raw_expression)
            for s in sanitizers
        )
        html_encode_present = any(
            s.function_name in ("htmlspecialchars", "htmlentities", "esc_attr", "wp_kses", "wp_kses_post")
            for s in sanitizers
        )
        if html_encode_present and not ent_quotes_present:
            # Check if it's esc_attr (always safe for attributes) or htmlspecialchars without ENT_QUOTES
            esc_attr_present = any(s.function_name == "esc_attr" for s in sanitizers)
            if esc_attr_present:
                return PROTECTED, "esc_attr applied — safe for HTML attribute context", "high"
            return PARTIAL, (
                "htmlspecialchars/htmlentities without ENT_QUOTES does not encode single quotes; "
                "unsafe in single-quoted attribute context"
            ), "high"
        if ent_quotes_present:
            return PROTECTED, "htmlspecialchars/htmlentities with ENT_QUOTES applied", "high"

    # --- Check if any covering sanitizer is in the safe categories ---
    if safe_cats & covering_cats:
        matched = [s.function_name for s in covering if s.sanitizer_category in safe_cats]
        return PROTECTED, f"Protected by: {', '.join(matched)}", "high"

    # --- Check partial protection ---
    partial_covering = [s for s in sanitizers if s.sanitizer_category in partial_cats]
    if partial_covering:
        matched = [s.function_name for s in partial_covering]
        return PARTIAL, f"Partial protection: {', '.join(matched)} (insufficient for {context})", "medium"

    # --- Unprotected ---
    detail = f"No sanitizer covers {context} context"
    confidence = "low" if flow.path_length > 3 else "high"
    return UNPROTECTED, detail, confidence


def classify_all(scan_run_id: int) -> dict[str, int]:
    """Classify all taint flows for a scan run. Returns counts by classification."""
    with get_session() as session:
        flows = session.execute(
            select(TaintFlow).where(TaintFlow.scan_run_id == scan_run_id)
        ).scalars().all()

        # Bulk-load sinks and sanitizers for efficiency
        sink_ids = list({f.sink_id for f in flows})
        source_ids = list({f.source_id for f in flows})

        sinks_by_id: dict[int, DataSink] = {
            s.id: s for s in session.execute(
                select(DataSink).where(DataSink.id.in_(sink_ids))
            ).scalars().all()
        } if sink_ids else {}

        # For each flow, load sanitizers by ID list
        counts: dict[str, int] = {PROTECTED: 0, PARTIAL: 0, UNPROTECTED: 0, "unclassified": 0}

        for flow in flows:
            sink = sinks_by_id.get(flow.sink_id)
            if sink is None:
                flow.classification = UNPROTECTED
                flow.classification_detail = "Sink record missing"
                flow.confidence = "low"
                counts[UNPROTECTED] += 1
                continue

            san_id_list = json.loads(flow.sanitizer_ids)
            sanitizers: list[Sanitizer] = []
            if san_id_list:
                sanitizers = session.execute(
                    select(Sanitizer).where(Sanitizer.id.in_(san_id_list))
                ).scalars().all()

            classification, detail, confidence = classify_flow(flow, sink, sanitizers)
            flow.classification = classification
            flow.classification_detail = detail
            flow.confidence = confidence
            counts[classification] = counts.get(classification, 0) + 1

    return counts
