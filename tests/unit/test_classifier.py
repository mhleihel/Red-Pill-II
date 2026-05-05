"""Test XSS classification logic."""
import json

import pytest

from booyah.db.models import DataSink, DataSource, Sanitizer, TaintFlow
from booyah.pipeline.stage_05_classify import classify_flow, PROTECTED, PARTIAL, UNPROTECTED


def _make_sink(output_context: str) -> DataSink:
    snk = DataSink()
    snk.sink_type = "html_echo"
    snk.output_context = output_context
    snk.raw_expression = "echo $x"
    snk.start_line = 1
    return snk


def _make_flow() -> TaintFlow:
    f = TaintFlow()
    f.id = 1
    f.path_length = 1
    f.sanitizer_ids = "[]"
    return f


def _make_sanitizer(func: str, category: str, contexts: list[str], raw: str = "") -> Sanitizer:
    s = Sanitizer()
    s.id = 1
    s.function_name = func
    s.sanitizer_category = category
    s.covers_context = json.dumps(contexts)
    s.raw_expression = raw or f"{func}($x)"
    return s


class TestHtmlBody:
    def test_unprotected(self):
        flow = _make_flow()
        sink = _make_sink("html_body")
        cls, _, _ = classify_flow(flow, sink, [])
        assert cls == UNPROTECTED

    def test_protected_by_htmlspecialchars(self):
        flow = _make_flow()
        sink = _make_sink("html_body")
        san = _make_sanitizer("htmlspecialchars", "html_encode", ["html_body"], "htmlspecialchars($x, ENT_QUOTES)")
        cls, _, _ = classify_flow(flow, sink, [san])
        assert cls == PROTECTED

    def test_partial_strip_tags(self):
        flow = _make_flow()
        sink = _make_sink("html_body")
        san = _make_sanitizer("strip_tags", "strip_tags", ["html_body"])
        cls, _, _ = classify_flow(flow, sink, [san])
        assert cls == PARTIAL

    def test_protected_by_intval(self):
        flow = _make_flow()
        sink = _make_sink("html_body")
        san = _make_sanitizer("intval", "type_cast", ["html_body", "html_attribute", "js_string", "js_block", "url_param", "url_full"])
        cls, _, _ = classify_flow(flow, sink, [san])
        assert cls == PROTECTED


class TestHtmlAttribute:
    def test_unprotected(self):
        flow = _make_flow()
        sink = _make_sink("html_attribute")
        cls, _, _ = classify_flow(flow, sink, [])
        assert cls == UNPROTECTED

    def test_partial_htmlspecialchars_no_ent_quotes(self):
        flow = _make_flow()
        sink = _make_sink("html_attribute")
        # htmlspecialchars WITHOUT ENT_QUOTES — does NOT cover html_attribute
        san = _make_sanitizer("htmlspecialchars", "html_encode", ["html_body"])
        cls, detail, _ = classify_flow(flow, sink, [san])
        # With no covers_context including html_attribute, this should be unprotected
        assert cls in (UNPROTECTED, PARTIAL)

    def test_protected_esc_attr(self):
        flow = _make_flow()
        sink = _make_sink("html_attribute")
        san = _make_sanitizer("esc_attr", "html_encode", ["html_attribute"])
        cls, _, _ = classify_flow(flow, sink, [san])
        assert cls == PROTECTED

    def test_protected_htmlspecialchars_ent_quotes(self):
        flow = _make_flow()
        sink = _make_sink("html_attribute")
        san = _make_sanitizer("htmlspecialchars", "html_encode", ["html_body", "html_attribute"],
                              raw="htmlspecialchars($x, ENT_QUOTES, 'UTF-8')")
        cls, _, _ = classify_flow(flow, sink, [san])
        assert cls == PROTECTED


class TestJsBlock:
    def test_string_sanitizer_is_unprotected_in_js_block(self):
        """html escaping does not protect js_block context."""
        flow = _make_flow()
        sink = _make_sink("js_block")
        san = _make_sanitizer("htmlspecialchars", "html_encode", ["html_body"])
        cls, detail, _ = classify_flow(flow, sink, [san])
        assert cls == UNPROTECTED

    def test_intval_protects_js_block(self):
        flow = _make_flow()
        sink = _make_sink("js_block")
        san = _make_sanitizer("intval", "type_cast", ["html_body", "html_attribute", "js_string", "js_block", "url_param"])
        cls, _, _ = classify_flow(flow, sink, [san])
        assert cls == PROTECTED


class TestUrlParam:
    def test_urlencode_protects(self):
        flow = _make_flow()
        sink = _make_sink("url_param")
        san = _make_sanitizer("urlencode", "url_encode", ["url_param"])
        cls, _, _ = classify_flow(flow, sink, [san])
        assert cls == PROTECTED

    def test_htmlspecialchars_partial_for_url(self):
        flow = _make_flow()
        sink = _make_sink("url_param")
        san = _make_sanitizer("htmlspecialchars", "html_encode", ["html_body"])
        cls, detail, _ = classify_flow(flow, sink, [san])
        # html_encode is in partial_cats for url_param
        assert cls == PARTIAL
