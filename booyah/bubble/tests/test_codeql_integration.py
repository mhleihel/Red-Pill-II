import json
from pathlib import Path


def _write_sarif(path: Path, *, uri: str) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "js/xss",
                                "name": "XSS",
                                "shortDescription": {"text": "Cross-site scripting"},
                                "properties": {"tags": ["security", "xss"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "js/xss",
                        "message": {"text": "Potential XSS sink"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": 9, "startColumn": 1},
                                }
                            }
                        ],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": uri},
                                                        "region": {"startLine": 2, "startColumn": 1},
                                                    }
                                                }
                                            },
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": uri},
                                                        "region": {"startLine": 9, "startColumn": 1},
                                                    }
                                                }
                                            },
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ],
            }
        ],
    }
    path.write_text(json.dumps(sarif), encoding="utf-8")


def test_codeql_sarif_paths_normalize_and_flow_support_is_proven(tmp_path: Path) -> None:
    from scripts.red_pill_mapper import Observation, build_codeql_flow_index, codeql_flow_support_for_pair, parse_codeql_sarif

    target = tmp_path / "target"
    target.mkdir()
    app = target / "app.js"
    app.write_text(
        "\n".join(
            [
                "function handler(req, res) {",
                "  const q = req.query.q;",
                "  const v = q;",
                "  const x = v;",
                "  const y = x;",
                "  const z = y;",
                "  const w = z;",
                "  const out = w;",
                "  el.innerHTML = out;",
                "}",
            ]
        ),
        encoding="utf-8",
    )

    sarif_path = tmp_path / "codeql.sarif"
    # Use a file:// URI to exercise normalization.
    _write_sarif(sarif_path, uri=f"file://{app}")

    codeql_obs = parse_codeql_sarif(sarif_path, target=target)
    assert codeql_obs, "expected at least one CodeQL observation"
    assert codeql_obs[0].file == "app.js"
    assert codeql_obs[0].metadata.get("codeql_has_flow") is True

    source = Observation(
        observation_id="obs-source",
        tool="builtin",
        kind="source",
        file="app.js",
        line=2,
        column=1,
        symbol="req.query.q",
        language="javascript",
        category="request_input",
        confidence=0.5,
        snippet="const q = req.query.q;",
        metadata={"source_kind": "query"},
    )
    sink = Observation(
        observation_id="obs-sink",
        tool="builtin",
        kind="sink",
        file="app.js",
        line=9,
        column=1,
        symbol="innerHTML",
        language="javascript",
        category="dom_html_sink",
        render_context="dom_html",
        execution_context="user_browser",
        confidence=0.7,
        snippet="el.innerHTML = out;",
        metadata={"sink_kind": "client_dom"},
    )

    index = build_codeql_flow_index([*codeql_obs, source, sink])
    support = codeql_flow_support_for_pair(index, source, sink)
    assert support is not None
    assert support.get("match_proven") is True
    assert float(support.get("match_quality", 0)) >= 0.8

