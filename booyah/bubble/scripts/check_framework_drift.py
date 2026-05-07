#!/usr/bin/env python3

"""Check for framework security-behavior drift.

Compares the last_reviewed_version in config/framework_patterns.json
against an embedded knowledge base of framework version milestones where
security-relevant behavior changed.  Warns when a framework version in
the config predates a milestone that the operator should review.

No network calls — entirely offline and deterministic.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPO_ROOT / "config" / "framework_patterns.json"

# ---------------------------------------------------------------------------
# Embedded knowledge base: framework version milestones where security-relevant
# behaviour changed.  Each entry records a framework, the version where the
# change landed, a severity (HIGH / MEDIUM / LOW), and a short description.
# ---------------------------------------------------------------------------

MILESTONES: list[dict[str, Any]] = [
    # ── React ──────────────────────────────────────────────────────────
    {
        "framework": "react",
        "version": "18.0.0",
        "date": "2022-03-29",
        "severity": "LOW",
        "description": "Concurrent rendering (createRoot). No new XSS bypass, but hydration behavior changed — teams relying on render-to-string sanitisation should re-audit SSR paths.",
    },
    {
        "framework": "react",
        "version": "19.0.0",
        "date": "2024-12-05",
        "severity": "MEDIUM",
        "description": "Server Components stable; new ref-prop and script-injection surfaces via RSC payloads. dangerouslySetInnerHTML behaviour unchanged but new SSR paths may bypass client-side sanitation assumptions.",
    },

    # ── Vue ────────────────────────────────────────────────────────────
    {
        "framework": "vue",
        "version": "3.0.0",
        "date": "2020-09-18",
        "severity": "LOW",
        "description": "Composition API introduced; v-html remains the sole raw-HTML bypass. Template compiler now warns on v-html with user input.",
    },
    {
        "framework": "vue",
        "version": "3.4.0",
        "date": "2023-12-28",
        "severity": "LOW",
        "description": "New parser and improved compiled-template performance. No new bypass APIs, but template compilation changes warrant review.",
    },
    {
        "framework": "vue",
        "version": "3.5.0",
        "date": "2024-09-03",
        "severity": "LOW",
        "description": "Reactivity system overhaul (Vue 3.5 'Tengen'). No new bypass APIs; v-html remains the sole escape hatch.",
    },

    # ── Angular ────────────────────────────────────────────────────────
    {
        "framework": "angular",
        "version": "16.0.0",
        "date": "2023-05-03",
        "severity": "MEDIUM",
        "description": "Signals developer preview; new reactive primitive that feeds into template bindings. Teams using bypassSecurityTrust* APIs should verify signal-to-template paths.",
    },
    {
        "framework": "angular",
        "version": "17.0.0",
        "date": "2023-11-08",
        "severity": "MEDIUM",
        "description": "New built-in control flow syntax (@if, @for, @switch). Old *ngIf/*ngFor still work, but @let and expression binding behaviour differs — re-audit bypassSecurityTrust* usage in new control-flow blocks.",
    },
    {
        "framework": "angular",
        "version": "18.0.0",
        "date": "2024-05-22",
        "severity": "LOW",
        "description": "Experimental zoneless change detection. Zone.js removal may alter sanitisation timing in edge cases; teams using bypassSecurityTrustHtml should test.",
    },
    {
        "framework": "angular",
        "version": "19.0.0",
        "date": "2024-11-19",
        "severity": "LOW",
        "description": "Incremental Hydration (developer preview). New SSR hydration path — verify bypassSecurityTrust* behaviour under partial hydration.",
    },

    # ── Django / Jinja2 ────────────────────────────────────────────────
    {
        "framework": "django_jinja",
        "version": "4.2.0",
        "date": "2023-04-03",
        "severity": "LOW",
        "description": "Django 4.2 LTS. No template-security changes; |safe and mark_safe behaviour unchanged.",
    },
    {
        "framework": "django_jinja",
        "version": "5.0.0",
        "date": "2023-12-04",
        "severity": "MEDIUM",
        "description": "New form-field rendering (field group templates). New template paths added — ensure autoescape is not inadvertently disabled in new field templates.",
    },
    {
        "framework": "django_jinja",
        "version": "5.1.0",
        "date": "2024-08-07",
        "severity": "LOW",
        "description": "Django 5.1. No template-security changes beyond 5.0; review any custom template tags that call mark_safe.",
    },

    # ── Rails / ERB ────────────────────────────────────────────────────
    {
        "framework": "rails_erb",
        "version": "7.1.0",
        "date": "2023-10-05",
        "severity": "MEDIUM",
        "description": "New authentication generator adds bcrypt-based has_secure_password patterns. No new ERB bypass, but generated views should be audited for raw() / <%== usage.",
    },
    {
        "framework": "rails_erb",
        "version": "7.2.0",
        "date": "2024-08-09",
        "severity": "LOW",
        "description": "Rails 7.2. Development container config; no ERB security changes.",
    },
    {
        "framework": "rails_erb",
        "version": "8.0.0",
        "date": "2024-11-07",
        "severity": "HIGH",
        "description": "Rails 8.0 introduces new authentication generator with session and password-reset flows. New generated ERB templates may use raw() or html_safe — audit generated views.",
    },

    # ── ASP.NET Razor ──────────────────────────────────────────────────
    {
        "framework": "aspnet_razor",
        "version": "7.0.0",
        "date": "2022-11-08",
        "severity": "LOW",
        "description": "ASP.NET 7. Minimal APIs mature; no Razor encoding changes. Html.Raw remains the bypass.",
    },
    {
        "framework": "aspnet_razor",
        "version": "8.0.0",
        "date": "2023-11-14",
        "severity": "MEDIUM",
        "description": "Blazor Server-Side Rendering (SSR) and streaming rendering. New render modes (Static, InteractiveServer, InteractiveWebAssembly) — Html.Raw behaviour consistent but SSR streaming paths are new XSS surface.",
    },
    {
        "framework": "aspnet_razor",
        "version": "9.0.0",
        "date": "2024-11-12",
        "severity": "LOW",
        "description": "ASP.NET 9. Blazor Hybrid and new RenderTreeBatch. No Html.Raw semantic change, but static SSR map fallback paths warrant review.",
    },

    # ── Flask ──────────────────────────────────────────────────────────
    {
        "framework": "flask",
        "version": "3.0.0",
        "date": "2023-09-30",
        "severity": "LOW",
        "description": "Flask 3.0 drops Python 3.7 support; async support stable. render_template / render_template_string autoescape unchanged.",
    },
    {
        "framework": "flask",
        "version": "3.1.0",
        "date": "2024-11-13",
        "severity": "LOW",
        "description": "Flask 3.1. Minor release; no template-security changes.",
    },

    # ── Laravel Blade ──────────────────────────────────────────────────
    {
        "framework": "laravel_blade",
        "version": "10.0.0",
        "date": "2023-02-14",
        "severity": "LOW",
        "description": "Laravel 10. Blade {{ }} autoescapes by default; {!! !!} raw echo unchanged.",
    },
    {
        "framework": "laravel_blade",
        "version": "11.0.0",
        "date": "2024-03-12",
        "severity": "MEDIUM",
        "description": "Laravel 11 slimmer skeleton; new application bootstrap. Verify that custom Blade directives do not inadvertently call Blade::withoutDoubleEncoding() or mark content as safe.",
    },
    {
        "framework": "laravel_blade",
        "version": "12.0.0",
        "date": "2025-02-24",
        "severity": "LOW",
        "description": "Laravel 12. Minor Blade improvements; no new bypass APIs.",
    },

    # ── Express ────────────────────────────────────────────────────────
    {
        "framework": "express",
        "version": "5.0.0",
        "date": "2024-09-09",
        "severity": "HIGH",
        "description": "Express 5.0 final. New res.render() behaviour with Promise-based template engines. Ensure template engine autoescape defaults haven't changed under Express 5.",
    },

    # ── FastAPI / Starlette ────────────────────────────────────────────
    {
        "framework": "fastapi",
        "version": "0.100.0",
        "date": "2023-07-07",
        "severity": "LOW",
        "description": "FastAPI 0.100. Pydantic v2 support; no change to template rendering (Jinja2 autoescape inherited).",
    },
    {
        "framework": "fastapi",
        "version": "0.110.0",
        "date": "2024-03-09",
        "severity": "LOW",
        "description": "FastAPI 0.110. No template-security changes.",
    },
    {
        "framework": "fastapi",
        "version": "0.115.0",
        "date": "2024-10-15",
        "severity": "LOW",
        "description": "FastAPI 0.115. No template-security changes.",
    },

    # ── HTMX ───────────────────────────────────────────────────────────
    {
        "framework": "htmx",
        "version": "2.0.0",
        "date": "2024-06-17",
        "severity": "HIGH",
        "description": "HTMX 2.0 drops IE support; hx-swap=innerHTML/outerHTML remain the primary XSS sink. New hx-swap values (e.g. multi-swap) may introduce HTML-injection paths. Review all hx-swap and hx-target attributes.",
    },

    # ── Svelte ─────────────────────────────────────────────────────────
    {
        "framework": "svelte",
        "version": "4.0.0",
        "date": "2023-06-22",
        "severity": "LOW",
        "description": "Svelte 4. Reduced bundle size; no change to {@html ...} bypass behaviour.",
    },
    {
        "framework": "svelte",
        "version": "5.0.0",
        "date": "2024-10-19",
        "severity": "HIGH",
        "description": "Svelte 5 'Runes'. New $state / $derived / $effect syntax; {@html ...} remains raw-HTML sink but new reactive statements and snippets mean HTML-injection may propagate through new code paths. Teams should re-audit all {@html} usage in Svelte 5 runes components.",
    },

    # ── Spring Boot ────────────────────────────────────────────────────
    {
        "framework": "spring_boot",
        "version": "3.2.0",
        "date": "2023-11-23",
        "severity": "LOW",
        "description": "Spring Boot 3.2. Virtual threads support; no Thymeleaf autoescape changes (th:text escapes, th:utext does not).",
    },
    {
        "framework": "spring_boot",
        "version": "3.3.0",
        "date": "2024-05-23",
        "severity": "LOW",
        "description": "Spring Boot 3.3. No template-security changes.",
    },
    {
        "framework": "spring_boot",
        "version": "3.4.0",
        "date": "2024-11-21",
        "severity": "LOW",
        "description": "Spring Boot 3.4. No template-security changes; th:utext remains the raw-HTML bypass.",
    },

    # ── Go net/http ────────────────────────────────────────────────────
    {
        "framework": "go_nethttp",
        "version": "1.22.0",
        "date": "2024-02-06",
        "severity": "MEDIUM",
        "description": "Go 1.22 enhanced routing patterns in net/http mux (method + path). No auto-escape in html/template changed, but new ServeMux may expose new route-parameter surfaces for template injection.",
    },
    {
        "framework": "go_nethttp",
        "version": "1.23.0",
        "date": "2024-08-13",
        "severity": "LOW",
        "description": "Go 1.23. No security changes to html/template or net/http.",
    },

    # ── Next.js ────────────────────────────────────────────────────────
    {
        "framework": "nextjs",
        "version": "14.0.0",
        "date": "2023-10-26",
        "severity": "LOW",
        "description": "Next.js 14. Server Actions stable. New server->client data paths — review any dangerouslySetInnerHTML usage that consumes Server Action responses.",
    },
    {
        "framework": "nextjs",
        "version": "15.0.0",
        "date": "2024-10-21",
        "severity": "MEDIUM",
        "description": "Next.js 15. React 19 dependency; new async request APIs (cookies(), headers(), params()). Server Components may stream raw HTML — verify that user data reaching dangerouslySetInnerHTML is sanitised.",
    },

    # ── Handlebars ─────────────────────────────────────────────────────
    {
        "framework": "handlebars",
        "version": "4.7.0",
        "date": "2020-01-29",
        "severity": "LOW",
        "description": "Handlebars 4.7. Triple-stash {{{ }}} raw-HTML behaviour unchanged. No new bypass APIs.",
    },

    # ── Twig (PHP) ─────────────────────────────────────────────────────
    {
        "framework": "twig",
        "version": "3.0.0",
        "date": "2020-11-16",
        "severity": "LOW",
        "description": "Twig 3.0. Autoescape enabled by default; |raw filter bypasses it. Behaviour consistent with Twig 2.x.",
    },

    # ── Slim (PHP) ─────────────────────────────────────────────────────
    {
        "framework": "slim",
        "version": "4.0.0",
        "date": "2020-08-23",
        "severity": "LOW",
        "description": "Slim 4.0 major release. No built-in template engine; teams must audit whichever renderer they wire in.",
    },

    # ── Phoenix (Elixir) ──────────────────────────────────────────────
    {
        "framework": "phoenix",
        "version": "1.7.0",
        "date": "2023-03-01",
        "severity": "MEDIUM",
        "description": "Phoenix 1.7. Verified routes, new component system (Phoenix.Component). HEEx auto-escape unchanged but new component attrs may expose raw-HTML paths.",
    },

    # ── Symfony (PHP) ─────────────────────────────────────────────────
    {
        "framework": "symfony",
        "version": "7.0.0",
        "date": "2023-11-29",
        "severity": "MEDIUM",
        "description": "Symfony 7.0 drops PHP 8.1 support; new security component APIs. Twig auto-escape unchanged, but new HtmlSanitizer component may be misconfigured.",
    },
    {
        "framework": "symfony",
        "version": "7.2.0",
        "date": "2024-11-29",
        "severity": "LOW",
        "description": "Symfony 7.2. New attribute-based security; no Twig auto-escape change. Review #[Route] controllers for SSTI via user-controlled template names.",
    },

    # ── Alpine.js ─────────────────────────────────────────────────────
    {
        "framework": "alpinejs",
        "version": "3.0.0",
        "date": "2021-06-10",
        "severity": "LOW",
        "description": "Alpine.js 3.0 rewrite. x-html remains the raw-HTML bypass (sets innerHTML); x-text escapes. Behaviour unchanged from 2.x.",
    },
    {
        "framework": "alpinejs",
        "version": "3.14.0",
        "date": "2024-08-21",
        "severity": "LOW",
        "description": "Alpine 3.14. New $refs and $watch APIs; no new XSS bypass. x-html remains the sole raw-HTML directive.",
    },

    # ── NestJS ────────────────────────────────────────────────────────
    {
        "framework": "nestjs",
        "version": "10.0.0",
        "date": "2023-06-18",
        "severity": "LOW",
        "description": "NestJS 10. Switched to SWC by default; no template-security changes. Underlying Express/Fastify adapter behaviour unchanged.",
    },
    {
        "framework": "nestjs",
        "version": "11.0.0",
        "date": "2024-12-02",
        "severity": "MEDIUM",
        "description": "NestJS 11. New express v5 and fastify v5 adapter support — ensure template engine auto-escape defaults haven't changed with new adapter versions.",
    },

    # ── Gin (Go) ──────────────────────────────────────────────────────
    {
        "framework": "gin",
        "version": "1.9.0",
        "date": "2023-04-09",
        "severity": "LOW",
        "description": "Gin 1.9. New binding and validation; no change to html/template rendering. c.HTML() safe; c.String() sends raw.",
    },
    {
        "framework": "gin",
        "version": "1.10.0",
        "date": "2024-06-17",
        "severity": "MEDIUM",
        "description": "Gin 1.10. New context methods; html/template auto-escape unchanged. Review any custom c.String() usage that may send user input unsanitised.",
    },
]

# Normalise framework keys from the config (which may be nested or flat)
# to the milestone keys used above.
FRAMEWORK_KEY_MAP: dict[str, str] = {
    # Direct matches
    "react": "react",
    "vue": "vue",
    "angular": "angular",
    "django_jinja": "django_jinja",
    "rails_erb": "rails_erb",
    "aspnet_razor": "aspnet_razor",
    "htmx": "htmx",
    "svelte": "svelte",
    # Aliases / alternate keys that could appear in config
    "django": "django_jinja",
    "jinja2": "django_jinja",
    "rails": "rails_erb",
    "aspnet": "aspnet_razor",
    "laravel": "laravel_blade",
    "flask": "flask",
    "fastapi": "fastapi",
    "express": "express",
    "spring_boot": "spring_boot",
    "go_nethttp": "go_nethttp",
    "nextjs": "nextjs",
    "handlebars": "handlebars",
    "twig": "twig",
    "slim": "slim",
    "phoenix": "phoenix",
    "symfony": "symfony",
    "alpinejs": "alpinejs",
    "nestjs": "nestjs",
    "gin": "gin",
}

SEVERITY_ORDER: dict[str, int] = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple, e.g. '18.3.1' -> (18, 3, 1).

    Normalises to 4 parts so '19.0' == '19.0.0' == (19, 0, 0, 0).
    """
    parts = v.strip().split(".")
    result: list[int] = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            break
    while len(result) < 4:
        result.append(0)
    return tuple(result)


def _version_older(configured: str, milestone: str) -> bool:
    """Return True if the configured version is strictly older than the milestone."""
    return _parse_version(configured) < _parse_version(milestone)


def load_config(path: Path) -> dict[str, Any] | None:
    """Load the framework config, returning None if not found or unreadable."""
    if not path.is_file():
        return None
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


def check_drift(
    config: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compare config versions against the milestone knowledge base.

    Returns a structured report dict.
    """
    findings: list[dict[str, Any]] = []
    frameworks_checked: list[str] = []
    frameworks_missing: list[str] = []

    if config is None:
        return {
            "schema_id": "red_pill_drift_report",
            "schema_version": "v0.1",
            "timestamp": date.today().isoformat(),
            "config_found": False,
            "error": "Config file not found or unreadable.",
            "highest_severity": "HIGH",
            "exit_code": 3,
            "findings": findings,
            "summary": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "total_findings": 0},
            "frameworks_checked": frameworks_checked,
            "frameworks_missing_from_config": frameworks_missing,
        }

    fw_configs = config.get("frameworks", {})
    if not isinstance(fw_configs, dict):
        return {
            "schema_id": "red_pill_drift_report",
            "schema_version": "v0.1",
            "timestamp": date.today().isoformat(),
            "config_found": True,
            "error": "Config has no 'frameworks' key or is malformed.",
            "highest_severity": "HIGH",
            "exit_code": 3,
            "findings": findings,
            "summary": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "total_findings": 0},
            "frameworks_checked": [],
            "frameworks_missing_from_config": [],
        }

    for fw_key, fw_data in fw_configs.items():
        if not isinstance(fw_data, dict):
            continue
        reviewed_version = fw_data.get("last_reviewed_version", "")
        if not reviewed_version:
            findings.append({
                "framework": fw_key,
                "configured_version": "(none)",
                "milestone_version": "N/A",
                "milestone_date": "",
                "severity": "MEDIUM",
                "description": f"Framework '{fw_key}' has no last_reviewed_version set in config. Add a version to enable drift tracking.",
                "drift_type": "missing_version",
            })
            continue

        frameworks_checked.append(fw_key)

        # Collect milestones for this framework (and any mapped aliases)
        relevant_milestones: list[dict[str, Any]] = []
        for ms in MILESTONES:
            ms_fw = ms["framework"]
            # Direct match
            if ms_fw == fw_key:
                relevant_milestones.append(ms)
                continue
            # Check if this milestone's framework maps to our config key
            mapped = FRAMEWORK_KEY_MAP.get(ms_fw, ms_fw)
            if mapped == fw_key:
                relevant_milestones.append(ms)

        for ms in relevant_milestones:
            if _version_older(reviewed_version, ms["version"]):
                findings.append({
                    "framework": fw_key,
                    "configured_version": reviewed_version,
                    "milestone_version": ms["version"],
                    "milestone_date": ms["date"],
                    "severity": ms["severity"],
                    "description": ms["description"],
                    "drift_type": "unreviewed_milestone",
                })

    # Note frameworks with milestones that aren't in config at all
    all_milestone_frameworks = {FRAMEWORK_KEY_MAP.get(ms["framework"], ms["framework"]) for ms in MILESTONES}
    frameworks_missing = sorted(all_milestone_frameworks - set(fw_configs.keys()))

    # Compute summary
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1

    total = sum(severity_counts.values())
    if severity_counts["HIGH"] > 0:
        highest = "HIGH"
        exit_code = 3
    elif severity_counts["MEDIUM"] > 0:
        highest = "MEDIUM"
        exit_code = 2
    elif severity_counts["LOW"] > 0 or total > 0:
        highest = "LOW"
        exit_code = 1
    else:
        highest = "NONE"
        exit_code = 0

    return {
        "schema_id": "red_pill_drift_report",
        "schema_version": "v0.1",
        "timestamp": date.today().isoformat(),
        "config_found": True,
        "highest_severity": highest,
        "exit_code": exit_code,
        "findings": findings,
        "summary": {
            "HIGH": severity_counts["HIGH"],
            "MEDIUM": severity_counts["MEDIUM"],
            "LOW": severity_counts["LOW"],
            "total_findings": total,
        },
        "frameworks_checked": sorted(frameworks_checked),
        "frameworks_missing_from_config": frameworks_missing,
    }


# Terminal colour helpers
_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_GREY = "\033[90m"


def _colour_for_severity(sev: str) -> str:
    return {"HIGH": _RED, "MEDIUM": _YELLOW, "LOW": _CYAN}.get(sev, _RESET)


def print_report(report: dict[str, Any]) -> None:
    """Print the drift report to stdout with terminal colours."""
    summary = report["summary"]
    findings: list[dict[str, Any]] = report["findings"]

    # Header
    print(f"{_BOLD}Red-Pill Framework Drift Check{_RESET}")
    print(f"  Timestamp: {report['timestamp']}")
    if not report.get("config_found"):
        print(f"\n{_RED}{_BOLD}ERROR:{_RESET} {report.get('error', 'Config not found.')}")
        print(f"\nExit code: {report['exit_code']}")
        return

    print(f"  Frameworks checked: {', '.join(report.get('frameworks_checked', [])) or '(none)'}")

    missing = report.get("frameworks_missing_from_config", [])
    if missing:
        print(f"  {_GREY}Frameworks with milestones but not in config: {', '.join(missing)}{_RESET}")

    # Summary counts
    print(f"\n{_BOLD}Findings:{_RESET}  "
          f"{_RED}HIGH:{summary['HIGH']}{_RESET}  "
          f"{_YELLOW}MEDIUM:{summary['MEDIUM']}{_RESET}  "
          f"{_CYAN}LOW:{summary['LOW']}{_RESET}  "
          f"TOTAL:{summary['total_findings']}")

    if not findings:
        print(f"\n{_GREEN}{_BOLD}No drift detected.{_RESET} All framework versions are up to date "
              f"against known security milestones.")
        print(f"\nExit code: {report['exit_code']}")
        return

    # Group findings by framework
    print(f"\n{_BOLD}─" * 60)
    by_fw: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        by_fw.setdefault(f["framework"], []).append(f)

    for fw_key in sorted(by_fw):
        fw_findings = by_fw[fw_key]
        print(f"\n{_BOLD}{fw_key}{_RESET}  (last reviewed: {fw_findings[0].get('configured_version', '?')})")
        for f_item in fw_findings:
            colour = _colour_for_severity(f_item["severity"])
            tag = f"{colour}{f_item['severity']:>6}{_RESET}"
            ms_ver = f_item.get("milestone_version", "")
            ms_date = f_item.get("milestone_date", "")
            desc = f_item["description"]
            print(f"  {tag}  v{ms_ver}  ({ms_date})  {desc}")

    print(f"\n{_BOLD}─" * 60)
    print(f"\nHighest severity: {_colour_for_severity(report['highest_severity'])}{report['highest_severity']}{_RESET}")
    print(f"Exit code: {report['exit_code']}")


def list_milestones() -> None:
    """Print all known milestones grouped by framework."""
    print(f"{_BOLD}Red-Pill Framework Drift Knowledge Base{_RESET}")
    print(f"  {len(MILESTONES)} milestones across {len(set(m['framework'] for m in MILESTONES))} frameworks\n")

    by_fw: dict[str, list[dict[str, Any]]] = {}
    for ms in MILESTONES:
        by_fw.setdefault(ms["framework"], []).append(ms)

    for fw_key in sorted(by_fw):
        print(f"{_BOLD}{fw_key}{_RESET}")
        for ms in by_fw[fw_key]:
            colour = _colour_for_severity(ms["severity"])
            tag = f"{colour}{ms['severity']:>6}{_RESET}"
            print(f"  {tag}  v{ms['version']}  ({ms['date']})  {ms['description']}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Red-Pill framework config for security-behavior drift."
    )
    parser.add_argument(
        "--config",
        default=str(CONFIG_PATH),
        help=f"Path to framework_patterns.json (default: {CONFIG_PATH}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON instead of terminal-coloured text.",
    )
    parser.add_argument(
        "--list-milestones",
        action="store_true",
        help="List all known framework version milestones and exit.",
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        default=True,
        help="Use non-zero exit codes for drift severity (default: true). Use --no-exit-code to always exit 0.",
    )
    parser.add_argument(
        "--no-exit-code",
        action="store_false",
        dest="exit_code",
        help="Always exit 0 regardless of findings.",
    )
    args = parser.parse_args()

    if args.list_milestones:
        list_milestones()
        return 0

    config = load_config(Path(args.config).expanduser().resolve())
    report = check_drift(config)

    if args.json:
        json.dumps(report, indent=2, ensure_ascii=False)
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_report(report)

    if args.exit_code:
        return report["exit_code"]
    return 0


if __name__ == "__main__":
    sys.exit(main())
