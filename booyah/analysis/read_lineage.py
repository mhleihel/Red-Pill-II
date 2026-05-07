#!/usr/bin/env python3
"""
Read and visualize the booyah_lineage.log from a PoC taint session.
Groups events by request, links write-requests to read-requests by value,
and prints a structured lineage map.

Usage:
    python3 booyah/analysis/read_lineage.py [--log PATH]

Default: reads log directly from Docker container magento2-248-p4-php-1.
"""
import json, sys, argparse, subprocess
from collections import defaultdict
from datetime import datetime

STEP_ORDER = {'source': 0, 'setter': 1, 'db_write': 2, 'db_read': 3, 'getter': 4}
STEP_LABEL = {
    'source':   '① SOURCE   ',
    'setter':   '② SETTER   ',
    'db_write': '③ DB WRITE ',
    'db_read':  '④ DB READ  ',
    'getter':   '⑤ GETTER   ',
}


def load_log(path: str) -> list:
    raw = ''
    if not path:
        try:
            raw = subprocess.check_output(
                ['docker', 'exec', 'magento2-248-p4-php-1',
                 'cat', '/var/www/html/var/log/booyah_lineage.log'],
                stderr=subprocess.DEVNULL
            ).decode()
        except Exception as e:
            print(f"Cannot read from Docker: {e}")
            sys.exit(1)
    else:
        raw = open(path).read()

    events = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return events


def group_by_request(events: list) -> dict:
    requests = defaultdict(list)
    for e in events:
        requests[e.get('req', 'unknown')].append(e)
    return dict(requests)


def link_requests(requests: dict) -> list:
    """
    Link write-requests to read-requests by matching taint token values.
    Returns list of confirmed lineage chains.
    """
    value_writers = defaultdict(list)
    for req_id, events in requests.items():
        for e in events:
            if e.get('step') in ('source', 'db_write'):
                val = e.get('value', '')
                if val:
                    value_writers[val].append(req_id)

    chains = []
    seen = set()

    for req_id, events in requests.items():
        read_events = [e for e in events if e.get('step') in ('db_read', 'getter')]
        if not read_events:
            continue
        for re_event in read_events:
            val = re_event.get('value', '')
            writers = [w for w in value_writers.get(val, []) if w != req_id]
            for writer_req in writers:
                key = (writer_req, req_id, val)
                if key in seen:
                    continue
                seen.add(key)
                write_events = [e for e in requests[writer_req] if e.get('value') == val]
                all_read = [e for e in events if e.get('value') == val
                            and e.get('step') in ('db_read', 'getter')]
                chains.append({
                    'write_req':    writer_req,
                    'read_req':     req_id,
                    'value':        val,
                    'write_events': sorted(write_events,
                                          key=lambda x: STEP_ORDER.get(x.get('step', ''), 99)),
                    'read_events':  sorted(all_read,
                                          key=lambda x: STEP_ORDER.get(x.get('step', ''), 99)),
                })
    return chains


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]


def print_request_block(req_id: str, events: list, label: str = '') -> None:
    ts_start = min(e['ts'] for e in events)
    http_route = next((e.get('file', '') for e in events
                       if 'HTTP POST' in e.get('file', '')), '')
    print(f"\n  [{label}] req={req_id[:16]}…  {fmt_ts(ts_start)}")
    if http_route:
        print(f"    Route : {http_route}")
    for e in sorted(events, key=lambda x: (STEP_ORDER.get(x.get('step', ''), 99), x['ts'])):
        step  = e.get('step', '?')
        slbl  = STEP_LABEL.get(step, f'  {step:<11}')
        field = e.get('field', '')
        value = e.get('value', '')[:40]
        meth  = e.get('method', '')
        file_ = e.get('file', '').replace('/var/www/html/', '')
        line  = e.get('line', 0)
        print(f"    {slbl}  field={field:<12}  value={value}")
        print(f"                    method={meth}")
        if file_ and 'HTTP' not in file_:
            print(f"                    file={file_}:{line}")


def main():
    parser = argparse.ArgumentParser(description='Visualize Booyah taint lineage log')
    parser.add_argument('--log', default='', help='Local log file path (default: read from Docker)')
    args = parser.parse_args()

    events = load_log(args.log)

    if not events:
        print("\nLog is empty.")
        print("Ensure BOOYAH_TAINT_ENABLED=1 is set in PHP-FPM and submit a review")
        print("with 'BSYH1234' in the nickname field, then re-run this script.\n")
        sys.exit(0)

    print(f"\n{'═'*72}")
    print(f"  Booyah Taint Lineage — {len(events)} event(s)")
    print(f"{'═'*72}")

    requests = group_by_request(events)
    write_reqs = {rid for rid, evts in requests.items()
                  if any(e.get('step') in ('source', 'db_write') for e in evts)}
    read_reqs  = {rid for rid, evts in requests.items()
                  if any(e.get('step') in ('db_read', 'getter') for e in evts)}

    print(f"\n  {len(requests)} request(s): {len(write_reqs)} write-path, {len(read_reqs)} read-path\n")

    # ── Section 1: Per-request events ────────────────────────────────────────
    print(f"{'─'*72}")
    print("  SECTION 1 — RAW REQUEST EVENTS (chronological)")
    print(f"{'─'*72}")
    for req_id, evts in sorted(requests.items(),
                                key=lambda x: min(e['ts'] for e in x[1])):
        has_write = any(e.get('step') in ('source', 'db_write') for e in evts)
        has_read  = any(e.get('step') in ('getter', 'db_read') for e in evts)
        if has_write and has_read:
            label = 'WRITE + READ'
        elif has_write:
            label = 'WRITE PATH — L1'
        else:
            label = 'READ PATH  — L2'
        print_request_block(req_id, evts, label=label)

    # ── Section 2: Cross-request lineage chains ───────────────────────────────
    chains = link_requests(requests)
    print(f"\n{'─'*72}")
    print(f"  SECTION 2 — CONFIRMED CROSS-REQUEST LINEAGE CHAINS ({len(chains)})")
    print(f"{'─'*72}")

    if not chains:
        print("\n  No L1→L2 chains confirmed yet.")
        if write_reqs and not read_reqs:
            print("  Write events recorded. Now navigate to the product page")
            print("  (http://localhost:8082/booyah-secure-phone.html)")
            print("  and to /review/customer/index to trigger L2 read-backs.")
        print()
    else:
        for i, chain in enumerate(chains, 1):
            val = chain['value']
            print(f"\n  Chain {i}  value='{val[:40]}'")
            print(f"  {'·'*68}")
            print(f"  WRITE  req={chain['write_req'][:16]}…")
            for e in chain['write_events']:
                slbl = STEP_LABEL.get(e.get('step', ''), '?')
                print(f"    {slbl}  {e.get('field', '')}  via  {e.get('method', '')}")
            print(f"           ↓↓  persisted to review_detail  ↓↓")
            print(f"  READ   req={chain['read_req'][:16]}…")
            for e in chain['read_events']:
                slbl  = STEP_LABEL.get(e.get('step', ''), '?')
                file_ = e.get('file', '').replace('/var/www/html/', '')
                ln    = e.get('line', 0)
                print(f"    {slbl}  {e.get('field', '')}  via  {e.get('method', '')}")
                if file_ and 'HTTP' not in file_:
                    print(f"               render: {file_}:{ln}")

    # ── Section 3: Store summary ──────────────────────────────────────────────
    print(f"\n{'─'*72}")
    print("  SECTION 3 — STORE / FIELD COVERAGE SUMMARY")
    print(f"{'─'*72}\n")
    stores: dict = defaultdict(set)
    for e in events:
        step  = e.get('step', '')
        field = e.get('field', '')
        if step and field:
            stores[field].add(step)

    for field, steps in sorted(stores.items()):
        has_l1 = bool(steps & {'source', 'db_write'})
        has_l2 = bool(steps & {'getter', 'db_read'})
        if has_l1 and has_l2:
            status = 'L1 + L2 CONFIRMED — full write→render chain observed'
        elif has_l1:
            status = 'L1 only — navigate to product page to trigger L2 getter'
        elif has_l2:
            status = 'L2 only — read observed without a write in this session'
        else:
            status = 'partial'
        step_list = ', '.join(sorted(steps, key=lambda s: STEP_ORDER.get(s, 99)))
        print(f"    review_detail.{field:<12}  [{step_list}]")
        print(f"    {'':16}  → {status}\n")

    print(f"{'═'*72}\n")


if __name__ == '__main__':
    main()
