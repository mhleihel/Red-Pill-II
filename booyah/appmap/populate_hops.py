#!/usr/bin/env python3
"""
populate_hops.py — Static analysis hop population for confirmed lineages.

Adds intermediate VARIABLE, FUNCTION_CALL, MODEL_GETTER/SETTER, SANITIZER nodes
and complete lineage_hop sequences for the runtime-confirmed flows:

  L1 write: POST /review/product/post  →  review_detail.{nickname,title,detail}
  L1 write: POST /newsletter/subscriber/newaction  →  newsletter_subscriber.subscriber_email

  L2 read:  GET /review/product/listajax  →  HTTP response (nickname, title, detail)
  L2 read:  GET /review/product/view/id/{id}  →  HTTP response (detail only confirmed)

Evidence: static_analysis (code was read manually; matches runtime-confirmed flows)
"""

import hashlib
import json
import sqlite3
from pathlib import Path

APPMAP_DB = Path(__file__).parent.parent.parent / "results" / "appmap.db"
MAGENTO   = Path("/Users/mhleihel/Desktop/magento2-2.4.8-p4")


# ── helpers ──────────────────────────────────────────────────────────────────

def sha8(*parts: str) -> str:
    h = hashlib.sha1("|".join(parts).encode()).hexdigest()
    return h[:8]

def nid(*parts: str) -> str:
    return "nd-" + sha8(*parts)

def eid(*parts: str) -> str:
    return "ed-" + sha8(*parts)

def lid(*parts: str) -> str:
    return "ln-" + sha8(*parts)

def hid(*parts: str) -> str:
    return "lh-" + sha8(*parts)

def rlid(*parts: str) -> str:
    return "rl-" + sha8(*parts)


def upsert_node(conn, row: dict):
    conn.execute(
        "INSERT OR IGNORE INTO nodes "
        "(node_id,node_type,fqn,file,line,module,area,provenance,sink_kind,extra) "
        "VALUES (:node_id,:node_type,:fqn,:file,:line,:module,:area,:provenance,:sink_kind,:extra)",
        row,
    )

def upsert_edge(conn, row: dict):
    conn.execute(
        "INSERT OR IGNORE INTO edges "
        "(edge_id,edge_type,from_node,to_node,label,transform_kind,confidence,evidence) "
        "VALUES (:edge_id,:edge_type,:from_node,:to_node,:label,:transform_kind,:confidence,:evidence)",
        row,
    )

def upsert_lineage(conn, row: dict):
    conn.execute(
        "INSERT OR REPLACE INTO lineages "
        "(lineage_id,order_num,route_id,source_node,sink_node,hop_count,"
        "flags_emitted,flags_required,flags_missing,upstream_lineage,downstream_lineage,"
        "analysis_method,confidence,run_id,notes) "
        "VALUES (:lineage_id,:order_num,:route_id,:source_node,:sink_node,:hop_count,"
        ":flags_emitted,:flags_required,:flags_missing,:upstream_lineage,:downstream_lineage,"
        ":analysis_method,:confidence,:run_id,:notes)",
        row,
    )

def upsert_hop(conn, row: dict):
    conn.execute(
        "INSERT OR REPLACE INTO lineage_hops "
        "(hop_id,lineage_id,hop_sequence,node_id,edge_from_prev,"
        "value_in,value_out,flags_emitted,flags_required,flags_invalidated,"
        "is_boundary,boundary_kind,store_kind,store_identifier,file,line) "
        "VALUES (:hop_id,:lineage_id,:hop_sequence,:node_id,:edge_from_prev,"
        ":value_in,:value_out,:flags_emitted,:flags_required,:flags_invalidated,"
        ":is_boundary,:boundary_kind,:store_kind,:store_identifier,:file,:line)",
        row,
    )

def upsert_reentry_link(conn, row: dict):
    conn.execute(
        "INSERT OR REPLACE INTO reentry_links "
        "(link_id,write_lineage_id,write_hop_id,read_lineage_id,read_hop_id,"
        "store_kind,store_identifier,confidence,evidence) "
        "VALUES (:link_id,:write_lineage_id,:write_hop_id,:read_lineage_id,:read_hop_id,"
        ":store_kind,:store_identifier,:confidence,:evidence)",
        row,
    )


def get_route_id(conn, method: str, pattern_fragment: str):
    row = conn.execute(
        "SELECT route_id FROM routes WHERE http_method=? AND url_pattern LIKE ?",
        (method, f"%{pattern_fragment}%"),
    ).fetchone()
    return row[0] if row else None


# ── Review write lineage (L1) ────────────────────────────────────────────────

REVIEW_WRITE_MODULE = "Magento_Review"
REVIEW_WRITE_AREA   = "frontend"

# The three fields confirmed by runtime taint
REVIEW_FIELDS = [
    ("nickname", "review_detail.nickname"),
    ("title",    "review_detail.title"),
    ("detail",   "review_detail.detail"),
]


def build_review_write_hops(conn, route_id: str) -> dict[str, str]:
    """
    Build intermediate nodes + hops for review/product/post → review_detail.{field}
    Returns {store_identifier: (lineage_id, sink_hop_id)} for each confirmed field.
    """

    # Intermediate nodes shared across all three fields
    # (they're the same code nodes — data, review object, getNickname/getTitle/getDetail differ)

    # VARIABLE: $data — the full POST array
    data_var_id = nid("Review\\Controller\\Product\\Post::execute", "data", "var")
    upsert_node(conn, {
        "node_id":   data_var_id,
        "node_type": "VARIABLE",
        "fqn":       "Review\\Controller\\Product\\Post::execute::$data",
        "file":      "app/code/Magento/Review/Controller/Product/Post.php",
        "line":      41,
        "module":    REVIEW_WRITE_MODULE,
        "area":      REVIEW_WRITE_AREA,
        "provenance": "PV_HTTP_BODY",
        "sink_kind": None,
        "extra":     json.dumps({"note": "getPostValue() result — all POST params"}),
    })

    # FUNCTION_CALL: $review->setData($data)
    set_data_id = nid("Review\\Model\\Review::setData", "call")
    upsert_node(conn, {
        "node_id":   set_data_id,
        "node_type": "FUNCTION_CALL",
        "fqn":       "Magento\\Review\\Model\\Review::setData",
        "file":      "app/code/Magento/Review/Controller/Product/Post.php",
        "line":      47,
        "module":    REVIEW_WRITE_MODULE,
        "area":      REVIEW_WRITE_AREA,
        "provenance": None,
        "sink_kind": None,
        "extra":     json.dumps({"note": "mass-assigns all POST params to Review model"}),
    })

    # FUNCTION_CALL: $review->save()  → triggers _afterSave in ResourceModel
    review_save_id = nid("Review\\Model\\Review::save", "call")
    upsert_node(conn, {
        "node_id":   review_save_id,
        "node_type": "FUNCTION_CALL",
        "fqn":       "Magento\\Review\\Model\\Review::save",
        "file":      "app/code/Magento/Review/Controller/Product/Post.php",
        "line":      52,
        "module":    REVIEW_WRITE_MODULE,
        "area":      REVIEW_WRITE_AREA,
        "provenance": None,
        "sink_kind": None,
        "extra":     json.dumps({"note": "triggers ResourceModel::_afterSave"}),
    })

    # FUNCTION_CALL: _afterSave builds $detail array
    after_save_id = nid("Review\\ResourceModel\\Review::_afterSave", "call")
    upsert_node(conn, {
        "node_id":   after_save_id,
        "node_type": "FUNCTION_CALL",
        "fqn":       "Magento\\Review\\Model\\ResourceModel\\Review::_afterSave",
        "file":      "app/code/Magento/Review/Model/ResourceModel/Review.php",
        "line":      180,
        "module":    REVIEW_WRITE_MODULE,
        "area":      REVIEW_WRITE_AREA,
        "provenance": None,
        "sink_kind": None,
        "extra":     json.dumps({"note": "builds $detail array from model getters"}),
    })

    # Edges between shared hops
    upsert_edge(conn, {
        "edge_id":       eid("ASSIGNS_TO", data_var_id, set_data_id),
        "edge_type":     "ASSIGNS_TO",
        "from_node":     data_var_id,
        "to_node":       set_data_id,
        "label":         "$data",
        "transform_kind": None,
        "confidence":    1.0,
        "evidence":      "static",
    })
    upsert_edge(conn, {
        "edge_id":       eid("PASSES_TO", set_data_id, review_save_id),
        "edge_type":     "PASSES_TO",
        "from_node":     set_data_id,
        "to_node":       review_save_id,
        "label":         "$review (model)",
        "transform_kind": None,
        "confidence":    1.0,
        "evidence":      "static",
    })
    upsert_edge(conn, {
        "edge_id":       eid("PASSES_TO", review_save_id, after_save_id),
        "edge_type":     "PASSES_TO",
        "from_node":     review_save_id,
        "to_node":       after_save_id,
        "label":         "triggers _afterSave",
        "transform_kind": None,
        "confidence":    1.0,
        "evidence":      "static",
    })

    result = {}

    for param, store_id in REVIEW_FIELDS:
        getter = f"get{param.capitalize()}"
        line_map = {"nickname": 189, "title": 187, "detail": 188}

        # MODEL_GETTER node: $object->getNickname() etc.
        getter_node_id = nid(f"Review\\ResourceModel\\Review::_afterSave::{getter}")
        upsert_node(conn, {
            "node_id":   getter_node_id,
            "node_type": "MODEL_GETTER",
            "fqn":       f"Magento\\Review\\Model\\Review::{getter}",
            "file":      "app/code/Magento/Review/Model/ResourceModel/Review.php",
            "line":      line_map[param],
            "module":    REVIEW_WRITE_MODULE,
            "area":      REVIEW_WRITE_AREA,
            "provenance": None,
            "sink_kind": None,
            "extra":     json.dumps({"field": param, "table": "review_detail"}),
        })

        # Sink node: the PERSISTENCE_WRITE (may already exist from build_appmap.py)
        sink_node_id = nid("PERSISTENCE_WRITE", "review_detail", param)
        existing = conn.execute(
            "SELECT node_id FROM nodes WHERE node_id=?", (sink_node_id,)
        ).fetchone()
        if not existing:
            upsert_node(conn, {
                "node_id":   sink_node_id,
                "node_type": "PERSISTENCE_WRITE",
                "fqn":       f"review_detail.{param}",
                "file":      "app/code/Magento/Review/Model/ResourceModel/Review.php",
                "line":      200,
                "module":    REVIEW_WRITE_MODULE,
                "area":      REVIEW_WRITE_AREA,
                "provenance": None,
                "sink_kind": "SK_DB_WRITE",
                "extra":     json.dumps({"table": "review_detail", "column": param}),
            })

        # Edges getter → sink
        upsert_edge(conn, {
            "edge_id":       eid("RETURNS_TO", after_save_id, getter_node_id),
            "edge_type":     "RETURNS_TO",
            "from_node":     after_save_id,
            "to_node":       getter_node_id,
            "label":         f"$detail['{param}']",
            "transform_kind": None,
            "confidence":    1.0,
            "evidence":      "static",
        })
        upsert_edge(conn, {
            "edge_id":       eid("PERSISTS_TO", getter_node_id, sink_node_id),
            "edge_type":     "PERSISTS_TO",
            "from_node":     getter_node_id,
            "to_node":       sink_node_id,
            "label":         f"review_detail.{param}",
            "transform_kind": None,
            "confidence":    1.0,
            "evidence":      "runtime",
        })

        # Source node: HTTP_PARAM (may exist from build_appmap.py)
        src_node_id = nid("HTTP_PARAM", "/review/product/post", param)
        existing_src = conn.execute(
            "SELECT node_id FROM nodes WHERE node_id=?", (src_node_id,)
        ).fetchone()
        if not existing_src:
            upsert_node(conn, {
                "node_id":   src_node_id,
                "node_type": "HTTP_PARAM",
                "fqn":       f"Review::Post::execute::$_POST['{param}']",
                "file":      "app/code/Magento/Review/Controller/Product/Post.php",
                "line":      41,
                "module":    REVIEW_WRITE_MODULE,
                "area":      REVIEW_WRITE_AREA,
                "provenance": "PV_HTTP_BODY",
                "sink_kind": None,
                "extra":     json.dumps({"param": param}),
            })

        # Find or create the L1 lineage
        lin_id = lid("1st", "review/product/post", param, "review_detail")
        # Check if exists
        existing_lin = conn.execute(
            "SELECT lineage_id FROM lineages WHERE lineage_id=?", (lin_id,)
        ).fetchone()

        if not existing_lin:
            upsert_lineage(conn, {
                "lineage_id":       lin_id,
                "order_num":        1,
                "route_id":         route_id,
                "source_node":      src_node_id,
                "sink_node":        sink_node_id,
                "hop_count":        6,
                "flags_emitted":    json.dumps(["PV_HTTP_BODY", "BD_DB_WRITE", "SK_DB_WRITE"]),
                "flags_required":   None,
                "flags_missing":    None,
                "upstream_lineage": None,
                "downstream_lineage": None,
                "analysis_method":  "hybrid",
                "confidence":       1.0,
                "run_id":           None,
                "notes":            f"runtime+static: POST {param} → review_detail.{param}",
            })

        # Delete old placeholder hops (they may have been inserted with wrong hop_ids by build_appmap.py)
        # We use the uid() from build_appmap which is sha8 of different parts — safe to just INSERT OR REPLACE
        hop_defs = [
            # seq, node_id, edge_from_prev, flags, boundary
            (0, src_node_id,   None,                   ["PV_HTTP_BODY"],           False, None, None, None,
             "app/code/Magento/Review/Controller/Product/Post.php", 41),
            (1, data_var_id,   eid("ASSIGNS_TO", src_node_id, data_var_id),  [],   False, None, None, None,
             "app/code/Magento/Review/Controller/Product/Post.php", 41),
            (2, set_data_id,   eid("ASSIGNS_TO", data_var_id, set_data_id),  [],   False, None, None, None,
             "app/code/Magento/Review/Controller/Product/Post.php", 47),
            (3, review_save_id,eid("PASSES_TO", set_data_id, review_save_id),[],   False, None, None, None,
             "app/code/Magento/Review/Controller/Product/Post.php", 52),
            (4, after_save_id, eid("PASSES_TO", review_save_id, after_save_id),[],  False, None, None, None,
             "app/code/Magento/Review/Model/ResourceModel/Review.php", 180),
            (5, getter_node_id,eid("RETURNS_TO", after_save_id, getter_node_id),[],  False, None, None, None,
             "app/code/Magento/Review/Model/ResourceModel/Review.php", line_map[param]),
            (6, sink_node_id,  eid("PERSISTS_TO", getter_node_id, sink_node_id),
             ["BD_DB_WRITE", "SK_DB_WRITE"],                                    True,  "BD_DB_WRITE", "db", store_id,
             "app/code/Magento/Review/Model/ResourceModel/Review.php", 200),
        ]

        # Build edges for hop 0→1 (src→data_var)
        upsert_edge(conn, {
            "edge_id":       eid("ASSIGNS_TO", src_node_id, data_var_id),
            "edge_type":     "ASSIGNS_TO",
            "from_node":     src_node_id,
            "to_node":       data_var_id,
            "label":         f"$_POST['{param}']→$data",
            "transform_kind": None,
            "confidence":    1.0,
            "evidence":      "static",
        })

        for seq, nid_, edge_prev, flags, is_bnd, bkind, skind, store, fpath, lineno in hop_defs:
            upsert_hop(conn, {
                "hop_id":          hid(lin_id, str(seq)),
                "lineage_id":      lin_id,
                "hop_sequence":    seq,
                "node_id":         nid_,
                "edge_from_prev":  edge_prev,
                "value_in":        None,
                "value_out":       None,
                "flags_emitted":   json.dumps(flags) if flags else None,
                "flags_required":  None,
                "flags_invalidated": None,
                "is_boundary":     1 if is_bnd else 0,
                "boundary_kind":   bkind,
                "store_kind":      skind,
                "store_identifier": store,
                "file":            fpath,
                "line":            lineno,
            })

        sink_hop_id = hid(lin_id, "6")
        result[store_id] = (lin_id, sink_hop_id)

    return result  # {store_id: (lineage_id, sink_hop_id)}


# ── Newsletter write lineage (L1) ─────────────────────────────────────────────

def build_newsletter_write_hops(conn, route_id: str) -> tuple[str, str]:
    """Returns (lineage_id, sink_hop_id) for newsletter_subscriber.subscriber_email"""

    MODULE = "Magento_Newsletter"
    AREA   = "frontend"

    # SOURCE: HTTP_PARAM email
    src_id = nid("HTTP_PARAM", "/newsletter/subscriber/new", "email")
    upsert_node(conn, {
        "node_id":   src_id,
        "node_type": "HTTP_PARAM",
        "fqn":       "Newsletter\\Subscriber\\NewAction::execute::$_POST['email']",
        "file":      "app/code/Magento/Newsletter/Controller/Subscriber/NewAction.php",
        "line":      178,
        "module":    MODULE,
        "area":      AREA,
        "provenance": "PV_HTTP_BODY",
        "sink_kind": None,
        "extra":     json.dumps({"param": "email"}),
    })

    # VARIABLE: $email
    email_var_id = nid("Newsletter\\Subscriber\\NewAction::execute::$email")
    upsert_node(conn, {
        "node_id":   email_var_id,
        "node_type": "VARIABLE",
        "fqn":       "Newsletter\\Subscriber\\NewAction::execute::$email",
        "file":      "app/code/Magento/Newsletter/Controller/Subscriber/NewAction.php",
        "line":      178,
        "module":    MODULE,
        "area":      AREA,
        "provenance": "PV_HTTP_BODY",
        "sink_kind": None,
        "extra":     None,
    })

    # FUNCTION_CALL: subscriptionManager->subscribe($email, $storeId)
    subscribe_call_id = nid("Newsletter\\SubscriptionManager::subscribe", "call")
    upsert_node(conn, {
        "node_id":   subscribe_call_id,
        "node_type": "FUNCTION_CALL",
        "fqn":       "Magento\\Newsletter\\Model\\SubscriptionManager::subscribe",
        "file":      "app/code/Magento/Newsletter/Model/SubscriptionManager.php",
        "line":      91,
        "module":    MODULE,
        "area":      AREA,
        "provenance": None,
        "sink_kind": None,
        "extra":     None,
    })

    # MODEL_SETTER: $subscriber->setSubscriberEmail($email)
    setter_id = nid("Newsletter\\Model\\Subscriber::setSubscriberEmail", "call")
    upsert_node(conn, {
        "node_id":   setter_id,
        "node_type": "MODEL_SETTER",
        "fqn":       "Magento\\Newsletter\\Model\\Subscriber::setSubscriberEmail",
        "file":      "app/code/Magento/Newsletter/Model/SubscriptionManager.php",
        "line":      103,
        "module":    MODULE,
        "area":      AREA,
        "provenance": None,
        "sink_kind": None,
        "extra":     None,
    })

    # PERSISTENCE_WRITE: INSERT newsletter_subscriber.subscriber_email
    sink_id = nid("PERSISTENCE_WRITE", "newsletter_subscriber", "subscriber_email")
    upsert_node(conn, {
        "node_id":   sink_id,
        "node_type": "PERSISTENCE_WRITE",
        "fqn":       "newsletter_subscriber.subscriber_email",
        "file":      "app/code/Magento/Newsletter/Model/ResourceModel/Subscriber.php",
        "line":      None,
        "module":    MODULE,
        "area":      AREA,
        "provenance": None,
        "sink_kind": "SK_DB_WRITE",
        "extra":     json.dumps({"table": "newsletter_subscriber", "column": "subscriber_email"}),
    })

    # Edges
    for src, dst, lbl in [
        (src_id,          email_var_id,    "$email = getPost('email')"),
        (email_var_id,    subscribe_call_id, "subscribe($email)"),
        (subscribe_call_id, setter_id,     "setSubscriberEmail($email)"),
        (setter_id,       sink_id,         "newsletter_subscriber.subscriber_email"),
    ]:
        upsert_edge(conn, {
            "edge_id":       eid("PASSES_TO", src, dst),
            "edge_type":     "PASSES_TO",
            "from_node":     src,
            "to_node":       dst,
            "label":         lbl,
            "transform_kind": None,
            "confidence":    1.0,
            "evidence":      "static",
        })

    # Lineage
    lin_id = lid("1st", "newsletter/subscriber/newaction", "subscriber_email")
    upsert_lineage(conn, {
        "lineage_id":       lin_id,
        "order_num":        1,
        "route_id":         route_id,
        "source_node":      src_id,
        "sink_node":        sink_id,
        "hop_count":        4,
        "flags_emitted":    json.dumps(["PV_HTTP_BODY", "BD_DB_WRITE", "SK_DB_WRITE"]),
        "flags_required":   None,
        "flags_missing":    None,
        "upstream_lineage": None,
        "downstream_lineage": None,
        "analysis_method":  "hybrid",
        "confidence":       1.0,
        "run_id":           None,
        "notes":            "runtime+static: POST email → newsletter_subscriber.subscriber_email",
    })

    # Hops
    hop_defs = [
        (0, src_id,          None,                             ["PV_HTTP_BODY"],           False, None,None,None),
        (1, email_var_id,    eid("PASSES_TO", src_id, email_var_id), [],                   False, None,None,None),
        (2, subscribe_call_id,eid("PASSES_TO", email_var_id, subscribe_call_id),[],        False, None,None,None),
        (3, setter_id,       eid("PASSES_TO", subscribe_call_id, setter_id),[],            False, None,None,None),
        (4, sink_id,         eid("PASSES_TO", setter_id, sink_id),
         ["BD_DB_WRITE","SK_DB_WRITE"],                                                     True, "BD_DB_WRITE","db",
         "newsletter_subscriber.subscriber_email"),
    ]

    file_map = {
        src_id:           ("app/code/Magento/Newsletter/Controller/Subscriber/NewAction.php",178),
        email_var_id:     ("app/code/Magento/Newsletter/Controller/Subscriber/NewAction.php",178),
        subscribe_call_id:("app/code/Magento/Newsletter/Controller/Subscriber/NewAction.php",200),
        setter_id:        ("app/code/Magento/Newsletter/Model/SubscriptionManager.php",103),
        sink_id:          ("app/code/Magento/Newsletter/Model/ResourceModel/Subscriber.php",None),
    }

    for seq, nid_, edge_prev, flags, is_bnd, bkind, skind, store in hop_defs:
        fpath, lineno = file_map[nid_]
        upsert_hop(conn, {
            "hop_id":          hid(lin_id, str(seq)),
            "lineage_id":      lin_id,
            "hop_sequence":    seq,
            "node_id":         nid_,
            "edge_from_prev":  edge_prev,
            "value_in":        None,
            "value_out":       None,
            "flags_emitted":   json.dumps(flags) if flags else None,
            "flags_required":  None,
            "flags_invalidated": None,
            "is_boundary":     1 if is_bnd else 0,
            "boundary_kind":   bkind,
            "store_kind":      skind,
            "store_identifier": store,
            "file":            fpath,
            "line":            lineno,
        })

    return lin_id, hid(lin_id, "4")


# ── Review read lineage — listajax (L2) ───────────────────────────────────────

def build_review_listajax_lineage(conn, route_id: str, write_results: dict) -> None:
    """
    2nd-order lineage: DB read from review_detail → HTTP response via list.phtml
    write_results: {store_id: (write_lineage_id, write_hop_id)}
    """

    MODULE = "Magento_Review"
    AREA   = "frontend"
    TPL    = "app/code/Magento/Review/view/frontend/templates/product/view/list.phtml"
    BLOCK  = "app/code/Magento/Review/Block/Product/View/ListView.php"

    # Shared nodes for this route

    # PERSISTENCE_READ: getReviewsCollection().load()
    col_load_id = nid("Review\\Block\\Product\\View\\ListView::getReviewsCollection", "load")
    upsert_node(conn, {
        "node_id":   col_load_id,
        "node_type": "PERSISTENCE_READ",
        "fqn":       "Magento\\Review\\Block\\Product\\View\\ListView::getReviewsCollection()->load",
        "file":      BLOCK,
        "line":      59,
        "module":    MODULE,
        "area":      AREA,
        "provenance": "PV_DB_REENTRY",
        "sink_kind": None,
        "extra":     json.dumps({"table": "review_detail", "note": "SELECTs all approved reviews for product"}),
    })

    field_config = {
        "review_detail.nickname": {
            "getter":   "getNickname",
            "tpl_line": 71,
            "field":    "nickname",
        },
        "review_detail.title": {
            "getter":   "getTitle",
            "tpl_line": 36,
            "field":    "title",
        },
        "review_detail.detail": {
            "getter":   "getDetail",
            "tpl_line": 53,
            "field":    "detail",
        },
    }

    for store_id, cfg in field_config.items():
        if store_id not in write_results:
            continue

        write_lin_id, write_hop_id = write_results[store_id]
        getter = cfg["getter"]
        tpl_line = cfg["tpl_line"]
        field = cfg["field"]

        # REENTRY_POINT node (may exist from build_appmap.py)
        reentry_id = nid("REENTRY_POINT", "review_detail", field)
        upsert_node(conn, {
            "node_id":   reentry_id,
            "node_type": "REENTRY_POINT",
            "fqn":       f"review_detail.{field} (re-entry)",
            "file":      BLOCK,
            "line":      59,
            "module":    MODULE,
            "area":      AREA,
            "provenance": "PV_DB_REENTRY",
            "sink_kind": None,
            "extra":     json.dumps({"store_identifier": store_id}),
        })

        # MODEL_GETTER: $_review->getNickname()
        getter_read_id = nid(f"Review::listajax::{getter}", "read")
        upsert_node(conn, {
            "node_id":   getter_read_id,
            "node_type": "MODEL_GETTER",
            "fqn":       f"Magento\\Review\\Model\\Review::{getter}",
            "file":      TPL,
            "line":      tpl_line,
            "module":    MODULE,
            "area":      AREA,
            "provenance": None,
            "sink_kind": None,
            "extra":     json.dumps({"template": "product/view/list.phtml", "field": field}),
        })

        # SANITIZER: $escaper->escapeHtml(...)
        sanitizer_id = nid(f"Escaper::escapeHtml::listajax::{field}")
        upsert_node(conn, {
            "node_id":   sanitizer_id,
            "node_type": "SANITIZER",
            "fqn":       "Magento\\Framework\\Escaper::escapeHtml",
            "file":      TPL,
            "line":      tpl_line,
            "module":    MODULE,
            "area":      AREA,
            "provenance": None,
            "sink_kind": None,
            "extra":     json.dumps({"covers_context": "HTML", "field": field}),
        })

        # OUTPUT_CALL: <?= ... ?> — HTTP response
        output_id = nid(f"OUTPUT_CALL::listajax::{field}")
        upsert_node(conn, {
            "node_id":   output_id,
            "node_type": "OUTPUT_CALL",
            "fqn":       f"list.phtml:{tpl_line}: echo escapeHtml($review->{getter}())",
            "file":      TPL,
            "line":      tpl_line,
            "module":    MODULE,
            "area":      AREA,
            "provenance": None,
            "sink_kind": "SK_HTTP_RESPONSE",
            "extra":     json.dumps({"context": "HTML text node", "field": field}),
        })

        # Edges
        for src, dst, etype, lbl in [
            (reentry_id,   col_load_id,  "READS_FROM",  f"SELECT review_detail.{field}"),
            (col_load_id,  getter_read_id,"RETURNS_TO",  f"$_review->{getter}()"),
            (getter_read_id,sanitizer_id,"TRANSFORMS",  f"escapeHtml({field})"),
            (sanitizer_id, output_id,    "RENDERS_IN",  "<?= ... ?>"),
        ]:
            upsert_edge(conn, {
                "edge_id":       eid(etype, src, dst),
                "edge_type":     etype,
                "from_node":     src,
                "to_node":       dst,
                "label":         lbl,
                "transform_kind": "ESCAPE_HTML" if etype == "TRANSFORMS" else None,
                "confidence":    1.0,
                "evidence":      "static",
            })

        # 2nd-order lineage
        lin2_id = lid("2nd", "listajax", field)
        upsert_lineage(conn, {
            "lineage_id":       lin2_id,
            "order_num":        2,
            "route_id":         route_id,
            "source_node":      reentry_id,
            "sink_node":        output_id,
            "hop_count":        4,
            "flags_emitted":    json.dumps(["PV_DB_REENTRY", "TR_ESCAPE_HTML", "SK_HTTP_RESPONSE"]),
            "flags_required":   json.dumps(["BD_DB_WRITE"]),
            "flags_missing":    None,
            "upstream_lineage": write_lin_id,
            "downstream_lineage": None,
            "analysis_method":  "static",
            "confidence":       1.0,
            "run_id":           None,
            "notes":            f"runtime-confirmed read-back: review_detail.{field} → listajax HTTP response",
        })

        # Hops
        hop_seq = [
            (0, reentry_id,    None,                                    ["PV_DB_REENTRY"],True,"BD_DB_READ","db",store_id),
            (1, col_load_id,   eid("READS_FROM",reentry_id,col_load_id),[], False,None,None,None),
            (2, getter_read_id,eid("RETURNS_TO",col_load_id,getter_read_id),[],False,None,None,None),
            (3, sanitizer_id,  eid("TRANSFORMS",getter_read_id,sanitizer_id),[],False,None,None,None),
            (4, output_id,     eid("RENDERS_IN",sanitizer_id,output_id),["SK_HTTP_RESPONSE"],True,"BD_RENDER_OUT",None,None),
        ]
        file_ln = {
            reentry_id:   (BLOCK, 59),
            col_load_id:  (BLOCK, 59),
            getter_read_id:(TPL, tpl_line),
            sanitizer_id: (TPL, tpl_line),
            output_id:    (TPL, tpl_line),
        }
        for seq, nid_, edge_prev, flags, is_bnd, bkind, skind, store in hop_seq:
            fpath, lineno = file_ln[nid_]
            upsert_hop(conn, {
                "hop_id":          hid(lin2_id, str(seq)),
                "lineage_id":      lin2_id,
                "hop_sequence":    seq,
                "node_id":         nid_,
                "edge_from_prev":  edge_prev,
                "value_in":        None,
                "value_out":       None,
                "flags_emitted":   json.dumps(flags) if flags else None,
                "flags_required":  None,
                "flags_invalidated": None,
                "is_boundary":     1 if is_bnd else 0,
                "boundary_kind":   bkind,
                "store_kind":      skind,
                "store_identifier": store,
                "file":            fpath,
                "line":            lineno,
            })

        read_hop_id = hid(lin2_id, "0")

        # Reentry link
        upsert_reentry_link(conn, {
            "link_id":          rlid(write_lin_id, lin2_id, field),
            "write_lineage_id": write_lin_id,
            "write_hop_id":     write_hop_id,
            "read_lineage_id":  lin2_id,
            "read_hop_id":      read_hop_id,
            "store_kind":       "db",
            "store_identifier": store_id,
            "confidence":       1.0,
            "evidence":         "runtime",
        })

        print(f"  2nd-order: {write_lin_id} → [{store_id}] → {lin2_id} (listajax)")


# ── Review read lineage — view/id/{id} (L2) ───────────────────────────────────

def build_review_view_lineage(conn, route_id: str, write_results: dict) -> None:
    """
    2nd-order lineage: DB read from review_detail.detail → review/product/view HTTP response
    Only detail is confirmed by runtime read-back.
    """

    MODULE = "Magento_Review"
    AREA   = "frontend"
    TPL    = "app/code/Magento/Review/view/frontend/templates/view.phtml"

    store_id = "review_detail.detail"
    if store_id not in write_results:
        return

    write_lin_id, write_hop_id = write_results[store_id]

    # REENTRY_POINT (may exist)
    reentry_id = nid("REENTRY_POINT", "review_detail", "detail")

    # PERSISTENCE_READ: Review::load()
    load_id = nid("Review::Block::View::getReviewData", "call")
    upsert_node(conn, {
        "node_id":   load_id,
        "node_type": "PERSISTENCE_READ",
        "fqn":       "Magento\\Review\\Block\\Product\\View::getReviewData",
        "file":      "app/code/Magento/Review/Block/Product/View.php",
        "line":      None,
        "module":    MODULE,
        "area":      AREA,
        "provenance": "PV_DB_REENTRY",
        "sink_kind": None,
        "extra":     json.dumps({"table": "review_detail"}),
    })

    # MODEL_GETTER: $block->getReviewData()->getDetail()
    getter_id = nid("Review::view::getDetail", "call")
    upsert_node(conn, {
        "node_id":   getter_id,
        "node_type": "MODEL_GETTER",
        "fqn":       "Magento\\Review\\Model\\Review::getDetail",
        "file":      TPL,
        "line":      65,
        "module":    MODULE,
        "area":      AREA,
        "provenance": None,
        "sink_kind": None,
        "extra":     json.dumps({"template": "view.phtml"}),
    })

    # SANITIZER: escapeHtml
    sanitizer_id = nid("Escaper::escapeHtml::view::detail")
    upsert_node(conn, {
        "node_id":   sanitizer_id,
        "node_type": "SANITIZER",
        "fqn":       "Magento\\Framework\\Escaper::escapeHtml",
        "file":      TPL,
        "line":      65,
        "module":    MODULE,
        "area":      AREA,
        "provenance": None,
        "sink_kind": None,
        "extra":     json.dumps({"covers_context": "HTML"}),
    })

    # OUTPUT_CALL
    output_id = nid("OUTPUT_CALL::view::detail")
    upsert_node(conn, {
        "node_id":   output_id,
        "node_type": "OUTPUT_CALL",
        "fqn":       "view.phtml:65: nl2br(escapeHtml($block->getReviewData()->getDetail()))",
        "file":      TPL,
        "line":      65,
        "module":    MODULE,
        "area":      AREA,
        "provenance": None,
        "sink_kind": "SK_HTTP_RESPONSE",
        "extra":     json.dumps({"context": "HTML text node — nl2br wrapped"}),
    })

    # Edges
    for src, dst, etype, lbl in [
        (reentry_id, load_id,     "READS_FROM",  "SELECT review_detail.detail"),
        (load_id,    getter_id,   "RETURNS_TO",  "getReviewData()->getDetail()"),
        (getter_id,  sanitizer_id,"TRANSFORMS",  "escapeHtml(detail)"),
        (sanitizer_id, output_id, "RENDERS_IN",  "nl2br(escapeHtml(...))"),
    ]:
        upsert_edge(conn, {
            "edge_id":       eid(etype, src, dst),
            "edge_type":     etype,
            "from_node":     src,
            "to_node":       dst,
            "label":         lbl,
            "transform_kind": "ESCAPE_HTML" if etype == "TRANSFORMS" else None,
            "confidence":    1.0,
            "evidence":      "static",
        })

    lin2_id = lid("2nd", "review/product/view", "detail")
    upsert_lineage(conn, {
        "lineage_id":       lin2_id,
        "order_num":        2,
        "route_id":         route_id,
        "source_node":      reentry_id,
        "sink_node":        output_id,
        "hop_count":        4,
        "flags_emitted":    json.dumps(["PV_DB_REENTRY", "TR_ESCAPE_HTML", "SK_HTTP_RESPONSE"]),
        "flags_required":   json.dumps(["BD_DB_WRITE"]),
        "flags_missing":    None,
        "upstream_lineage": write_lin_id,
        "downstream_lineage": None,
        "analysis_method":  "static",
        "confidence":       1.0,
        "run_id":           None,
        "notes":            "runtime-confirmed read-back: review_detail.detail → view HTTP response",
    })

    hop_seq = [
        (0, reentry_id,  None,                               ["PV_DB_REENTRY"],True,"BD_DB_READ","db",store_id),
        (1, load_id,     eid("READS_FROM",reentry_id,load_id),[],False,None,None,None),
        (2, getter_id,   eid("RETURNS_TO",load_id,getter_id),[],False,None,None,None),
        (3, sanitizer_id,eid("TRANSFORMS",getter_id,sanitizer_id),[],False,None,None,None),
        (4, output_id,   eid("RENDERS_IN",sanitizer_id,output_id),["SK_HTTP_RESPONSE"],True,"BD_RENDER_OUT",None,None),
    ]
    file_ln = {
        reentry_id:  ("app/code/Magento/Review/Block/Product/View/ListView.php",59),
        load_id:     ("app/code/Magento/Review/Block/Product/View.php",None),
        getter_id:   (TPL,65),
        sanitizer_id:(TPL,65),
        output_id:   (TPL,65),
    }
    for seq, nid_, edge_prev, flags, is_bnd, bkind, skind, store in hop_seq:
        fpath, lineno = file_ln[nid_]
        upsert_hop(conn, {
            "hop_id":          hid(lin2_id, str(seq)),
            "lineage_id":      lin2_id,
            "hop_sequence":    seq,
            "node_id":         nid_,
            "edge_from_prev":  edge_prev,
            "value_in":        None,
            "value_out":       None,
            "flags_emitted":   json.dumps(flags) if flags else None,
            "flags_required":  None,
            "flags_invalidated": None,
            "is_boundary":     1 if is_bnd else 0,
            "boundary_kind":   bkind,
            "store_kind":      skind,
            "store_identifier": store,
            "file":            fpath,
            "line":            lineno,
        })

    upsert_reentry_link(conn, {
        "link_id":          rlid(write_lin_id, lin2_id, "detail-view"),
        "write_lineage_id": write_lin_id,
        "write_hop_id":     write_hop_id,
        "read_lineage_id":  lin2_id,
        "read_hop_id":      hid(lin2_id, "0"),
        "store_kind":       "db",
        "store_identifier": store_id,
        "confidence":       1.0,
        "evidence":         "runtime",
    })

    print(f"  2nd-order: {write_lin_id} → [{store_id}] → {lin2_id} (review/view)")


# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary(conn: sqlite3.Connection) -> None:
    print("\n── APPMAP SUMMARY (after hop population) ──────────────────")
    for q, label in [
        ("SELECT COUNT(*) FROM nodes",                                    "total nodes"),
        ("SELECT COUNT(*) FROM nodes WHERE node_type='HTTP_PARAM'",       "  HTTP_PARAM sources"),
        ("SELECT COUNT(*) FROM nodes WHERE node_type='PERSISTENCE_WRITE'","  PERSISTENCE_WRITE sinks"),
        ("SELECT COUNT(*) FROM nodes WHERE node_type='PERSISTENCE_READ'", "  PERSISTENCE_READ nodes"),
        ("SELECT COUNT(*) FROM nodes WHERE node_type='REENTRY_POINT'",    "  REENTRY_POINT nodes"),
        ("SELECT COUNT(*) FROM nodes WHERE node_type='MODEL_GETTER'",     "  MODEL_GETTER nodes"),
        ("SELECT COUNT(*) FROM nodes WHERE node_type='SANITIZER'",        "  SANITIZER nodes"),
        ("SELECT COUNT(*) FROM nodes WHERE node_type='OUTPUT_CALL'",      "  OUTPUT_CALL sinks"),
        ("SELECT COUNT(*) FROM edges",                                     "total edges"),
        ("SELECT COUNT(*) FROM lineages WHERE order_num=1",               "1st-order lineages (complete)"),
        ("SELECT COUNT(*) FROM lineages WHERE order_num=2",               "2nd-order lineages"),
        ("SELECT COUNT(*) FROM lineage_hops",                             "total lineage hops"),
        ("SELECT COUNT(*) FROM reentry_links",                            "reentry_links"),
    ]:
        n = conn.execute(q).fetchone()[0]
        print(f"  {n:>6}  {label}")

    print("\n── COMPLETE 2ND-ORDER CHAINS ───────────────────────────────")
    for row in conn.execute("""
        SELECT rl.store_identifier, l1.lineage_id, l2.lineage_id,
               r1.url_pattern AS write_route, r2.url_pattern AS read_route
        FROM reentry_links rl
        JOIN lineages l1 ON rl.write_lineage_id = l1.lineage_id
        JOIN lineages l2 ON rl.read_lineage_id  = l2.lineage_id
        LEFT JOIN routes r1 ON l1.route_id = r1.route_id
        LEFT JOIN routes r2 ON l2.route_id = r2.route_id
        WHERE l2.order_num = 2
        ORDER BY rl.store_identifier
    """):
        print(f"  [{row[0]}]")
        print(f"    write: {row[3] or '(no route)'} → L1={row[1]}")
        print(f"    read:  {row[4] or '(no route)'} → L2={row[2]}")
    print("───────────────────────────────────────────────────────────")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"Populating hops in: {APPMAP_DB}")
    conn = sqlite3.connect(APPMAP_DB)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")

    # 1. Review write lineages
    review_post_route = get_route_id(conn, "POST", "/review/product/post")
    print(f"\n[1] Review write route: {review_post_route}")
    if review_post_route:
        write_results = build_review_write_hops(conn, review_post_route)
        print(f"  Built L1 lineages for: {list(write_results.keys())}")
    else:
        print("  WARNING: /review/product/post not found in routes")
        write_results = {}

    # 2. Newsletter write lineage
    newsletter_route = get_route_id(conn, "POST", "/newsletter/subscriber/new")
    print(f"\n[2] Newsletter write route: {newsletter_route}")
    if newsletter_route:
        nl_lid, nl_hop = build_newsletter_write_hops(conn, newsletter_route)
        print(f"  Built L1 lineage: {nl_lid}")
    else:
        print("  WARNING: /newsletter/subscriber/newaction not found in routes")

    # 3. Review read lineage — listajax
    listajax_route = get_route_id(conn, "GET", "/review/product/listajax")
    print(f"\n[3] Listajax read route: {listajax_route}")
    if listajax_route and write_results:
        build_review_listajax_lineage(conn, listajax_route, write_results)
    else:
        print("  WARNING: listajax route not found or no write results")

    # 4. Review read lineage — view
    view_route = get_route_id(conn, "GET", "/review/product/view")
    print(f"\n[4] Review view read route: {view_route}")
    if view_route and write_results:
        build_review_view_lineage(conn, view_route, write_results)
    else:
        print("  WARNING: review/product/view route not found or no write results")

    conn.commit()
    print_summary(conn)
    conn.close()


if __name__ == "__main__":
    main()
