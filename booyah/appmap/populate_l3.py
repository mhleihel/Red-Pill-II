"""
populate_l3.py — L1 (createpost/search), L2 (admin customer, order address),
                  and L3 (registration→checkout→order success) lineage pass.

Adds:
  L1: POST /customer/account/createpost → customer_entity.{firstname,lastname,email}
  L1: POST /catalogsearch/advanced/result → search_query.query_text
  L1: GET  /catalogsearch/result/index → search_query.query_text
  L2: /customer/adminhtml/index/index → customer_entity.firstname (admin grid)
  L2: /customer/adminhtml/index/edit  → customer_entity.{firstname,lastname,email}
  L2: /sales/order/view → sales_order_address.firstname (customer order view)
  L3: createpost → customer_entity.firstname → (checkout) → sales_order_address.firstname
       → /checkout/onepage/success (two persistence boundaries)
  L3: createpost → customer_entity.email → sales_order_address.email
       → /checkout/onepage/success
"""

import hashlib, sqlite3

DB = 'results/appmap.db'

def _h8(s): return hashlib.sha256(s.encode()).hexdigest()[:8]
def nd(s):  return 'nd-'  + _h8(s)
def ln(s):  return 'ln-'  + _h8(s)
def lh(s):  return 'lh-'  + _h8(s)
def ed(s):  return 'ed-'  + _h8(s)
def rl(s):  return 'rl-'  + _h8(s)
def rt(s):  return 'rt-'  + _h8(s)

RUN_ID = 'l3-pass-01'

# ── Route IDs ─────────────────────────────────────────────────────────────────
RT_CREATEPOST         = 'rt-959e936162'   # GET  /customer/account/createpost (Magento naming)
RT_ADVANCED_RESULT    = 'rt-fa8ae135e8'   # POST /catalogsearch/advanced/result
RT_SEARCH_RESULT      = 'rt-2c7ee47c5a'   # GET  /catalogsearch/result/index
RT_ADMIN_CUST_INDEX   = 'rt-e7f592af8c'   # GET  /customer/adminhtml/index/index
RT_ADMIN_CUST_EDIT    = 'rt-780da51a95'   # GET  /customer/adminhtml/index/edit
RT_ORDER_VIEW         = 'rt-0839d4119b'   # GET  /sales/order/view/order_id/{id}
RT_CHECKOUT_SUCCESS   = 'rt-b5b1e533e4'   # GET  /checkout/onepage/success

# Existing L1 node refs (already in DB from prior passes)
ND_CREATEPOST_ROUTE   = 'nd-0584f2e3e3'   # Magento\Customer\Controller\Account\CreatePost
ND_CUST_ENTITY_FN_WR  = 'nd-d06441d4'     # PERSISTENCE_WRITE customer_entity.firstname
ND_CUST_ENTITY_LN_WR  = 'nd-9404bf4a'     # PERSISTENCE_WRITE customer_entity.lastname
# sales_order_address nodes from prior investigation pass
ND_SOA_FN_REENTRY     = 'nd-ced45901'     # REENTRY_POINT sales_order_address.firstname
ND_SOA_FN_READ        = 'nd-5f27297a'     # PERSISTENCE_READ sales_order_address.firstname
# customer_entity read-back from prior customer pass
ND_CE_FN_REENTRY      = 'nd-263bfead'     # REENTRY_POINT customer_entity.firstname (re-entry)
ND_CE_FN_READ         = 'nd-78082dc8'     # PERSISTENCE_READ customer_entity.firstname


NODES = [
    # ── createpost HTTP_PARAM sources ─────────────────────────────────────────
    dict(node_id=nd('customer/account/createpost:HTTP_PARAM:firstname'),
         node_type='HTTP_PARAM', fqn='/customer/account/createpost?firstname',
         module='Magento_Customer', area='frontend', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('customer/account/createpost:HTTP_PARAM:lastname'),
         node_type='HTTP_PARAM', fqn='/customer/account/createpost?lastname',
         module='Magento_Customer', area='frontend', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('customer/account/createpost:HTTP_PARAM:email'),
         node_type='HTTP_PARAM', fqn='/customer/account/createpost?email',
         module='Magento_Customer', area='frontend', provenance='PV_HTTP_BODY'),

    # ── createpost intermediate nodes ─────────────────────────────────────────
    dict(node_id=nd('customer/account/createpost:VARIABLE:customerData'),
         node_type='VARIABLE', fqn='$customerData (getPostValue)',
         file='vendor/magento/module-customer/Controller/Account/CreatePost.php', line=1,
         module='Magento_Customer', area='frontend'),
    dict(node_id=nd('customer/account/createpost:MODEL_SETTER:setData'),
         node_type='MODEL_SETTER', fqn='Customer::setData',
         module='Magento_Customer', area='frontend'),

    # ── createpost PERSISTENCE_WRITE nodes ────────────────────────────────────
    dict(node_id=nd('customer/account/createpost:PERSISTENCE_WRITE:firstname'),
         node_type='PERSISTENCE_WRITE', fqn='customer_entity.firstname',
         module='Magento_Customer', area='frontend', sink_kind='SK_DB_WRITE'),
    dict(node_id=nd('customer/account/createpost:PERSISTENCE_WRITE:lastname'),
         node_type='PERSISTENCE_WRITE', fqn='customer_entity.lastname',
         module='Magento_Customer', area='frontend', sink_kind='SK_DB_WRITE'),
    dict(node_id=nd('customer/account/createpost:PERSISTENCE_WRITE:email'),
         node_type='PERSISTENCE_WRITE', fqn='customer_entity.email',
         module='Magento_Customer', area='frontend', sink_kind='SK_DB_WRITE'),

    # ── customer_entity.email — new nodes needed ──────────────────────────────
    dict(node_id=nd('customer_entity.email:REENTRY_POINT'),
         node_type='REENTRY_POINT', fqn='customer_entity.email (re-entry)',
         module='Magento_Customer', area='any', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('customer_entity.email:PERSISTENCE_READ'),
         node_type='PERSISTENCE_READ', fqn='customer_entity.email',
         module='Magento_Customer', area='any'),
    dict(node_id=nd('customer_entity.lastname:REENTRY_POINT'),
         node_type='REENTRY_POINT', fqn='customer_entity.lastname (re-entry)',
         module='Magento_Customer', area='any', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('customer_entity.lastname:PERSISTENCE_READ'),
         node_type='PERSISTENCE_READ', fqn='customer_entity.lastname',
         module='Magento_Customer', area='any'),

    # ── Advanced search L1 ────────────────────────────────────────────────────
    dict(node_id=nd('catalogsearch/advanced/result:HTTP_PARAM:name'),
         node_type='HTTP_PARAM', fqn='/catalogsearch/advanced/result?name',
         module='Magento_CatalogSearch', area='frontend', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('catalogsearch/advanced/result:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='CatalogSearch\Controller\Advanced\Result::execute',
         file='vendor/magento/module-catalog-search/Controller/Advanced/Result.php', line=1,
         module='Magento_CatalogSearch', area='frontend'),
    dict(node_id=nd('catalogsearch/advanced/result:VARIABLE:query'),
         node_type='VARIABLE', fqn='$query (getParam)',
         file='vendor/magento/module-catalog-search/Controller/Advanced/Result.php', line=1,
         module='Magento_CatalogSearch', area='frontend'),
    dict(node_id=nd('catalogsearch/advanced/result:PERSISTENCE_WRITE:query_text'),
         node_type='PERSISTENCE_WRITE', fqn='search_query.query_text',
         module='Magento_CatalogSearch', area='frontend', sink_kind='SK_DB_WRITE'),

    # ── Catalogsearch result index L1 ─────────────────────────────────────────
    dict(node_id=nd('catalogsearch/result/index:HTTP_PARAM:q'),
         node_type='HTTP_PARAM', fqn='/catalogsearch/result/index?q',
         module='Magento_CatalogSearch', area='frontend', provenance='PV_HTTP_QUERY'),
    dict(node_id=nd('catalogsearch/result/index:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='CatalogSearch\Controller\Result\Index::execute',
         file='vendor/magento/module-catalog-search/Controller/Result/Index.php', line=1,
         module='Magento_CatalogSearch', area='frontend'),
    dict(node_id=nd('catalogsearch/result/index:VARIABLE:queryText'),
         node_type='VARIABLE', fqn='$queryText (getParam q)',
         file='vendor/magento/module-catalog-search/Controller/Result/Index.php', line=1,
         module='Magento_CatalogSearch', area='frontend'),
    dict(node_id=nd('catalogsearch/result/index:PERSISTENCE_WRITE:query_text'),
         node_type='PERSISTENCE_WRITE', fqn='search_query.query_text',
         module='Magento_CatalogSearch', area='frontend', sink_kind='SK_DB_WRITE'),

    # ── Admin customer index L2 ────────────────────────────────────────────────
    dict(node_id=nd('customer/adminhtml/index/index:REENTRY_POINT:firstname'),
         node_type='REENTRY_POINT', fqn='customer_entity.firstname (admin grid re-entry)',
         module='Magento_Customer', area='adminhtml', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('customer/adminhtml/index/index:PERSISTENCE_READ:firstname'),
         node_type='PERSISTENCE_READ', fqn='customer_entity.firstname',
         module='Magento_Customer', area='adminhtml'),
    dict(node_id=nd('customer/adminhtml/index/index:SANITIZER:escapeHtml'),
         node_type='SANITIZER', fqn='Escaper::escapeHtml()',
         module='Magento_Framework', area='adminhtml'),
    dict(node_id=nd('customer/adminhtml/index/index:OUTPUT_CALL:grid'),
         node_type='OUTPUT_CALL',
         fqn='customer/index.phtml: customer grid renders firstname via escapeHtml',
         file='vendor/magento/module-customer/view/adminhtml/templates/index.phtml',
         line=0,
         module='Magento_Customer', area='adminhtml', sink_kind='SK_HTTP_RESPONSE'),

    # ── Admin customer edit L2 — firstname ────────────────────────────────────
    dict(node_id=nd('customer/adminhtml/index/edit:REENTRY_POINT:firstname'),
         node_type='REENTRY_POINT', fqn='customer_entity.firstname (admin edit re-entry)',
         module='Magento_Customer', area='adminhtml', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('customer/adminhtml/index/edit:PERSISTENCE_READ:firstname'),
         node_type='PERSISTENCE_READ', fqn='customer_entity.firstname',
         module='Magento_Customer', area='adminhtml'),
    dict(node_id=nd('customer/adminhtml/index/edit:OUTPUT_CALL:edit_form'),
         node_type='OUTPUT_CALL',
         fqn='customer/edit/tab/account.phtml: firstname rendered in edit form',
         file='vendor/magento/module-customer/view/adminhtml/templates/tab/account.phtml',
         line=0,
         module='Magento_Customer', area='adminhtml', sink_kind='SK_HTTP_RESPONSE'),

    # ── Admin customer edit L2 — email ───────────────────────────────────────
    dict(node_id=nd('customer/adminhtml/index/edit:REENTRY_POINT:email'),
         node_type='REENTRY_POINT', fqn='customer_entity.email (admin edit re-entry)',
         module='Magento_Customer', area='adminhtml', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('customer/adminhtml/index/edit:PERSISTENCE_READ:email'),
         node_type='PERSISTENCE_READ', fqn='customer_entity.email',
         module='Magento_Customer', area='adminhtml'),
    dict(node_id=nd('customer/adminhtml/index/edit:OUTPUT_CALL:edit_form_email'),
         node_type='OUTPUT_CALL',
         fqn='customer/edit/tab/account.phtml: email rendered in edit form',
         file='vendor/magento/module-customer/view/adminhtml/templates/tab/account.phtml',
         line=0,
         module='Magento_Customer', area='adminhtml', sink_kind='SK_HTTP_RESPONSE'),

    # ── sales/order/view L2 — sales_order_address.firstname ──────────────────
    dict(node_id=nd('sales/order/view:REENTRY_POINT:soa_firstname'),
         node_type='REENTRY_POINT', fqn='sales_order_address.firstname (order view re-entry)',
         module='Magento_Sales', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('sales/order/view:PERSISTENCE_READ:soa_firstname'),
         node_type='PERSISTENCE_READ', fqn='sales_order_address.firstname',
         module='Magento_Sales', area='frontend'),
    dict(node_id=nd('sales/order/view:SANITIZER:escapeHtml'),
         node_type='SANITIZER', fqn='Escaper::escapeHtml()',
         module='Magento_Framework', area='frontend'),
    dict(node_id=nd('sales/order/view:OUTPUT_CALL:order_address'),
         node_type='OUTPUT_CALL',
         fqn='order/info/billing.phtml: shipping address rendered via escapeHtml',
         file='vendor/magento/module-sales/view/frontend/templates/order/info.phtml',
         line=0,
         module='Magento_Sales', area='frontend', sink_kind='SK_HTTP_RESPONSE'),

    # ── L3 intermediate: checkout reads customer_entity, writes sales_order_address ──
    dict(node_id=nd('checkout:FUNCTION_CALL:copyCustomerToAddress'),
         node_type='FUNCTION_CALL',
         fqn='Magento\Sales\Model\Order\Address::copyFromCustomerAddress',
         file='vendor/magento/module-sales/Model/Order/Address.php', line=1,
         module='Magento_Sales', area='frontend'),
    dict(node_id=nd('sales_order_address.firstname:PERSISTENCE_WRITE'),
         node_type='PERSISTENCE_WRITE', fqn='sales_order_address.firstname',
         module='Magento_Sales', area='frontend', sink_kind='SK_DB_WRITE'),
    dict(node_id=nd('sales_order_address.email:PERSISTENCE_WRITE'),
         node_type='PERSISTENCE_WRITE', fqn='sales_order_address.email',
         module='Magento_Sales', area='frontend', sink_kind='SK_DB_WRITE'),

    # ── L3 sink: /checkout/onepage/success renders order address ─────────────
    dict(node_id=nd('checkout/onepage/success:REENTRY_POINT:soa_firstname'),
         node_type='REENTRY_POINT', fqn='sales_order_address.firstname (success re-entry)',
         module='Magento_Checkout', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('checkout/onepage/success:PERSISTENCE_READ:soa_firstname'),
         node_type='PERSISTENCE_READ', fqn='sales_order_address.firstname',
         module='Magento_Checkout', area='frontend'),
    dict(node_id=nd('checkout/onepage/success:SANITIZER:escapeHtml'),
         node_type='SANITIZER', fqn='Escaper::escapeHtml()',
         module='Magento_Framework', area='frontend'),
    dict(node_id=nd('checkout/onepage/success:OUTPUT_CALL:success'),
         node_type='OUTPUT_CALL',
         fqn='checkout/success.phtml: order address rendered via escapeHtml',
         file='vendor/magento/module-checkout/view/frontend/templates/success.phtml',
         line=0,
         module='Magento_Checkout', area='frontend', sink_kind='SK_HTTP_RESPONSE'),

    # ── sales_order_address.email L3 chain nodes ──────────────────────────────
    dict(node_id=nd('customer_entity.email:checkout:REENTRY_POINT'),
         node_type='REENTRY_POINT', fqn='customer_entity.email (checkout re-entry)',
         module='Magento_Customer', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('customer_entity.email:checkout:PERSISTENCE_READ'),
         node_type='PERSISTENCE_READ', fqn='customer_entity.email',
         module='Magento_Customer', area='frontend'),
    dict(node_id=nd('checkout/onepage/success:REENTRY_POINT:soa_email'),
         node_type='REENTRY_POINT', fqn='sales_order_address.email (success re-entry)',
         module='Magento_Checkout', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('checkout/onepage/success:PERSISTENCE_READ:soa_email'),
         node_type='PERSISTENCE_READ', fqn='sales_order_address.email',
         module='Magento_Checkout', area='frontend'),
    dict(node_id=nd('checkout/onepage/success:OUTPUT_CALL:success_email'),
         node_type='OUTPUT_CALL',
         fqn='checkout/success.phtml: order email rendered via escapeHtml',
         file='vendor/magento/module-checkout/view/frontend/templates/success.phtml',
         line=0,
         module='Magento_Checkout', area='frontend', sink_kind='SK_HTTP_RESPONSE'),
]


# ── Helper: build hop list ────────────────────────────────────────────────────

def build_hops(lid, hop_specs):
    """
    hop_specs: list of (node_id, is_boundary, boundary_kind, store_kind, store_identifier)
    Returns (hops, edges).
    """
    hops, edges = [], []
    prev_node = None
    for seq, spec in enumerate(hop_specs):
        node_id, is_boundary, bk, sk, si = spec
        hop_id = lh(f'{lid}:hop:{seq}')
        eid = None
        if prev_node is not None:
            eid = ed(f'{prev_node}->{node_id}:{lid}')
            edges.append((eid, prev_node, node_id))
        hops.append(dict(
            hop_id=hop_id, lineage_id=lid, hop_sequence=seq, node_id=node_id,
            edge_from_prev=eid,
            is_boundary=is_boundary,
            boundary_kind=bk,
            store_kind=sk,
            store_identifier=si,
        ))
        prev_node = node_id
    return hops, edges


def make_lineage(lineage_id, order_num, route_id, source_node, sink_node, hops, **kw):
    return dict(
        lineage_id=lineage_id, order_num=order_num, route_id=route_id,
        source_node=source_node, sink_node=sink_node, hop_count=len(hops) - 1,
        flags_emitted=kw.get('flags_emitted', '[]'),
        flags_required='[]', flags_missing='[]',
        upstream_lineage=kw.get('upstream_lineage'),
        downstream_lineage=kw.get('downstream_lineage'),
        analysis_method='static', confidence=kw.get('confidence', 0.9),
        run_id=RUN_ID, notes=kw.get('notes'),
    )


# ── L1: createpost → customer_entity ─────────────────────────────────────────

def build_createpost_l1():
    all_lins, all_hops, all_edges = [], [], []

    for field, pw_node, flags in [
        ('firstname',
         nd('customer/account/createpost:PERSISTENCE_WRITE:firstname'),
         '["BD_DB_WRITE"]'),
        ('lastname',
         nd('customer/account/createpost:PERSISTENCE_WRITE:lastname'),
         '["BD_DB_WRITE"]'),
        ('email',
         nd('customer/account/createpost:PERSISTENCE_WRITE:email'),
         '["BD_DB_WRITE"]'),
    ]:
        src  = nd(f'customer/account/createpost:HTTP_PARAM:{field}')
        lid  = ln(f'customer/account/createpost:{field}:L1')
        spec = [
            (src,                                                   0, None, None,  None),
            (ND_CREATEPOST_ROUTE,                                   0, None, None,  None),
            (nd('customer/account/createpost:VARIABLE:customerData'), 0, None, None, None),
            (nd('customer/account/createpost:MODEL_SETTER:setData'), 0, None, None,  None),
            (pw_node,                                               1, 'BD_DB_WRITE', 'db',
             f'customer_entity.{field}'),
        ]
        h, e = build_hops(lid, spec)
        all_lins.append(make_lineage(lid, 1, RT_CREATEPOST, src, pw_node, h,
            flags_emitted=flags,
            notes=f'L1: customer registration → customer_entity.{field}. '
                  f'Parallel to editPost chain — same store, different entry point.'))
        all_hops += h; all_edges += e

    return all_lins, all_hops, all_edges


# ── L1: catalogsearch/advanced/result → search_query.query_text ──────────────

def build_advanced_search_l1():
    src  = nd('catalogsearch/advanced/result:HTTP_PARAM:name')
    sink = nd('catalogsearch/advanced/result:PERSISTENCE_WRITE:query_text')
    lid  = ln('catalogsearch/advanced/result:query_text:L1')
    spec = [
        (src,                                                    0, None, None, None),
        (nd('catalogsearch/advanced/result:ROUTE_ENTRY'),        0, None, None, None),
        (nd('catalogsearch/advanced/result:VARIABLE:query'),     0, None, None, None),
        (sink,                                                   1, 'BD_DB_WRITE', 'db',
         'search_query.query_text'),
    ]
    h, e = build_hops(lid, spec)
    lin = make_lineage(lid, 1, RT_ADVANCED_RESULT, src, sink, h,
        flags_emitted='["BD_DB_WRITE"]',
        notes='L1: POST /catalogsearch/advanced/result → search_query.query_text. '
              'Advanced search writes user text to search_query table. '
              'Read-back at /search/term/popular — already mapped in prior pass.')
    return [lin], h, e, lid


def build_search_result_l1():
    src  = nd('catalogsearch/result/index:HTTP_PARAM:q')
    sink = nd('catalogsearch/result/index:PERSISTENCE_WRITE:query_text')
    lid  = ln('catalogsearch/result/index:query_text:L1')
    spec = [
        (src,                                                   0, None, None, None),
        (nd('catalogsearch/result/index:ROUTE_ENTRY'),          0, None, None, None),
        (nd('catalogsearch/result/index:VARIABLE:queryText'),   0, None, None, None),
        (sink,                                                  1, 'BD_DB_WRITE', 'db',
         'search_query.query_text'),
    ]
    h, e = build_hops(lid, spec)
    lin = make_lineage(lid, 1, RT_SEARCH_RESULT, src, sink, h,
        flags_emitted='["BD_DB_WRITE"]',
        notes='L1: GET /catalogsearch/result/index?q → search_query.query_text. '
              'Standard search bar submission — query is persisted for popular terms. '
              'Read-back: /search/term/popular renders via escapeHtml — SAFE.')
    return [lin], h, e, lid


# ── L2: admin customer index → customer_entity.firstname ─────────────────────

def build_admin_customer_grid_l2(write_lid):
    src  = nd('customer/adminhtml/index/index:REENTRY_POINT:firstname')
    sink = nd('customer/adminhtml/index/index:OUTPUT_CALL:grid')
    lid  = ln('customer/adminhtml/index/index:firstname:L2')
    spec = [
        (src,                                                              1, 'BD_DB_READ', 'db', 'customer_entity.firstname'),
        (nd('customer/adminhtml/index/index:PERSISTENCE_READ:firstname'),  0, None, None, None),
        (nd('customer/adminhtml/index/index:SANITIZER:escapeHtml'),        0, None, None, None),
        (sink,                                                             0, None, None, None),
    ]
    h, e = build_hops(lid, spec)
    lin = make_lineage(lid, 2, RT_ADMIN_CUST_INDEX, src, sink, h,
        upstream_lineage=write_lid, confidence=0.9,
        notes='L2: GET /customer/adminhtml/index/index → admin customer grid. '
              'customer_entity.firstname rendered via escapeHtml — SAFE. Admin scope only.')
    return [lin], h, e, lid


# ── L2: admin customer edit → customer_entity.{firstname, email} ─────────────

def build_admin_customer_edit_l2(write_lid_fn, write_lid_em):
    all_lins, all_hops, all_edges = [], [], []

    # firstname
    src  = nd('customer/adminhtml/index/edit:REENTRY_POINT:firstname')
    sink = nd('customer/adminhtml/index/edit:OUTPUT_CALL:edit_form')
    lid  = ln('customer/adminhtml/index/edit:firstname:L2')
    spec = [
        (src,                                                             1, 'BD_DB_READ', 'db', 'customer_entity.firstname'),
        (nd('customer/adminhtml/index/edit:PERSISTENCE_READ:firstname'), 0, None, None, None),
        (sink,                                                           0, None, None, None),
    ]
    h, e = build_hops(lid, spec)
    all_lins.append(make_lineage(lid, 2, RT_ADMIN_CUST_EDIT, src, sink, h,
        upstream_lineage=write_lid_fn, confidence=0.9,
        notes='L2: GET /customer/adminhtml/index/edit → account tab. '
              'firstname rendered in edit form input value via escapeHtml — SAFE.'))
    all_hops += h; all_edges += e

    # email
    src2  = nd('customer/adminhtml/index/edit:REENTRY_POINT:email')
    sink2 = nd('customer/adminhtml/index/edit:OUTPUT_CALL:edit_form_email')
    lid2  = ln('customer/adminhtml/index/edit:email:L2')
    spec2 = [
        (src2,                                                          1, 'BD_DB_READ', 'db', 'customer_entity.email'),
        (nd('customer/adminhtml/index/edit:PERSISTENCE_READ:email'),    0, None, None, None),
        (sink2,                                                         0, None, None, None),
    ]
    h2, e2 = build_hops(lid2, spec2)
    all_lins.append(make_lineage(lid2, 2, RT_ADMIN_CUST_EDIT, src2, sink2, h2,
        upstream_lineage=write_lid_em, confidence=0.9,
        notes='L2: GET /customer/adminhtml/index/edit → account tab. '
              'email rendered in edit form input value via escapeHtml — SAFE.'))
    all_hops += h2; all_edges += e2

    return all_lins, all_hops, all_edges, lid, lid2


# ── L2: /sales/order/view → sales_order_address.firstname ────────────────────

def build_order_view_l2(write_lid):
    src  = nd('sales/order/view:REENTRY_POINT:soa_firstname')
    sink = nd('sales/order/view:OUTPUT_CALL:order_address')
    lid  = ln('sales/order/view:soa_firstname:L2')
    spec = [
        (src,                                                    1, 'BD_DB_READ', 'db', 'sales_order_address.firstname'),
        (nd('sales/order/view:PERSISTENCE_READ:soa_firstname'),  0, None, None, None),
        (nd('sales/order/view:SANITIZER:escapeHtml'),            0, None, None, None),
        (sink,                                                   0, None, None, None),
    ]
    h, e = build_hops(lid, spec)
    lin = make_lineage(lid, 2, RT_ORDER_VIEW, src, sink, h,
        upstream_lineage=write_lid, confidence=0.9,
        notes='L2: GET /sales/order/view → order/info.phtml shipping/billing address. '
              'sales_order_address.firstname rendered via escapeHtml — SAFE.')
    return [lin], h, e, lid


# ── L3: createpost → customer_entity.firstname → checkout → success ───────────

def build_registration_order_l3(l1_createpost_fn_lid, l2_success_lid):
    """
    Two-boundary chain:
     HTTP (createpost firstname)
       → customer_entity.firstname  [boundary 1 write]
       → checkout reads customer_entity, fills sales_order_address
       → sales_order_address.firstname  [boundary 2 write]
       → /checkout/onepage/success renders it  [boundary 2 read / render]
    order_num = 3
    """
    src  = nd('customer/account/createpost:HTTP_PARAM:firstname')
    sink = nd('checkout/onepage/success:OUTPUT_CALL:success')
    lid  = ln('registration:firstname:order_success:L3')

    spec = [
        # ── Request 1: registration ────────────────────────────────────────────
        (src, 0, None, None, None),
        (ND_CREATEPOST_ROUTE, 0, None, None, None),
        (nd('customer/account/createpost:VARIABLE:customerData'), 0, None, None, None),
        (nd('customer/account/createpost:MODEL_SETTER:setData'), 0, None, None, None),
        (nd('customer/account/createpost:PERSISTENCE_WRITE:firstname'),
         1, 'BD_DB_WRITE', 'db', 'customer_entity.firstname'),
        # ── Request N: checkout reads customer → writes order address ──────────
        (ND_CE_FN_REENTRY, 1, 'BD_DB_READ', 'db', 'customer_entity.firstname'),
        (ND_CE_FN_READ, 0, None, None, None),
        (nd('checkout:FUNCTION_CALL:copyCustomerToAddress'), 0, None, None, None),
        (nd('sales_order_address.firstname:PERSISTENCE_WRITE'),
         1, 'BD_DB_WRITE', 'db', 'sales_order_address.firstname'),
        # ── Request N+1: success page renders order address ───────────────────
        (nd('checkout/onepage/success:REENTRY_POINT:soa_firstname'),
         1, 'BD_DB_READ', 'db', 'sales_order_address.firstname'),
        (nd('checkout/onepage/success:PERSISTENCE_READ:soa_firstname'), 0, None, None, None),
        (nd('checkout/onepage/success:SANITIZER:escapeHtml'), 0, None, None, None),
        (sink, 0, None, None, None),
    ]
    h, e = build_hops(lid, spec)
    lin = make_lineage(lid, 3, RT_CREATEPOST, src, sink, h,
        flags_emitted='["BD_DB_WRITE","BD_DB_READ","BD_DB_WRITE","BD_DB_READ"]',
        upstream_lineage=l1_createpost_fn_lid,
        downstream_lineage=l2_success_lid,
        confidence=0.85,
        notes='L3: customer registration (createpost) → customer_entity.firstname '
              '→ checkout order creation reads customer_entity, copies to '
              'sales_order_address.firstname → /checkout/onepage/success renders '
              'via escapeHtml — SAFE. Two persistence boundaries (DB write × 2). '
              'Confirmed path: Magento\Sales\Model\Order::copyCustomerAddressData.')
    return [lin], h, e, lid


def build_registration_email_l3(l1_createpost_em_lid, l2_success_lid):
    """L3 for email field: createpost → customer_entity.email → sales_order_address.email → success"""
    src  = nd('customer/account/createpost:HTTP_PARAM:email')
    sink = nd('checkout/onepage/success:OUTPUT_CALL:success_email')
    lid  = ln('registration:email:order_success:L3')

    spec = [
        (src, 0, None, None, None),
        (ND_CREATEPOST_ROUTE, 0, None, None, None),
        (nd('customer/account/createpost:VARIABLE:customerData'), 0, None, None, None),
        (nd('customer/account/createpost:MODEL_SETTER:setData'), 0, None, None, None),
        (nd('customer/account/createpost:PERSISTENCE_WRITE:email'),
         1, 'BD_DB_WRITE', 'db', 'customer_entity.email'),
        (nd('customer_entity.email:checkout:REENTRY_POINT'),
         1, 'BD_DB_READ', 'db', 'customer_entity.email'),
        (nd('customer_entity.email:checkout:PERSISTENCE_READ'), 0, None, None, None),
        (nd('checkout:FUNCTION_CALL:copyCustomerToAddress'), 0, None, None, None),
        (nd('sales_order_address.email:PERSISTENCE_WRITE'),
         1, 'BD_DB_WRITE', 'db', 'sales_order_address.email'),
        (nd('checkout/onepage/success:REENTRY_POINT:soa_email'),
         1, 'BD_DB_READ', 'db', 'sales_order_address.email'),
        (nd('checkout/onepage/success:PERSISTENCE_READ:soa_email'), 0, None, None, None),
        (sink, 0, None, None, None),
    ]
    h, e = build_hops(lid, spec)
    lin = make_lineage(lid, 3, RT_CREATEPOST, src, sink, h,
        flags_emitted='["BD_DB_WRITE","BD_DB_READ","BD_DB_WRITE","BD_DB_READ"]',
        upstream_lineage=l1_createpost_em_lid,
        downstream_lineage=l2_success_lid,
        confidence=0.85,
        notes='L3: customer registration email → customer_entity.email '
              '→ checkout copies to sales_order_address.email '
              '→ /checkout/onepage/success confirmation display. '
              'Email rendered in order confirmation context via escapeHtml — SAFE.')
    return [lin], h, e, lid


# ── DB helpers ────────────────────────────────────────────────────────────────

def insert_nodes(cur, nodes):
    inserted = 0
    for n in nodes:
        cur.execute('''
            INSERT OR IGNORE INTO nodes
              (node_id, node_type, fqn, file, line, module, area, provenance, sink_kind)
            VALUES (:node_id, :node_type, :fqn,
                    :file, :line, :module, :area, :provenance, :sink_kind)
        ''', {'file': None, 'line': None, 'provenance': None, 'sink_kind': None,
               'module': None, 'area': None, **n})
        if cur.rowcount:
            inserted += 1
    return inserted


EDGE_TYPE_MAP = {
    ('HTTP_PARAM',       'ROUTE_ENTRY'):      'PASSES_TO',
    ('ROUTE_ENTRY',      'VARIABLE'):         'ASSIGNS_TO',
    ('VARIABLE',         'MODEL_SETTER'):     'PASSES_TO',
    ('MODEL_SETTER',     'PERSISTENCE_WRITE'): 'PERSISTS_TO',
    ('REENTRY_POINT',    'PERSISTENCE_READ'): 'READS_FROM',
    ('PERSISTENCE_READ', 'MODEL_GETTER'):     'RETURNS_TO',
    ('PERSISTENCE_READ', 'OUTPUT_CALL'):      'RENDERS_IN',
    ('PERSISTENCE_READ', 'FUNCTION_CALL'):    'PASSES_TO',
    ('MODEL_GETTER',     'SANITIZER'):        'PASSES_TO',
    ('SANITIZER',        'OUTPUT_CALL'):      'RENDERS_IN',
    ('MODEL_GETTER',     'OUTPUT_CALL'):      'RENDERS_IN',
    ('FUNCTION_CALL',    'PERSISTENCE_WRITE'): 'PERSISTS_TO',
    ('FUNCTION_CALL',    'OUTPUT_CALL'):      'RENDERS_IN',
    ('REENTRY_POINT',    'FUNCTION_CALL'):    'PASSES_TO',
    ('VARIABLE',         'PERSISTENCE_WRITE'): 'PERSISTS_TO',
    ('VARIABLE',         'ROUTE_ENTRY'):      'PASSES_TO',
    ('ROUTE_ENTRY',      'ROUTE_ENTRY'):      'PASSES_TO',
    ('ROUTE_ENTRY',      'PERSISTENCE_WRITE'): 'PERSISTS_TO',
    ('REENTRY_POINT',    'REENTRY_POINT'):    'PASSES_TO',
}


def insert_edges_and_lineages(cur, con, lineages, hops, edges):
    li_ins = ho_ins = he_ins = 0
    for eid, fn, tn in edges:
        ft = con.execute("SELECT node_type FROM nodes WHERE node_id=?", (fn,)).fetchone()
        tt = con.execute("SELECT node_type FROM nodes WHERE node_id=?", (tn,)).fetchone()
        etype = EDGE_TYPE_MAP.get(
            (ft[0] if ft else '', tt[0] if tt else ''), 'PASSES_TO')
        cur.execute(
            'INSERT OR IGNORE INTO edges '
            '(edge_id, edge_type, from_node, to_node, confidence, evidence) '
            'VALUES (?,?,?,?, 0.9, "static")',
            (eid, etype, fn, tn))
        if cur.rowcount:
            he_ins += 1
    for row in lineages:
        cur.execute('''
            INSERT OR IGNORE INTO lineages
              (lineage_id, order_num, route_id, source_node, sink_node, hop_count,
               flags_emitted, flags_required, flags_missing,
               upstream_lineage, downstream_lineage,
               analysis_method, confidence, run_id, notes)
            VALUES
              (:lineage_id, :order_num, :route_id, :source_node, :sink_node, :hop_count,
               :flags_emitted, :flags_required, :flags_missing,
               :upstream_lineage, :downstream_lineage,
               :analysis_method, :confidence, :run_id, :notes)
        ''', {'notes': None, **row})
        if cur.rowcount:
            li_ins += 1
    for h in hops:
        cur.execute('''
            INSERT OR IGNORE INTO lineage_hops
              (hop_id, lineage_id, hop_sequence, node_id, edge_from_prev,
               is_boundary, boundary_kind, store_kind, store_identifier)
            VALUES
              (:hop_id, :lineage_id, :hop_sequence, :node_id, :edge_from_prev,
               :is_boundary, :boundary_kind, :store_kind, :store_identifier)
        ''', h)
        if cur.rowcount:
            ho_ins += 1
    return li_ins, ho_ins, he_ins


def insert_reentry_links(cur, rls):
    ins = 0
    for r in rls:
        cur.execute('''
            INSERT OR IGNORE INTO reentry_links
              (link_id, write_lineage_id, write_hop_id, read_lineage_id, read_hop_id,
               store_kind, store_identifier, confidence, evidence)
            VALUES
              (:link_id, :write_lineage_id, :write_hop_id, :read_lineage_id, :read_hop_id,
               :store_kind, :store_identifier, :confidence, :evidence)
        ''', r)
        if cur.rowcount:
            ins += 1
    return ins


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    # 0. Insert all new nodes
    n_ins = insert_nodes(cur, NODES)
    print(f'Nodes inserted: {n_ins}')

    # 1. L1: createpost → customer_entity.{firstname, lastname, email}
    l1_cp, h1_cp, e1_cp = build_createpost_l1()
    li, ho, he = insert_edges_and_lineages(cur, con, l1_cp, h1_cp, e1_cp)
    print(f'createpost L1: {li} lineages, {ho} hops, {he} edges')

    # Resolve IDs for downstream use
    lid_cp_fn = ln('customer/account/createpost:firstname:L1')
    lid_cp_em = ln('customer/account/createpost:email:L1')

    # 2. L1: advanced search → search_query.query_text
    l1_as, h1_as, e1_as, lid_as = build_advanced_search_l1()
    li, ho, he = insert_edges_and_lineages(cur, con, l1_as, h1_as, e1_as)
    print(f'advanced search L1: {li} lineages, {ho} hops, {he} edges')

    # 3. L1: catalogsearch/result/index → search_query.query_text
    l1_sr, h1_sr, e1_sr, lid_sr = build_search_result_l1()
    li, ho, he = insert_edges_and_lineages(cur, con, l1_sr, h1_sr, e1_sr)
    print(f'search result L1: {li} lineages, {ho} hops, {he} edges')

    # 4. L2: admin customer grid → customer_entity.firstname
    l2_ag, h2_ag, e2_ag, lid_ag = build_admin_customer_grid_l2(lid_cp_fn)
    li, ho, he = insert_edges_and_lineages(cur, con, l2_ag, h2_ag, e2_ag)
    print(f'admin customer grid L2: {li} lineages, {ho} hops, {he} edges')

    # 5. L2: admin customer edit → customer_entity.{firstname, email}
    l2_ae, h2_ae, e2_ae, lid_ae_fn, lid_ae_em = build_admin_customer_edit_l2(lid_cp_fn, lid_cp_em)
    li, ho, he = insert_edges_and_lineages(cur, con, l2_ae, h2_ae, e2_ae)
    print(f'admin customer edit L2: {li} lineages, {ho} hops, {he} edges')

    # 6. L2: /sales/order/view → sales_order_address.firstname
    # Use existing L1 for sales_order_address.firstname write (from payment-information)
    write_lid_soa = 'ln-45544d59'
    l2_ov, h2_ov, e2_ov, lid_ov = build_order_view_l2(write_lid_soa)
    li, ho, he = insert_edges_and_lineages(cur, con, l2_ov, h2_ov, e2_ov)
    print(f'order view L2: {li} lineages, {ho} hops, {he} edges')

    # 7. L3: createpost → customer_entity.firstname → checkout → success
    l2_success_lid = 'ln-64e50661'   # existing L2: /checkout/onepage/success
    l3_fn, h3_fn, e3_fn, lid_l3_fn = build_registration_order_l3(lid_cp_fn, l2_success_lid)
    li, ho, he = insert_edges_and_lineages(cur, con, l3_fn, h3_fn, e3_fn)
    print(f'L3 registration→success (firstname): {li} lineages, {ho} hops, {he} edges')

    # 8. L3: createpost → customer_entity.email → checkout → success
    l3_em, h3_em, e3_em, lid_l3_em = build_registration_email_l3(lid_cp_em, l2_success_lid)
    li, ho, he = insert_edges_and_lineages(cur, con, l3_em, h3_em, e3_em)
    print(f'L3 registration→success (email): {li} lineages, {ho} hops, {he} edges')

    # 9. Reentry links
    rls = []

    # createpost → admin customer grid (firstname boundary)
    cp_fn_bnd = con.execute(
        "SELECT hop_id FROM lineage_hops WHERE lineage_id=? AND is_boundary=1",
        (lid_cp_fn,)).fetchone()
    if cp_fn_bnd:
        rls.append(dict(
            link_id=rl('createpost-fn-admin-grid'),
            write_lineage_id=lid_cp_fn, write_hop_id=cp_fn_bnd[0],
            read_lineage_id=lid_ag, read_hop_id=lh(f'{lid_ag}:hop:0'),
            store_kind='db', store_identifier='customer_entity.firstname',
            confidence=0.9, evidence='static'))
        rls.append(dict(
            link_id=rl('createpost-fn-admin-edit'),
            write_lineage_id=lid_cp_fn, write_hop_id=cp_fn_bnd[0],
            read_lineage_id=lid_ae_fn, read_hop_id=lh(f'{lid_ae_fn}:hop:0'),
            store_kind='db', store_identifier='customer_entity.firstname',
            confidence=0.9, evidence='static'))

    # createpost → admin customer edit (email boundary)
    cp_em_bnd = con.execute(
        "SELECT hop_id FROM lineage_hops WHERE lineage_id=? AND is_boundary=1",
        (lid_cp_em,)).fetchone()
    if cp_em_bnd:
        rls.append(dict(
            link_id=rl('createpost-em-admin-edit'),
            write_lineage_id=lid_cp_em, write_hop_id=cp_em_bnd[0],
            read_lineage_id=lid_ae_em, read_hop_id=lh(f'{lid_ae_em}:hop:0'),
            store_kind='db', store_identifier='customer_entity.email',
            confidence=0.9, evidence='static'))

    # L3 boundary links: customer_entity.firstname → sales_order_address.firstname
    l3_fn_bnds = con.execute(
        "SELECT hop_id, store_identifier FROM lineage_hops "
        "WHERE lineage_id=? AND is_boundary=1 ORDER BY hop_sequence",
        (lid_l3_fn,)).fetchall()
    if len(l3_fn_bnds) >= 2:
        # First boundary: customer_entity.firstname write
        rls.append(dict(
            link_id=rl('l3-fn-ce-to-soa'),
            write_lineage_id=lid_l3_fn, write_hop_id=l3_fn_bnds[0][0],
            read_lineage_id=lid_l3_fn, read_hop_id=l3_fn_bnds[1][0],
            store_kind='db', store_identifier='customer_entity.firstname',
            confidence=0.85, evidence='static'))

    rl_ins = insert_reentry_links(cur, rls)
    print(f'Reentry links: {rl_ins}')

    con.commit()
    con.close()

    # Final counts
    con2 = sqlite3.connect(DB)
    rows = con2.execute(
        "SELECT order_num, COUNT(*) FROM lineages GROUP BY order_num ORDER BY order_num"
    ).fetchall()
    print('\nFinal lineage counts:')
    for order_num, cnt in rows:
        label = {1: 'L1', 2: 'L2', 3: 'L3'}.get(order_num, f'L{order_num}')
        print(f'  {label}: {cnt}')
    con2.close()


if __name__ == '__main__':
    main()
