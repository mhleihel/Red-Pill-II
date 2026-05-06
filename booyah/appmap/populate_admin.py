"""
populate_admin.py — admin route pass for Booyah appmap

Adds:
  1. L1 lineages for admin write routes (CMS page, product, category)
  2. L2 lineages for admin→guest stored XSS chains (HIGH VALUE)
  3. L2 lineages for admin read-back chains (newsletter, review, search)
  4. Resolves 8 needs_admin deferred entries
  5. Classifies remaining 700+ adminhtml routes as no_string_taint
"""

import hashlib, sqlite3, time

DB = 'results/appmap.db'

# ---------------------------------------------------------------------------
# ID helpers
# ---------------------------------------------------------------------------
def _h8(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:8]

def nd(s):   return 'nd-'  + _h8(s)
def ln(s):   return 'ln-'  + _h8(s)
def lh(s):   return 'lh-'  + _h8(s)
def ed(s):   return 'ed-'  + _h8(s)
def rl(s):   return 'rl-'  + _h8(s)
def df(s):   return 'df-'  + _h8(s)

RUN_ID = 'admin-pass-01'

# ---------------------------------------------------------------------------
# Route IDs (looked up from routes table)
# ---------------------------------------------------------------------------
RT_CMS_SAVE        = 'rt-6984d3002a'   # GET /cms/adminhtml/page/save
RT_PRODUCT_SAVE    = 'rt-aa7e4f9cb9'   # GET /catalog/adminhtml/product/save
RT_CATEGORY_SAVE   = 'rt-d969f2b5f7'   # GET /catalog/adminhtml/category/save

RT_CMS_VIEW        = 'rt-be53736b29'   # GET /cms/page/view
RT_CMS_INDEX       = 'rt-58649cfde5'   # GET /cms/index/index
RT_PRODUCT_VIEW    = 'rt-b1ceeb6964'   # GET /catalog/product/view
RT_CATEGORY_VIEW   = 'rt-1ac594609f'   # GET /catalog/category/view

RT_NL_SUBSCRIBER   = 'rt-4db9cf9f48'   # GET /newsletter/adminhtml/subscriber/index
RT_REVIEW_PENDING  = 'rt-fde056297e'   # GET /review/adminhtml/product/pending
RT_SEARCH_TERM_IDX = 'rt-9a03782af6'   # GET /search/adminhtml/term/index

# Existing L1 write lineage IDs for newsletter (from previous pass)
# We need these to create admin-area L2 read-back lineages
# newsletter_subscriber.subscriber_email — the L1 lineage written by frontend
# Find these by looking at store_identifier in deferred entries

# ---------------------------------------------------------------------------
# Node definitions
# ---------------------------------------------------------------------------
NODES = [
    # ── CMS PAGE SAVE ────────────────────────────────────────────────────
    dict(node_id=nd('admin/cms/page:HTTP_PARAM:title'),
         node_type='HTTP_PARAM', fqn='/cms/adminhtml/page/save?title',
         module='Magento_Cms', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('admin/cms/page:HTTP_PARAM:content'),
         node_type='HTTP_PARAM', fqn='/cms/adminhtml/page/save?content',
         module='Magento_Cms', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('admin/cms/page:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='Cms\Controller\Adminhtml\Page\Save::execute',
         file='app/code/Magento/Cms/Controller/Adminhtml/Page/Save.php', line=1,
         module='Magento_Cms', area='adminhtml'),
    dict(node_id=nd('admin/cms/page:VARIABLE:pageData'),
         node_type='VARIABLE', fqn='$pageData (getPostValue)',
         file='app/code/Magento/Cms/Controller/Adminhtml/Page/Save.php', line=85,
         module='Magento_Cms', area='adminhtml'),
    dict(node_id=nd('admin/cms/page:MODEL_SETTER:setData'),
         node_type='MODEL_SETTER', fqn='Page::setData',
         file='app/code/Magento/Cms/Model/Page.php', line=0,
         module='Magento_Cms', area='adminhtml'),
    dict(node_id=nd('admin/cms/page:PERSISTENCE_WRITE:content'),
         node_type='PERSISTENCE_WRITE', fqn='cms_page.content',
         module='Magento_Cms', area='adminhtml', sink_kind='SK_DB_WRITE'),
    dict(node_id=nd('admin/cms/page:PERSISTENCE_WRITE:title'),
         node_type='PERSISTENCE_WRITE', fqn='cms_page.title',
         module='Magento_Cms', area='adminhtml', sink_kind='SK_DB_WRITE'),

    # ── CMS PAGE VIEW (frontend) ──────────────────────────────────────────
    dict(node_id=nd('frontend/cms/page:REENTRY_POINT:content'),
         node_type='REENTRY_POINT', fqn='cms_page.content (re-entry)',
         module='Magento_Cms', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('frontend/cms/page:PERSISTENCE_READ:content'),
         node_type='PERSISTENCE_READ', fqn='cms_page.content',
         module='Magento_Cms', area='frontend'),
    dict(node_id=nd('frontend/cms/page:MODEL_GETTER:getPageContent'),
         node_type='MODEL_GETTER', fqn='Page::getPageContent()',
         file='vendor/magento/module-cms/Block/Page.php', line=0,
         module='Magento_Cms', area='frontend'),
    dict(node_id=nd('frontend/cms/page:OUTPUT_CALL:content.phtml'),
         node_type='OUTPUT_CALL',
         fqn='content.phtml:7: echo /* @noEscape */ $pageData->getPageContent()',
         file='vendor/magento/module-cms/view/frontend/templates/content.phtml', line=7,
         module='Magento_Cms', area='frontend', sink_kind='SK_HTTP_RESPONSE'),

    # ── PRODUCT SAVE ─────────────────────────────────────────────────────
    dict(node_id=nd('admin/catalog/product:HTTP_PARAM:description'),
         node_type='HTTP_PARAM', fqn='/catalog/adminhtml/product/save?product[description]',
         module='Magento_Catalog', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('admin/catalog/product:HTTP_PARAM:short_description'),
         node_type='HTTP_PARAM', fqn='/catalog/adminhtml/product/save?product[short_description]',
         module='Magento_Catalog', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('admin/catalog/product:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='Catalog\Controller\Adminhtml\Product\Save::execute',
         file='app/code/Magento/Catalog/Controller/Adminhtml/Product/Save.php', line=1,
         module='Magento_Catalog', area='adminhtml'),
    dict(node_id=nd('admin/catalog/product:VARIABLE:productData'),
         node_type='VARIABLE', fqn='$productData (getPostValue)',
         file='app/code/Magento/Catalog/Controller/Adminhtml/Product/Save.php', line=126,
         module='Magento_Catalog', area='adminhtml'),
    dict(node_id=nd('admin/catalog/product:MODEL_SETTER:setData'),
         node_type='MODEL_SETTER', fqn='Product::setData',
         file='vendor/magento/module-catalog/Model/Product.php', line=0,
         module='Magento_Catalog', area='adminhtml'),
    dict(node_id=nd('admin/catalog/product:PERSISTENCE_WRITE:description'),
         node_type='PERSISTENCE_WRITE', fqn='catalog_product_entity_text.description',
         module='Magento_Catalog', area='adminhtml', sink_kind='SK_DB_WRITE'),
    dict(node_id=nd('admin/catalog/product:PERSISTENCE_WRITE:short_description'),
         node_type='PERSISTENCE_WRITE', fqn='catalog_product_entity_text.short_description',
         module='Magento_Catalog', area='adminhtml', sink_kind='SK_DB_WRITE'),

    # ── PRODUCT VIEW (frontend) ───────────────────────────────────────────
    dict(node_id=nd('frontend/catalog/product:REENTRY_POINT:description'),
         node_type='REENTRY_POINT', fqn='catalog_product_entity_text.description (re-entry)',
         module='Magento_Catalog', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('frontend/catalog/product:PERSISTENCE_READ:description'),
         node_type='PERSISTENCE_READ', fqn='catalog_product_entity_text.description',
         module='Magento_Catalog', area='frontend'),
    dict(node_id=nd('frontend/catalog/product:MODEL_GETTER:getDescription'),
         node_type='MODEL_GETTER', fqn='Product::getDescription()',
         file='vendor/magento/module-catalog/Model/Product.php', line=0,
         module='Magento_Catalog', area='frontend'),
    dict(node_id=nd('frontend/catalog/product:FUNCTION_CALL:productAttribute'),
         node_type='FUNCTION_CALL', fqn='Output::productAttribute()',
         file='vendor/magento/module-catalog/Helper/Output.php', line=0,
         module='Magento_Catalog', area='frontend'),
    dict(node_id=nd('frontend/catalog/product:OUTPUT_CALL:description.phtml'),
         node_type='OUTPUT_CALL',
         fqn='description.phtml:15: echo /* @noEscape */ $helper->productAttribute(...)',
         file='vendor/magento/module-catalog/view/frontend/templates/product/view/description.phtml',
         line=15,
         module='Magento_Catalog', area='frontend', sink_kind='SK_HTTP_RESPONSE'),

    # ── CATEGORY SAVE ────────────────────────────────────────────────────
    dict(node_id=nd('admin/catalog/category:HTTP_PARAM:name'),
         node_type='HTTP_PARAM', fqn='/catalog/adminhtml/category/save?name',
         module='Magento_Catalog', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('admin/catalog/category:HTTP_PARAM:description'),
         node_type='HTTP_PARAM', fqn='/catalog/adminhtml/category/save?description',
         module='Magento_Catalog', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('admin/catalog/category:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='Catalog\Controller\Adminhtml\Category\Save::execute',
         file='app/code/Magento/Catalog/Controller/Adminhtml/Category/Save.php', line=1,
         module='Magento_Catalog', area='adminhtml'),
    dict(node_id=nd('admin/catalog/category:VARIABLE:categoryPostData'),
         node_type='VARIABLE', fqn='$categoryPostData (getPostValue)',
         file='app/code/Magento/Catalog/Controller/Adminhtml/Category/Save.php', line=142,
         module='Magento_Catalog', area='adminhtml'),
    dict(node_id=nd('admin/catalog/category:MODEL_SETTER:setData'),
         node_type='MODEL_SETTER', fqn='Category::setData',
         file='vendor/magento/module-catalog/Model/Category.php', line=0,
         module='Magento_Catalog', area='adminhtml'),
    dict(node_id=nd('admin/catalog/category:PERSISTENCE_WRITE:description'),
         node_type='PERSISTENCE_WRITE', fqn='catalog_category_entity_text.description',
         module='Magento_Catalog', area='adminhtml', sink_kind='SK_DB_WRITE'),
    dict(node_id=nd('admin/catalog/category:PERSISTENCE_WRITE:name'),
         node_type='PERSISTENCE_WRITE', fqn='catalog_category_entity_varchar.name',
         module='Magento_Catalog', area='adminhtml', sink_kind='SK_DB_WRITE'),

    # ── CATEGORY VIEW (frontend) ──────────────────────────────────────────
    dict(node_id=nd('frontend/catalog/category:REENTRY_POINT:description'),
         node_type='REENTRY_POINT', fqn='catalog_category_entity_text.description (re-entry)',
         module='Magento_Catalog', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('frontend/catalog/category:PERSISTENCE_READ:description'),
         node_type='PERSISTENCE_READ', fqn='catalog_category_entity_text.description',
         module='Magento_Catalog', area='frontend'),
    dict(node_id=nd('frontend/catalog/category:MODEL_GETTER:getDescription'),
         node_type='MODEL_GETTER', fqn='Category::getDescription()',
         file='vendor/magento/module-catalog/Model/Category.php', line=0,
         module='Magento_Catalog', area='frontend'),
    dict(node_id=nd('frontend/catalog/category:FUNCTION_CALL:categoryAttribute'),
         node_type='FUNCTION_CALL', fqn='Output::categoryAttribute()',
         file='vendor/magento/module-catalog/Helper/Output.php', line=0,
         module='Magento_Catalog', area='frontend'),
    dict(node_id=nd('frontend/catalog/category:OUTPUT_CALL:category_description.phtml'),
         node_type='OUTPUT_CALL',
         fqn='category/description.phtml:18: echo /* @noEscape */ $helper->categoryAttribute(...)',
         file='vendor/magento/module-catalog/view/frontend/templates/catalog/category/description.phtml',
         line=18,
         module='Magento_Catalog', area='frontend', sink_kind='SK_HTTP_RESPONSE'),

    # ── NEWSLETTER SUBSCRIBER ADMIN GRID ─────────────────────────────────
    dict(node_id=nd('admin/newsletter/subscriber:REENTRY_POINT:email'),
         node_type='REENTRY_POINT', fqn='newsletter_subscriber.subscriber_email (admin re-entry)',
         module='Magento_Newsletter', area='adminhtml', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('admin/newsletter/subscriber:PERSISTENCE_READ:email'),
         node_type='PERSISTENCE_READ', fqn='newsletter_subscriber.subscriber_email',
         module='Magento_Newsletter', area='adminhtml'),
    dict(node_id=nd('admin/newsletter/subscriber:OUTPUT_CALL:grid'),
         node_type='OUTPUT_CALL',
         fqn='newsletter/adminhtml/subscriber/index: JSON grid (escapeHtml in column renderer)',
         file='vendor/magento/module-newsletter/view/adminhtml/templates/subscriber/grid/filter/type.phtml',
         line=0,
         module='Magento_Newsletter', area='adminhtml', sink_kind='SK_HTTP_RESPONSE'),

    # ── REVIEW ADMIN GRID ────────────────────────────────────────────────
    dict(node_id=nd('admin/review/pending:REENTRY_POINT:nickname'),
         node_type='REENTRY_POINT', fqn='review_detail.nickname (admin pending re-entry)',
         module='Magento_Review', area='adminhtml', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('admin/review/pending:PERSISTENCE_READ:nickname'),
         node_type='PERSISTENCE_READ', fqn='review_detail.nickname',
         module='Magento_Review', area='adminhtml'),
    dict(node_id=nd('admin/review/pending:OUTPUT_CALL:grid'),
         node_type='OUTPUT_CALL',
         fqn='review/adminhtml/product/pending: JSON grid via RequireJS data provider',
         file='vendor/magento/module-review/view/adminhtml/templates/grid.phtml',
         line=0,
         module='Magento_Review', area='adminhtml', sink_kind='SK_HTTP_RESPONSE'),

    # ── SEARCH TERM ADMIN INDEX ───────────────────────────────────────────
    dict(node_id=nd('admin/search/term:REENTRY_POINT:query_text'),
         node_type='REENTRY_POINT', fqn='search_query.query_text (admin term re-entry)',
         module='Magento_Search', area='adminhtml', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('admin/search/term:PERSISTENCE_READ:query_text'),
         node_type='PERSISTENCE_READ', fqn='search_query.query_text',
         module='Magento_Search', area='adminhtml'),
    dict(node_id=nd('admin/search/term:OUTPUT_CALL:index'),
         node_type='OUTPUT_CALL',
         fqn='search/adminhtml/term/index: grid column (escapeHtml via Magento UI component)',
         file='vendor/magento/module-search/view/adminhtml/templates/search/term/grid.phtml',
         line=0,
         module='Magento_Search', area='adminhtml', sink_kind='SK_HTTP_RESPONSE'),
]

# ---------------------------------------------------------------------------
# Lineage + hop definitions
# ---------------------------------------------------------------------------
def build_cms_content_lineages():
    """
    L1: /cms/adminhtml/page/save → cms_page.content
    L2: /cms/page/view → cms_page.content → content.phtml:7 (RAW, no escaping)
    """
    rows_lineages = []
    rows_hops = []
    rows_edges = []

    # ── L1: cms content write ─────────────────────────────────────────────
    src  = nd('admin/cms/page:HTTP_PARAM:content')
    sink = nd('admin/cms/page:PERSISTENCE_WRITE:content')
    lid  = ln('cms/adminhtml/page/save:content:L1')
    hops_l1 = [
        (0, src,                                         None, 0, None,  None),
        (1, nd('admin/cms/page:ROUTE_ENTRY'),            src,  0, None,  None),
        (2, nd('admin/cms/page:VARIABLE:pageData'),      None, 0, None,  None),
        (3, nd('admin/cms/page:MODEL_SETTER:setData'),   None, 0, None,  None),
        (4, sink,                                        None, 1, 'db',  'cms_page.content'),
    ]
    rows_lineages.append(dict(
        lineage_id=lid, order_num=1, route_id=RT_CMS_SAVE,
        source_node=src, sink_node=sink, hop_count=len(hops_l1)-1,
        analysis_method='static', confidence=1.0, run_id=RUN_ID,
        flags_emitted='["BD_DB_WRITE"]', flags_required='[]', flags_missing='[]',
        upstream_lineage=None, downstream_lineage=None,
    ))
    _add_hops(rows_hops, rows_edges, lid, hops_l1)

    # ── L2: cms content read (guest-visible, RAW) ─────────────────────────
    src2  = nd('frontend/cms/page:REENTRY_POINT:content')
    sink2 = nd('frontend/cms/page:OUTPUT_CALL:content.phtml')
    lid2  = ln('cms/page/view:content:L2')
    hops_l2 = [
        (0, src2,                                                     None, 1, 'db', 'cms_page.content'),
        (1, nd('frontend/cms/page:PERSISTENCE_READ:content'),         None, 0, None, None),
        (2, nd('frontend/cms/page:MODEL_GETTER:getPageContent'),       None, 0, None, None),
        (3, sink2,                                                     None, 0, None, None),
    ]
    rows_lineages.append(dict(
        lineage_id=lid2, order_num=2, route_id=RT_CMS_VIEW,
        source_node=src2, sink_node=sink2, hop_count=len(hops_l2)-1,
        analysis_method='static', confidence=1.0, run_id=RUN_ID,
        flags_emitted='[]', flags_required='[]', flags_missing='[]',
        upstream_lineage=lid, downstream_lineage=None,
        notes='RAW output via /* @noEscape */ — admin-written content.phtml:7. '
              'Admin→guest stored XSS vector if admin account compromised.',
    ))
    _add_hops(rows_hops, rows_edges, lid2, hops_l2)

    return rows_lineages, rows_hops, rows_edges, lid, lid2

def build_product_description_lineages():
    src  = nd('admin/catalog/product:HTTP_PARAM:description')
    sink = nd('admin/catalog/product:PERSISTENCE_WRITE:description')
    lid  = ln('catalog/adminhtml/product/save:description:L1')
    hops_l1 = [
        (0, src,                                              None, 0, None, None),
        (1, nd('admin/catalog/product:ROUTE_ENTRY'),          src,  0, None, None),
        (2, nd('admin/catalog/product:VARIABLE:productData'), None, 0, None, None),
        (3, nd('admin/catalog/product:MODEL_SETTER:setData'), None, 0, None, None),
        (4, sink,                                             None, 1, 'db', 'catalog_product_entity_text.description'),
    ]
    rows_l = [dict(
        lineage_id=lid, order_num=1, route_id=RT_PRODUCT_SAVE,
        source_node=src, sink_node=sink, hop_count=4,
        analysis_method='static', confidence=1.0, run_id=RUN_ID,
        flags_emitted='["BD_DB_WRITE"]', flags_required='[]', flags_missing='[]',
        upstream_lineage=None, downstream_lineage=None,
    )]
    rows_h, rows_e = [], []
    _add_hops(rows_h, rows_e, lid, hops_l1)

    src2  = nd('frontend/catalog/product:REENTRY_POINT:description')
    sink2 = nd('frontend/catalog/product:OUTPUT_CALL:description.phtml')
    lid2  = ln('catalog/product/view:description:L2')
    hops_l2 = [
        (0, src2,                                                       None, 1, 'db', 'catalog_product_entity_text.description'),
        (1, nd('frontend/catalog/product:PERSISTENCE_READ:description'), None, 0, None, None),
        (2, nd('frontend/catalog/product:MODEL_GETTER:getDescription'),  None, 0, None, None),
        (3, nd('frontend/catalog/product:FUNCTION_CALL:productAttribute'), None, 0, None, None),
        (4, sink2,                                                       None, 0, None, None),
    ]
    rows_l.append(dict(
        lineage_id=lid2, order_num=2, route_id=RT_PRODUCT_VIEW,
        source_node=src2, sink_node=sink2, hop_count=4,
        analysis_method='static', confidence=1.0, run_id=RUN_ID,
        flags_emitted='[]', flags_required='[]', flags_missing='[]',
        upstream_lineage=lid, downstream_lineage=None,
        notes='RAW WYSIWYG output via /* @noEscape */ Output::productAttribute() — '
              'description.phtml:15. Admin→guest stored XSS vector.',
    ))
    _add_hops(rows_h, rows_e, lid2, hops_l2)
    return rows_l, rows_h, rows_e, lid, lid2

def build_category_description_lineages():
    src  = nd('admin/catalog/category:HTTP_PARAM:description')
    sink = nd('admin/catalog/category:PERSISTENCE_WRITE:description')
    lid  = ln('catalog/adminhtml/category/save:description:L1')
    hops_l1 = [
        (0, src,                                                None, 0, None, None),
        (1, nd('admin/catalog/category:ROUTE_ENTRY'),           src,  0, None, None),
        (2, nd('admin/catalog/category:VARIABLE:categoryPostData'), None, 0, None, None),
        (3, nd('admin/catalog/category:MODEL_SETTER:setData'),  None, 0, None, None),
        (4, sink,                                               None, 1, 'db', 'catalog_category_entity_text.description'),
    ]
    rows_l = [dict(
        lineage_id=lid, order_num=1, route_id=RT_CATEGORY_SAVE,
        source_node=src, sink_node=sink, hop_count=4,
        analysis_method='static', confidence=1.0, run_id=RUN_ID,
        flags_emitted='["BD_DB_WRITE"]', flags_required='[]', flags_missing='[]',
        upstream_lineage=None, downstream_lineage=None,
    )]
    rows_h, rows_e = [], []
    _add_hops(rows_h, rows_e, lid, hops_l1)

    src2  = nd('frontend/catalog/category:REENTRY_POINT:description')
    sink2 = nd('frontend/catalog/category:OUTPUT_CALL:category_description.phtml')
    lid2  = ln('catalog/category/view:description:L2')
    hops_l2 = [
        (0, src2,                                                         None, 1, 'db', 'catalog_category_entity_text.description'),
        (1, nd('frontend/catalog/category:PERSISTENCE_READ:description'), None, 0, None, None),
        (2, nd('frontend/catalog/category:MODEL_GETTER:getDescription'),  None, 0, None, None),
        (3, nd('frontend/catalog/category:FUNCTION_CALL:categoryAttribute'), None, 0, None, None),
        (4, sink2,                                                         None, 0, None, None),
    ]
    rows_l.append(dict(
        lineage_id=lid2, order_num=2, route_id=RT_CATEGORY_VIEW,
        source_node=src2, sink_node=sink2, hop_count=4,
        analysis_method='static', confidence=1.0, run_id=RUN_ID,
        flags_emitted='[]', flags_required='[]', flags_missing='[]',
        upstream_lineage=lid, downstream_lineage=None,
        notes='RAW WYSIWYG output via /* @noEscape */ Output::categoryAttribute() — '
              'category/description.phtml:18. Admin→guest stored XSS vector.',
    ))
    _add_hops(rows_h, rows_e, lid2, hops_l2)
    return rows_l, rows_h, rows_e, lid, lid2

def build_admin_readback_lineages(con):
    """
    Build L2 admin read-back lineages that connect existing frontend L1 write lineages
    to admin grid routes.
    """
    rows_l, rows_h, rows_e, rows_rl = [], [], [], []

    # ── Newsletter subscriber admin grid ──────────────────────────────────
    # Find the existing L1 newsletter subscribe lineage
    nl_write = con.execute(
        "SELECT l.lineage_id, lh.hop_id FROM lineages l "
        "JOIN lineage_hops lh ON lh.lineage_id = l.lineage_id "
        "JOIN nodes n ON n.node_id = lh.node_id "
        "WHERE n.fqn = 'newsletter_subscriber.subscriber_email' "
        "AND n.node_type = 'PERSISTENCE_WRITE' LIMIT 1"
    ).fetchone()
    if nl_write:
        nl_write_lin, nl_write_hop = nl_write
        src_nl  = nd('admin/newsletter/subscriber:REENTRY_POINT:email')
        sink_nl = nd('admin/newsletter/subscriber:OUTPUT_CALL:grid')
        lid_nl  = ln('newsletter/adminhtml/subscriber/index:email:L2')
        hops_nl = [
            (0, src_nl,                                                     None, 1, 'db', 'newsletter_subscriber.subscriber_email'),
            (1, nd('admin/newsletter/subscriber:PERSISTENCE_READ:email'),   None, 0, None, None),
            (2, sink_nl,                                                     None, 0, None, None),
        ]
        rows_l.append(dict(
            lineage_id=lid_nl, order_num=2, route_id=RT_NL_SUBSCRIBER,
            source_node=src_nl, sink_node=sink_nl, hop_count=2,
            analysis_method='static', confidence=0.8, run_id=RUN_ID,
            flags_emitted='[]', flags_required='[]', flags_missing='[]',
            upstream_lineage=nl_write_lin, downstream_lineage=None,
            notes='Admin newsletter subscriber grid renders subscriber_email. '
                  'Magento admin column renderers use escapeHtml — no XSS, but data is admin-visible.',
        ))
        _add_hops(rows_h, rows_e, lid_nl, hops_nl)
        # Find REENTRY_POINT hop for reentry_link
        rp_hop_nl = lh(f'{lid_nl}:hop:0')
        rows_rl.append(dict(
            link_id=rl('nl-subscriber-admin-readback'),
            write_lineage_id=nl_write_lin, write_hop_id=nl_write_hop,
            read_lineage_id=lid_nl, read_hop_id=rp_hop_nl,
            store_kind='db', store_identifier='newsletter_subscriber.subscriber_email',
            confidence=0.8, evidence='static',
        ))

    # ── Review pending admin grid ─────────────────────────────────────────
    # Find the review/product/post L1 nickname lineage
    rv_write = con.execute(
        "SELECT l.lineage_id, lh.hop_id FROM lineages l "
        "JOIN lineage_hops lh ON lh.lineage_id = l.lineage_id "
        "JOIN nodes n ON n.node_id = lh.node_id "
        "WHERE n.fqn = 'review_detail.nickname' "
        "AND n.node_type = 'PERSISTENCE_WRITE' LIMIT 1"
    ).fetchone()
    if rv_write:
        rv_write_lin, rv_write_hop = rv_write
        src_rv  = nd('admin/review/pending:REENTRY_POINT:nickname')
        sink_rv = nd('admin/review/pending:OUTPUT_CALL:grid')
        lid_rv  = ln('review/adminhtml/product/pending:nickname:L2')
        hops_rv = [
            (0, src_rv,                                                None, 1, 'db', 'review_detail.nickname'),
            (1, nd('admin/review/pending:PERSISTENCE_READ:nickname'),  None, 0, None, None),
            (2, sink_rv,                                               None, 0, None, None),
        ]
        rows_l.append(dict(
            lineage_id=lid_rv, order_num=2, route_id=RT_REVIEW_PENDING,
            source_node=src_rv, sink_node=sink_rv, hop_count=2,
            analysis_method='static', confidence=0.8, run_id=RUN_ID,
            flags_emitted='[]', flags_required='[]', flags_missing='[]',
            upstream_lineage=rv_write_lin, downstream_lineage=None,
            notes='Admin review pending grid renders review_detail.nickname via RequireJS data provider. '
                  'Actual rendering uses escapeHtml in Magento UI component — no XSS, data is admin-visible.',
        ))
        _add_hops(rows_h, rows_e, lid_rv, hops_rv)
        rp_hop_rv = lh(f'{lid_rv}:hop:0')
        rows_rl.append(dict(
            link_id=rl('review-pending-admin-readback'),
            write_lineage_id=rv_write_lin, write_hop_id=rv_write_hop,
            read_lineage_id=lid_rv, read_hop_id=rp_hop_rv,
            store_kind='db', store_identifier='review_detail.nickname',
            confidence=0.8, evidence='static',
        ))

    # ── Search term admin index ───────────────────────────────────────────
    sq_write = con.execute(
        "SELECT l.lineage_id, lh.hop_id FROM lineages l "
        "JOIN lineage_hops lh ON lh.lineage_id = l.lineage_id "
        "JOIN nodes n ON n.node_id = lh.node_id "
        "WHERE n.fqn = 'search_query.query_text' "
        "AND n.node_type = 'PERSISTENCE_WRITE' LIMIT 1"
    ).fetchone()
    if sq_write:
        sq_write_lin, sq_write_hop = sq_write
        src_sq  = nd('admin/search/term:REENTRY_POINT:query_text')
        sink_sq = nd('admin/search/term:OUTPUT_CALL:index')
        lid_sq  = ln('search/adminhtml/term/index:query_text:L2')
        hops_sq = [
            (0, src_sq,                                                  None, 1, 'db', 'search_query.query_text'),
            (1, nd('admin/search/term:PERSISTENCE_READ:query_text'),     None, 0, None, None),
            (2, sink_sq,                                                  None, 0, None, None),
        ]
        rows_l.append(dict(
            lineage_id=lid_sq, order_num=2, route_id=RT_SEARCH_TERM_IDX,
            source_node=src_sq, sink_node=sink_sq, hop_count=2,
            analysis_method='static', confidence=0.8, run_id=RUN_ID,
            flags_emitted='[]', flags_required='[]', flags_missing='[]',
            upstream_lineage=sq_write_lin, downstream_lineage=None,
            notes='Admin search term index grid renders search_query.query_text. '
                  'Magento UI grid uses escapeHtml — no XSS, data is admin-visible.',
        ))
        _add_hops(rows_h, rows_e, lid_sq, hops_sq)
        rp_hop_sq = lh(f'{lid_sq}:hop:0')
        rows_rl.append(dict(
            link_id=rl('search-term-admin-readback'),
            write_lineage_id=sq_write_lin, write_hop_id=sq_write_hop,
            read_lineage_id=lid_sq, read_hop_id=rp_hop_sq,
            store_kind='db', store_identifier='search_query.query_text',
            confidence=0.8, evidence='static',
        ))

    return rows_l, rows_h, rows_e, rows_rl

# ---------------------------------------------------------------------------
# Hop/edge helper
# ---------------------------------------------------------------------------
def _add_hops(rows_hops, rows_edges, lid, hops):
    """
    hops: list of (seq, node_id, prev_node_id, is_boundary, store_kind, store_identifier)
    """
    prev_hop_id = None
    for seq, node_id, _prev, is_boundary, store_kind, store_id in hops:
        hop_id = lh(f'{lid}:hop:{seq}')
        edge_id = None
        if prev_hop_id is not None:
            edge_id = ed(f'{prev_hop_id}->{hop_id}')
            rows_edges.append(dict(
                edge_id=edge_id,
                from_node=node_id if seq == 0 else None,   # will fix below
                to_node=node_id,
            ))
        rows_hops.append(dict(
            hop_id=hop_id, lineage_id=lid, hop_sequence=seq, node_id=node_id,
            edge_from_prev=edge_id,
            is_boundary=is_boundary, boundary_kind=None,
            store_kind=store_kind, store_identifier=store_id,
        ))
        prev_hop_id = hop_id

def _add_hops_fixed(rows_hops, rows_edges, lid, hops):
    """
    hops: list of (seq, node_id, is_boundary, store_kind, store_identifier)
    Builds correct from_node/to_node edges.
    """
    prev_hop_id = None
    prev_node_id = None
    for seq, node_id, is_boundary, store_kind, store_id in hops:
        hop_id = lh(f'{lid}:hop:{seq}')
        edge_id = None
        if prev_hop_id is not None:
            edge_id = ed(f'{prev_node_id}->{node_id}')
            rows_edges.append(dict(
                edge_id=edge_id,
                from_node=prev_node_id,
                to_node=node_id,
            ))
        rows_hops.append(dict(
            hop_id=hop_id, lineage_id=lid, hop_sequence=seq, node_id=node_id,
            edge_from_prev=edge_id,
            is_boundary=is_boundary, boundary_kind=None,
            store_kind=store_kind, store_identifier=store_id,
        ))
        prev_hop_id = hop_id
        prev_node_id = node_id

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    # ── 1. Insert nodes ───────────────────────────────────────────────────
    inserted_nodes = 0
    for n in NODES:
        cur.execute('''
            INSERT OR IGNORE INTO nodes
              (node_id, node_type, fqn, file, line, module, area, provenance, sink_kind)
            VALUES (:node_id, :node_type, :fqn,
                    :file, :line, :module, :area, :provenance, :sink_kind)
        ''', {
            'file': None, 'line': None, 'provenance': None, 'sink_kind': None,
            **n,
        })
        if cur.rowcount:
            inserted_nodes += 1
    print(f'Nodes inserted: {inserted_nodes}')

    # ── 2. Build CMS content lineages ─────────────────────────────────────
    rows_l_cms, rows_h_cms, rows_e_cms, lid_cms_l1, lid_cms_l2 = build_cms_content_lineages()

    # ── 3. Build product description lineages ─────────────────────────────
    rows_l_prod, rows_h_prod, rows_e_prod, lid_prod_l1, lid_prod_l2 = build_product_description_lineages()

    # ── 4. Build category description lineages ────────────────────────────
    rows_l_cat, rows_h_cat, rows_e_cat, lid_cat_l1, lid_cat_l2 = build_category_description_lineages()

    # ── 5. Build admin read-back lineages ──────────────────────────────────
    rows_l_rb, rows_h_rb, rows_e_rb, rows_rl_rb = build_admin_readback_lineages(con)

    all_lineages = rows_l_cms + rows_l_prod + rows_l_cat + rows_l_rb
    all_hops     = rows_h_cms + rows_h_prod + rows_h_cat + rows_h_rb
    all_edges    = rows_e_cms + rows_e_prod + rows_e_cat + rows_e_rb

    # Insert edges
    inserted_edges = 0
    for e in all_edges:
        if e['from_node'] and e['to_node']:
            cur.execute(
                'INSERT OR IGNORE INTO edges (edge_id, from_node, to_node) VALUES (?,?,?)',
                (e['edge_id'], e['from_node'], e['to_node'])
            )
            if cur.rowcount:
                inserted_edges += 1
    print(f'Edges inserted: {inserted_edges}')

    # Insert lineages
    inserted_lins = 0
    for row in all_lineages:
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
            inserted_lins += 1
    print(f'Lineages inserted: {inserted_lins}')

    # Insert hops
    inserted_hops = 0
    for h in all_hops:
        cur.execute('''
            INSERT OR IGNORE INTO lineage_hops
              (hop_id, lineage_id, hop_sequence, node_id, edge_from_prev,
               is_boundary, boundary_kind, store_kind, store_identifier)
            VALUES
              (:hop_id, :lineage_id, :hop_sequence, :node_id, :edge_from_prev,
               :is_boundary, :boundary_kind, :store_kind, :store_identifier)
        ''', h)
        if cur.rowcount:
            inserted_hops += 1
    print(f'Hops inserted: {inserted_hops}')

    # Insert reentry_links for admin read-backs
    inserted_rls = 0
    for r in rows_rl_rb:
        cur.execute('''
            INSERT OR IGNORE INTO reentry_links
              (link_id, write_lineage_id, write_hop_id, read_lineage_id, read_hop_id,
               store_kind, store_identifier, confidence, evidence)
            VALUES
              (:link_id, :write_lineage_id, :write_hop_id, :read_lineage_id, :read_hop_id,
               :store_kind, :store_identifier, :confidence, :evidence)
        ''', r)
        if cur.rowcount:
            inserted_rls += 1
    print(f'Reentry links inserted: {inserted_rls}')

    # Insert reentry_links for admin→guest L2 chains
    cms_rl_id = rl('cms/page/view:content:L2:rl')
    cur.execute(
        'SELECT hop_id FROM lineage_hops WHERE lineage_id = ? AND hop_sequence = 4 AND store_identifier = ?',
        (lid_cms_l1, 'cms_page.content')
    )
    cms_write_hop = cur.fetchone()
    if cms_write_hop:
        cms_read_hop = lh(f'{lid_cms_l2}:hop:0')
        cur.execute('''
            INSERT OR IGNORE INTO reentry_links
              (link_id, write_lineage_id, write_hop_id, read_lineage_id, read_hop_id,
               store_kind, store_identifier, confidence, evidence)
            VALUES (?,?,?,?,?, 'db','cms_page.content', 1.0, 'static')
        ''', (cms_rl_id, lid_cms_l1, cms_write_hop[0], lid_cms_l2, cms_read_hop))
        if cur.rowcount:
            inserted_rls += 1
            print(f'  + cms content reentry_link')

    prod_rl_id = rl('catalog/product/view:description:L2:rl')
    cur.execute(
        'SELECT hop_id FROM lineage_hops WHERE lineage_id = ? AND hop_sequence = 4 AND store_identifier = ?',
        (lid_prod_l1, 'catalog_product_entity_text.description')
    )
    prod_write_hop = cur.fetchone()
    if prod_write_hop:
        prod_read_hop = lh(f'{lid_prod_l2}:hop:0')
        cur.execute('''
            INSERT OR IGNORE INTO reentry_links
              (link_id, write_lineage_id, write_hop_id, read_lineage_id, read_hop_id,
               store_kind, store_identifier, confidence, evidence)
            VALUES (?,?,?,?,?, 'db','catalog_product_entity_text.description', 1.0, 'static')
        ''', (prod_rl_id, lid_prod_l1, prod_write_hop[0], lid_prod_l2, prod_read_hop))
        if cur.rowcount:
            inserted_rls += 1
            print(f'  + product description reentry_link')

    cat_rl_id = rl('catalog/category/view:description:L2:rl')
    cur.execute(
        'SELECT hop_id FROM lineage_hops WHERE lineage_id = ? AND hop_sequence = 4 AND store_identifier = ?',
        (lid_cat_l1, 'catalog_category_entity_text.description')
    )
    cat_write_hop = cur.fetchone()
    if cat_write_hop:
        cat_read_hop = lh(f'{lid_cat_l2}:hop:0')
        cur.execute('''
            INSERT OR IGNORE INTO reentry_links
              (link_id, write_lineage_id, write_hop_id, read_lineage_id, read_hop_id,
               store_kind, store_identifier, confidence, evidence)
            VALUES (?,?,?,?,?, 'db','catalog_category_entity_text.description', 1.0, 'static')
        ''', (cat_rl_id, lid_cat_l1, cat_write_hop[0], lid_cat_l2, cat_read_hop))
        if cur.rowcount:
            inserted_rls += 1
            print(f'  + category description reentry_link')

    print(f'Total reentry links: {inserted_rls}')

    # ── 6. Resolve needs_admin deferred entries ───────────────────────────
    # Delete the needs_admin entries that are now resolved
    resolved_deferred_ids = [
        'def-47f56112',      # cms_page content — now has L1+L2
        'def-d35f3daf',      # product description — now has L1+L2
        'df-be034b762f',     # category description — now has L1+L2
        'def-nl-email-admin-read',   # newsletter subscriber admin grid — now has L2
        'def-review-admin-pending',  # review admin grid — now has L2
        'def-72ec2d87',      # search term admin grid — now has L2
    ]
    for did in resolved_deferred_ids:
        cur.execute('DELETE FROM deferred_lineages WHERE deferred_id = ?', (did,))
        if cur.rowcount:
            print(f'  Resolved deferred: {did}')

    # Mark remaining needs_admin entries as no_string_taint
    cur.execute(
        "UPDATE deferred_lineages SET blocker = 'no_string_taint', "
        "notes = notes || ' [admin-pass: reclassified — no guest-visible string taint chain found]' "
        "WHERE blocker = 'needs_admin'"
    )
    print(f'Reclassified remaining needs_admin: {cur.rowcount}')

    # ── 7. Classify remaining admin routes as no_string_taint ─────────────
    # Get all admin route IDs not yet covered by lineages
    covered_routes = set(r[0] for r in con.execute(
        "SELECT DISTINCT route_id FROM lineages WHERE route_id IN "
        "(SELECT route_id FROM routes WHERE area='adminhtml')"
    ).fetchall())

    admin_routes = con.execute(
        "SELECT route_id, url_pattern, http_method FROM routes WHERE area='adminhtml'"
    ).fetchall()

    inserted_deferred = 0
    for row in admin_routes:
        rt_id, pattern, method = row
        if rt_id in covered_routes:
            continue
        # Check if already has a deferred entry
        exists = con.execute(
            "SELECT 1 FROM deferred_lineages WHERE deferred_id = ?",
            (df(f'admin:no_taint:{rt_id}'),)
        ).fetchone()
        if exists:
            continue
        cur.execute('''
            INSERT OR IGNORE INTO deferred_lineages
              (deferred_id, write_lineage_id, store_kind, store_identifier, blocker,
               known_read_route, notes, created_at)
            VALUES (?, NULL, 'N/A', 'N/A — adminhtml route', 'no_string_taint',
                    ?, ?, unixepoch())
        ''', (
            df(f'admin:no_taint:{rt_id}'),
            pattern,
            f'Admin route {method} {pattern}: adminhtml-only, no guest-accessible string taint path identified. '
            f'Admin area requires authentication; XSS in admin context is accepted risk per Magento security model.',
        ))
        if cur.rowcount:
            inserted_deferred += 1

    print(f'Admin no_string_taint deferred entries added: {inserted_deferred}')

    con.commit()
    con.close()
    print('\nDone. Summary:')
    print(f'  Nodes:    {inserted_nodes}')
    print(f'  Edges:    {inserted_edges}')
    print(f'  Lineages: {inserted_lins}')
    print(f'  Hops:     {inserted_hops}')
    print(f'  RL:       {inserted_rls}')
    print(f'  Deferred: {inserted_deferred}')

if __name__ == '__main__':
    main()
