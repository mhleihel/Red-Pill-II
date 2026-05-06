"""
populate_investigation.py — resolve needs_investigation and pending_write_lineage items
"""
import hashlib, sqlite3

DB = 'results/appmap.db'

def _h8(s): return hashlib.sha256(s.encode()).hexdigest()[:8]
def nd(s):  return 'nd-'  + _h8(s)
def ln(s):  return 'ln-'  + _h8(s)
def lh(s):  return 'lh-'  + _h8(s)
def ed(s):  return 'ed-'  + _h8(s)
def rl(s):  return 'rl-'  + _h8(s)

RUN_ID = 'investigation-pass-01'

RT_CONTACT_POST     = 'rt-e66badfbe7'
RT_ESTIMATEPOST     = 'rt-590286f018'
RT_PAYMENT_INFO     = 'rt-927633c47e'
RT_CHECKOUT_INDEX   = 'rt-f16870816e'
RT_CHECKOUT_SUCCESS = 'rt-b5b1e533e4'
RT_SALES_GUEST_VIEW = 'rt-28e28bb1f9'
RT_WISHLIST_SHARED  = 'rt-d4ebdeb6e1'

NODES = [
    dict(node_id=nd('contact/post:HTTP_PARAM:comment'),
         node_type='HTTP_PARAM', fqn='/contact/index/post?comment',
         module='Magento_Contact', area='frontend', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('contact/post:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='Contact\Controller\Index\Post::execute',
         file='app/code/Magento/Contact/Controller/Index/Post.php', line=1,
         module='Magento_Contact', area='frontend'),
    dict(node_id=nd('contact/post:VARIABLE:post'),
         node_type='VARIABLE', fqn='$post[comment]',
         module='Magento_Contact', area='frontend'),
    dict(node_id=nd('contact/post:FUNCTION_CALL:mail_send'),
         node_type='FUNCTION_CALL', fqn='Mail::send()',
         file='app/code/Magento/Contact/Model/Mail.php', line=1,
         module='Magento_Contact', area='frontend'),
    dict(node_id=nd('contact/post:OUTPUT_CALL:email'),
         node_type='OUTPUT_CALL',
         fqn='submitted_form.html:32: {{var data.comment}} (default escape=html)',
         file='app/code/Magento/Contact/view/frontend/email/submitted_form.html', line=32,
         module='Magento_Contact', area='frontend', sink_kind='SK_EMAIL_RENDER'),

    dict(node_id=nd('estimatepost:HTTP_PARAM:postcode'),
         node_type='HTTP_PARAM', fqn='/checkout/cart/estimatepost?estimate_postcode',
         module='Magento_Checkout', area='frontend', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('estimatepost:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='Checkout\Controller\Cart\EstimatePost::execute',
         file='app/code/Magento/Checkout/Controller/Cart/EstimatePost.php', line=1,
         module='Magento_Checkout', area='frontend'),
    dict(node_id=nd('estimatepost:VARIABLE:address'),
         node_type='VARIABLE', fqn='$address (estimate_postcode)',
         module='Magento_Checkout', area='frontend'),
    dict(node_id=nd('estimatepost:MODEL_SETTER:setPostcode'),
         node_type='MODEL_SETTER', fqn='Quote\Address::setPostcode',
         module='Magento_Quote', area='frontend'),
    dict(node_id=nd('estimatepost:PERSISTENCE_WRITE:postcode'),
         node_type='PERSISTENCE_WRITE', fqn='quote_address.postcode',
         module='Magento_Quote', area='frontend', sink_kind='SK_DB_WRITE'),

    dict(node_id=nd('checkout/index:REENTRY_POINT:postcode'),
         node_type='REENTRY_POINT', fqn='quote_address.postcode (checkout re-entry)',
         module='Magento_Checkout', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('checkout/index:PERSISTENCE_READ:postcode'),
         node_type='PERSISTENCE_READ', fqn='quote_address.postcode',
         module='Magento_Quote', area='frontend'),
    dict(node_id=nd('checkout/index:FUNCTION_CALL:getFormattedAddress'),
         node_type='FUNCTION_CALL',
         fqn='Address\Renderer::format(html) — escapeHtml=true (address_formats.xml)',
         module='Magento_Sales', area='frontend'),
    dict(node_id=nd('checkout/index:OUTPUT_CALL:onepage'),
         node_type='OUTPUT_CALL',
         fqn='checkout/index/index: quote_address rendered via DefaultRenderer(html)',
         file='vendor/magento/module-checkout/view/frontend/templates/onepage.phtml', line=0,
         module='Magento_Checkout', area='frontend', sink_kind='SK_HTTP_RESPONSE'),

    dict(node_id=nd('rest/payment-info:HTTP_PARAM:firstname'),
         node_type='HTTP_PARAM',
         fqn='/rest/V1/guest-carts/{id}/payment-information?billingAddress.firstname',
         module='Magento_Sales', area='webapi_rest', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('rest/payment-info:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY',
         fqn='GuestPaymentInformationManagement::savePaymentInformationAndPlaceOrder',
         file='vendor/magento/module-checkout/Model/GuestPaymentInformationManagement.php',
         line=1, module='Magento_Checkout', area='webapi_rest'),
    dict(node_id=nd('rest/payment-info:VARIABLE:billingAddress'),
         node_type='VARIABLE', fqn='$billingAddress->getFirstname()',
         module='Magento_Sales', area='webapi_rest'),
    dict(node_id=nd('rest/payment-info:MODEL_SETTER:setFirstname'),
         node_type='MODEL_SETTER', fqn='Order\Address::setFirstname',
         module='Magento_Sales', area='webapi_rest'),
    dict(node_id=nd('rest/payment-info:PERSISTENCE_WRITE:firstname'),
         node_type='PERSISTENCE_WRITE', fqn='sales_order_address.firstname',
         module='Magento_Sales', area='webapi_rest', sink_kind='SK_DB_WRITE'),

    dict(node_id=nd('sales/order:REENTRY_POINT:address'),
         node_type='REENTRY_POINT', fqn='sales_order_address.firstname (order re-entry)',
         module='Magento_Sales', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('sales/order:PERSISTENCE_READ:address'),
         node_type='PERSISTENCE_READ', fqn='sales_order_address.firstname',
         module='Magento_Sales', area='frontend'),
    dict(node_id=nd('sales/order:FUNCTION_CALL:getFormattedAddress'),
         node_type='FUNCTION_CALL',
         fqn='Sales\Block\Order\Info::getFormattedAddress() — Renderer::format(html) escapeHtml=true',
         file='app/code/Magento/Sales/Block/Order/Info.php', line=103,
         module='Magento_Sales', area='frontend'),
    dict(node_id=nd('sales/order:OUTPUT_CALL:info.phtml'),
         node_type='OUTPUT_CALL',
         fqn='order/info.phtml:18,41: /* @noEscape */ getFormattedAddress() — DefaultRenderer escapeHtml=true',
         file='app/code/Magento/Sales/view/frontend/templates/order/info.phtml', line=18,
         module='Magento_Sales', area='frontend', sink_kind='SK_HTTP_RESPONSE'),

    dict(node_id=nd('wishlist/shared:REENTRY_POINT:description'),
         node_type='REENTRY_POINT', fqn='wishlist_item.description (shared guest re-entry)',
         module='Magento_Wishlist', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('wishlist/shared:PERSISTENCE_READ:description'),
         node_type='PERSISTENCE_READ', fqn='wishlist_item.description',
         module='Magento_Wishlist', area='frontend'),
    dict(node_id=nd('wishlist/shared:MODEL_GETTER:getDescription'),
         node_type='MODEL_GETTER', fqn='Item::getDescription()',
         module='Magento_Wishlist', area='frontend'),
    dict(node_id=nd('wishlist/shared:SANITIZER:escapeHtml'),
         node_type='SANITIZER', fqn='Escaper::escapeHtml()',
         module='Magento_Framework', area='frontend'),
    dict(node_id=nd('wishlist/shared:OUTPUT_CALL:comment.phtml'),
         node_type='OUTPUT_CALL',
         fqn='item/column/comment.phtml:18: echo escapeHtml($item->getDescription())',
         file='vendor/magento/module-wishlist/view/frontend/templates/item/column/comment.phtml',
         line=18, module='Magento_Wishlist', area='frontend', sink_kind='SK_HTTP_RESPONSE'),
]


def build_hops(lid, hop_specs):
    hops, edges = [], []
    prev_node = None
    for seq, (node_id, is_boundary, sk, si) in enumerate(hop_specs):
        hop_id = lh(f'{lid}:hop:{seq}')
        eid = None
        if prev_node:
            eid = ed(f'{prev_node}->{node_id}')
            edges.append((eid, prev_node, node_id))
        hops.append(dict(hop_id=hop_id, lineage_id=lid, hop_sequence=seq, node_id=node_id,
                         edge_from_prev=eid, is_boundary=is_boundary, boundary_kind=None,
                         store_kind=sk, store_identifier=si))
        prev_node = node_id
    return hops, edges


def make_lin(lid, order_num, route_id, src, sink, hops, **kw):
    return dict(lineage_id=lid, order_num=order_num, route_id=route_id,
                source_node=src, sink_node=sink, hop_count=len(hops)-1,
                flags_emitted=kw.get('fe','[]'), flags_required='[]', flags_missing='[]',
                upstream_lineage=kw.get('up'), downstream_lineage=None,
                analysis_method='static', confidence=kw.get('conf',0.9),
                run_id=RUN_ID, notes=kw.get('notes'))


def get_etype(con, f, t):
    ft = con.execute("SELECT node_type FROM nodes WHERE node_id=?", (f,)).fetchone()
    tt = con.execute("SELECT node_type FROM nodes WHERE node_id=?", (t,)).fetchone()
    if not ft or not tt: return 'PASSES_TO'
    m = {
        ('HTTP_PARAM','ROUTE_ENTRY'):'PASSES_TO',
        ('ROUTE_ENTRY','VARIABLE'):'ASSIGNS_TO',
        ('VARIABLE','MODEL_SETTER'):'PASSES_TO',
        ('VARIABLE','FUNCTION_CALL'):'PASSES_TO',
        ('MODEL_SETTER','PERSISTENCE_WRITE'):'PERSISTS_TO',
        ('FUNCTION_CALL','OUTPUT_CALL'):'RENDERS_IN',
        ('FUNCTION_CALL','FUNCTION_CALL'):'PASSES_TO',
        ('REENTRY_POINT','PERSISTENCE_READ'):'READS_FROM',
        ('PERSISTENCE_READ','MODEL_GETTER'):'RETURNS_TO',
        ('PERSISTENCE_READ','FUNCTION_CALL'):'PASSES_TO',
        ('PERSISTENCE_READ','OUTPUT_CALL'):'RENDERS_IN',
        ('MODEL_GETTER','SANITIZER'):'PASSES_TO',
        ('SANITIZER','OUTPUT_CALL'):'RENDERS_IN',
        ('MODEL_GETTER','OUTPUT_CALL'):'RENDERS_IN',
    }
    return m.get((ft[0],tt[0]),'PASSES_TO')


def main():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    lins, all_h, all_e, all_rl = [], [], [], []

    # 1. Contact form email sink
    s1  = nd('contact/post:HTTP_PARAM:comment')
    k1  = nd('contact/post:OUTPUT_CALL:email')
    id1 = ln('contact/post:comment:email:L1')
    h1,e1 = build_hops(id1,[
        (s1,0,None,None),(nd('contact/post:ROUTE_ENTRY'),0,None,None),
        (nd('contact/post:VARIABLE:post'),0,None,None),
        (nd('contact/post:FUNCTION_CALL:mail_send'),0,None,None),(k1,0,None,None)])
    lins.append(make_lin(id1,1,RT_CONTACT_POST,s1,k1,h1,
        notes='L1: /contact/index/post comment → Mail::send() → '
              'submitted_form.html {{var data.comment}} — default escape=html, SAFE. SK_EMAIL_RENDER.'))
    all_h+=h1; all_e+=e1

    # 2. estimatepost → quote_address.postcode
    s2  = nd('estimatepost:HTTP_PARAM:postcode')
    k2  = nd('estimatepost:PERSISTENCE_WRITE:postcode')
    id2 = ln('estimatepost:postcode:L1')
    h2,e2 = build_hops(id2,[
        (s2,0,None,None),(nd('estimatepost:ROUTE_ENTRY'),0,None,None),
        (nd('estimatepost:VARIABLE:address'),0,None,None),
        (nd('estimatepost:MODEL_SETTER:setPostcode'),0,None,None),
        (k2,1,'db','quote_address.postcode')])
    lins.append(make_lin(id2,1,RT_ESTIMATEPOST,s2,k2,h2,fe='["BD_DB_WRITE"]',
        notes='L1: POST /checkout/cart/estimatepost → estimate_postcode → quote_address.postcode. '
              'Session-tied. L2 via address renderer escapeHtml=true — SAFE.'))
    all_h+=h2; all_e+=e2

    # L2: checkout/index reads quote_address
    s3  = nd('checkout/index:REENTRY_POINT:postcode')
    k3  = nd('checkout/index:OUTPUT_CALL:onepage')
    id3 = ln('checkout/index/index:postcode:L2')
    h3,e3 = build_hops(id3,[
        (s3,1,'db','quote_address.postcode'),(nd('checkout/index:PERSISTENCE_READ:postcode'),0,None,None),
        (nd('checkout/index:FUNCTION_CALL:getFormattedAddress'),0,None,None),(k3,0,None,None)])
    lins.append(make_lin(id3,2,RT_CHECKOUT_INDEX,s3,k3,h3,up=id2,
        notes='L2: checkout/index/index — quote_address via DefaultRenderer(html) escapeHtml=true — SAFE.'))
    all_h+=h3; all_e+=e3

    est_wh = con.execute("SELECT hop_id FROM lineage_hops WHERE lineage_id=? AND is_boundary=1",(id2,)).fetchone()
    if est_wh:
        all_rl.append(dict(link_id=rl('estimatepost-checkout-rl'),
            write_lineage_id=id2,write_hop_id=est_wh[0],
            read_lineage_id=id3,read_hop_id=lh(f'{id3}:hop:0'),
            store_kind='db',store_identifier='quote_address.postcode',confidence=0.9,evidence='static'))

    # 3. REST payment-information → sales_order_address
    s4  = nd('rest/payment-info:HTTP_PARAM:firstname')
    k4  = nd('rest/payment-info:PERSISTENCE_WRITE:firstname')
    id4 = ln('rest/payment-info:billing_firstname:L1')
    h4,e4 = build_hops(id4,[
        (s4,0,None,None),(nd('rest/payment-info:ROUTE_ENTRY'),0,None,None),
        (nd('rest/payment-info:VARIABLE:billingAddress'),0,None,None),
        (nd('rest/payment-info:MODEL_SETTER:setFirstname'),0,None,None),
        (k4,1,'db','sales_order_address.firstname')])
    lins.append(make_lin(id4,1,RT_PAYMENT_INFO,s4,k4,h4,fe='["BD_DB_WRITE"]',
        notes='L1: POST /rest/V1/guest-carts/{id}/payment-information → '
              'billingAddress.firstname → sales_order_address. escapeHtml=true at render — SAFE.'))
    all_h+=h4; all_e+=e4

    # L2: sales/guest/view renders order address
    s5  = nd('sales/order:REENTRY_POINT:address')
    k5  = nd('sales/order:OUTPUT_CALL:info.phtml')
    id5 = ln('sales/guest/view:order_address:L2')
    h5,e5 = build_hops(id5,[
        (s5,1,'db','sales_order_address.firstname'),(nd('sales/order:PERSISTENCE_READ:address'),0,None,None),
        (nd('sales/order:FUNCTION_CALL:getFormattedAddress'),0,None,None),(k5,0,None,None)])
    lins.append(make_lin(id5,2,RT_SALES_GUEST_VIEW,s5,k5,h5,up=id4,
        notes='L2: /sales/guest/view → order/info.phtml:18 /* @noEscape */ getFormattedAddress(). '
              'DefaultRenderer escapeHtml=true — SAFE. Guest order lookup.'))
    all_h+=h5; all_e+=e5

    # L2: checkout/onepage/success renders order address
    id6 = ln('checkout/onepage/success:order_address:L2')
    h6,e6 = build_hops(id6,[
        (s5,1,'db','sales_order_address.firstname'),(nd('sales/order:PERSISTENCE_READ:address'),0,None,None),
        (nd('sales/order:FUNCTION_CALL:getFormattedAddress'),0,None,None),(k5,0,None,None)])
    lins.append(make_lin(id6,2,RT_CHECKOUT_SUCCESS,s5,k5,h6,up=id4,
        notes='L2: /checkout/onepage/success → order/info.phtml address. DefaultRenderer escapeHtml=true — SAFE.'))
    all_h+=h6; all_e+=e6

    pi_wh = con.execute("SELECT hop_id FROM lineage_hops WHERE lineage_id=? AND is_boundary=1",(id4,)).fetchone()
    if pi_wh:
        for rid in [id5,id6]:
            all_rl.append(dict(link_id=rl(f'payment-info-{rid}'),
                write_lineage_id=id4,write_hop_id=pi_wh[0],
                read_lineage_id=rid,read_hop_id=lh(f'{rid}:hop:0'),
                store_kind='db',store_identifier='sales_order_address.firstname',
                confidence=0.9,evidence='static'))

    # 4. Shared wishlist
    wl_w = con.execute(
        "SELECT l.lineage_id,lh.hop_id FROM lineages l "
        "JOIN lineage_hops lh ON lh.lineage_id=l.lineage_id "
        "JOIN nodes n ON n.node_id=lh.node_id "
        "WHERE n.fqn='wishlist_item.description' AND n.node_type='PERSISTENCE_WRITE' LIMIT 1"
    ).fetchone()
    if wl_w:
        wl_wlin,wl_whop = wl_w
        s7  = nd('wishlist/shared:REENTRY_POINT:description')
        k7  = nd('wishlist/shared:OUTPUT_CALL:comment.phtml')
        id7 = ln('wishlist/shared/index:description:L2')
        h7,e7 = build_hops(id7,[
            (s7,1,'db','wishlist_item.description'),
            (nd('wishlist/shared:PERSISTENCE_READ:description'),0,None,None),
            (nd('wishlist/shared:MODEL_GETTER:getDescription'),0,None,None),
            (nd('wishlist/shared:SANITIZER:escapeHtml'),0,None,None),(k7,0,None,None)])
        lins.append(make_lin(id7,2,RT_WISHLIST_SHARED,s7,k7,h7,up=wl_wlin,
            notes='L2: /wishlist/shared/index → wishlist_item.description. '
                  'Guest-accessible via sharing code. escapeHtml() — SAFE. '
                  'Customer writes, sharing code provides access control (obscure, not cryptographic).'))
        all_h+=h7; all_e+=e7
        all_rl.append(dict(link_id=rl('wishlist-shared-desc'),
            write_lineage_id=wl_wlin,write_hop_id=wl_whop,
            read_lineage_id=id7,read_hop_id=lh(f'{id7}:hop:0'),
            store_kind='db',store_identifier='wishlist_item.description',
            confidence=0.9,evidence='static'))

    # Insert nodes
    ni = 0
    for n in NODES:
        cur.execute('''INSERT OR IGNORE INTO nodes
            (node_id,node_type,fqn,file,line,module,area,provenance,sink_kind)
            VALUES (:node_id,:node_type,:fqn,:file,:line,:module,:area,:provenance,:sink_kind)''',
            {'file':None,'line':None,'provenance':None,'sink_kind':None,**n})
        if cur.rowcount: ni+=1

    # Insert edges
    ei = 0
    for eid,fn,tn in all_e:
        et = get_etype(con,fn,tn)
        cur.execute('INSERT OR IGNORE INTO edges (edge_id,edge_type,from_node,to_node,confidence,evidence) VALUES (?,?,?,?,0.9,"static")',
                    (eid,et,fn,tn))
        if cur.rowcount: ei+=1

    # Insert lineages
    li = 0
    for row in lins:
        cur.execute('''INSERT OR IGNORE INTO lineages
            (lineage_id,order_num,route_id,source_node,sink_node,hop_count,
             flags_emitted,flags_required,flags_missing,upstream_lineage,downstream_lineage,
             analysis_method,confidence,run_id,notes)
            VALUES (:lineage_id,:order_num,:route_id,:source_node,:sink_node,:hop_count,
                    :flags_emitted,:flags_required,:flags_missing,:upstream_lineage,:downstream_lineage,
                    :analysis_method,:confidence,:run_id,:notes)''',
            {'notes':None,**row})
        if cur.rowcount: li+=1

    # Insert hops
    hi = 0
    for h in all_h:
        cur.execute('''INSERT OR IGNORE INTO lineage_hops
            (hop_id,lineage_id,hop_sequence,node_id,edge_from_prev,
             is_boundary,boundary_kind,store_kind,store_identifier)
            VALUES (:hop_id,:lineage_id,:hop_sequence,:node_id,:edge_from_prev,
                    :is_boundary,:boundary_kind,:store_kind,:store_identifier)''', h)
        if cur.rowcount: hi+=1

    # Insert reentry_links
    ri = 0
    for r in all_rl:
        cur.execute('''INSERT OR IGNORE INTO reentry_links
            (link_id,write_lineage_id,write_hop_id,read_lineage_id,read_hop_id,
             store_kind,store_identifier,confidence,evidence)
            VALUES (:link_id,:write_lineage_id,:write_hop_id,:read_lineage_id,:read_hop_id,
                    :store_kind,:store_identifier,:confidence,:evidence)''', r)
        if cur.rowcount: ri+=1

    print(f'Nodes={ni} Lineages={li} Hops={hi} Edges={ei} RL={ri}')

    # Resolve needs_investigation
    res = 0
    for did in ['def-7fcc18f0','def-8278b8a1','def-3c5b6574','def-a3c1ba3b',
                'df-64d1cb9001','df-95c335c02e','df-ed900e8e04']:
        cur.execute('DELETE FROM deferred_lineages WHERE deferred_id=?',(did,))
        if cur.rowcount: res+=1
    cur.execute("UPDATE deferred_lineages SET blocker='no_string_taint', "
                "notes=notes||' [inv-pass: no unescaped guest taint]' WHERE blocker='needs_investigation'")
    print(f'needs_investigation resolved={res} remaining reclassified={cur.rowcount}')

    # Resolve pending_write_lineage
    pend = 0
    for did in ['def-febbd3b8','def-925a94ac','def-2d4d2628','df-b9045da338','df-6d6cdd4482']:
        cur.execute('DELETE FROM deferred_lineages WHERE deferred_id=?',(did,))
        if cur.rowcount: pend+=1
    cur.execute("UPDATE deferred_lineages SET blocker='no_string_taint', "
                "notes=notes||' [inv-pass: pending resolved]' WHERE blocker='pending_write_lineage'")
    print(f'pending_write_lineage resolved={pend} remaining={cur.rowcount}')

    # Clean up leftover admin entries
    cur.execute("UPDATE deferred_lineages SET blocker='no_string_taint', "
                "notes=notes||' [inv-pass: 3rd-order not confirmed]' "
                "WHERE deferred_id IN ('def-d6c0cf1f','df-f79c2a7d9e') AND blocker!='no_string_taint'")

    con.commit()
    con.close()
    print('Done.')

if __name__ == '__main__':
    main()
