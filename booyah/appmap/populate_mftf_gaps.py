"""
populate_mftf_gaps.py — fills the 9 MFTF ActionGroup flows not yet in the appmap.

New L1 lineages:
  POST /V1/guest-carts/{id}/gift-message  → gift_message.{sender, recipient, message}
  GET  /cms/adminhtml/block/save           → cms_block.content
  GET  /customer/adminhtml/index/save      → customer_entity.{firstname, lastname, email}  (admin path)
  GET  /newsletter/adminhtml/template/save → newsletter_template.{template_text, template_subject}
  GET  /sales/adminhtml/order/addcomment   → sales_order_status_history.comment
  POST /wishlist/index/send                → SK_EMAIL_RENDER (email only, no DB write)
  GET  /checkout/adminhtml/agreement/save  → checkout_agreement.content
  GET  /adminhtml/adminhtml/system/variable/save → variable.html_value
  GET  /search/adminhtml/term/save         → search_query.{query_text, redirect_url}

New L2 lineages:
  gift_message.message   → /checkout/cart/index gift options inline (escapeHtml)
  gift_message.sender    → /checkout/cart/index inline (getEscaped — attr context)
  gift_message.recipient → /checkout/cart/index inline (getEscaped — attr context)
  cms_block.content      → /cms/block/view (raw HTML via BlockFilter — no escaping)
  sales_order_status_history.comment → /sales/order/view (escapeHtml with allowed tags b/br/strong/i/u/a)
  sales_order_status_history.comment → /sales/adminhtml/order/view (same partial escape)
  checkout_agreement.content → /checkout/index/index (raw HTML rendered, admin-trusted)
  variable.html_value    → any CMS page via {{customVar code=...}} (raw HTML — no escape)
  newsletter_template.template_text → email send (SK_EMAIL_RENDER)
"""

import hashlib, sqlite3

DB = 'results/appmap.db'

def _h8(s): return hashlib.sha256(s.encode()).hexdigest()[:8]
def nd(s):  return 'nd-'  + _h8(s)
def ln(s):  return 'ln-'  + _h8(s)
def lh(s):  return 'lh-'  + _h8(s)
def ed(s):  return 'ed-'  + _h8(s)
def rl(s):  return 'rl-'  + _h8(s)

RUN_ID = 'mftf-gaps-01'

# ── Existing route IDs ────────────────────────────────────────────────────────
RT_CMS_BLOCK_SAVE         = 'rt-aecc10969f'   # GET /cms/adminhtml/block/save
RT_ADMIN_CUST_SAVE        = 'rt-d2c5810418'   # GET /customer/adminhtml/index/save
RT_NL_TEMPLATE_SAVE       = 'rt-579d697597'   # GET /newsletter/adminhtml/template/save
RT_ORDER_ADDCOMMENT       = 'rt-013045b83f'   # GET /sales/adminhtml/order/addcomment
RT_WISHLIST_SEND          = 'rt-0e19b84cc9'   # POST /wishlist/index/send
RT_AGREEMENT_SAVE         = 'rt-dd99793c67'   # GET /checkout/adminhtml/agreement/save
RT_VARIABLE_SAVE          = 'rt-f91cce7892'   # GET /adminhtml/adminhtml/system/variable/save
RT_SEARCH_TERM_SAVE       = 'rt-08c92df5e8'   # GET /search/adminhtml/term/save
RT_CHECKOUT_CART          = 'rt-792421a312'   # GET /checkout/cart/index
RT_ORDER_VIEW_FE          = 'rt-0839d4119b'   # GET /sales/order/view/order_id/{id}
RT_CHECKOUT_INDEX         = 'rt-f16870816e'   # GET /checkout/index/index
RT_CMS_PAGE_VIEW          = 'rt-07b9b4b7eb'   # GET /cms/page/view  (may need insert)

# ── Routes to insert if missing ───────────────────────────────────────────────
NEW_ROUTES = [
    dict(route_id='rt-gift-guest-rest',
         http_method='POST',
         url_pattern='/rest/V1/guest-carts/{id}/gift-message',
         area='webapi_rest',
         module='Magento_GiftMessage',
         controller='Magento\\GiftMessage\\Api\\GuestCartRepositoryInterface',
         action='save',
         notes='REST: guest sets cart-level gift message'),
]

# ── Node definitions ──────────────────────────────────────────────────────────
NODES = [

    # ── Gift message — L1 sources ─────────────────────────────────────────────
    dict(node_id=nd('giftmessage:HTTP_PARAM:sender'),
         node_type='HTTP_PARAM', fqn='/rest/V1/guest-carts/{id}/gift-message?sender',
         module='Magento_GiftMessage', area='webapi_rest', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('giftmessage:HTTP_PARAM:recipient'),
         node_type='HTTP_PARAM', fqn='/rest/V1/guest-carts/{id}/gift-message?recipient',
         module='Magento_GiftMessage', area='webapi_rest', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('giftmessage:HTTP_PARAM:message'),
         node_type='HTTP_PARAM', fqn='/rest/V1/guest-carts/{id}/gift-message?message',
         module='Magento_GiftMessage', area='webapi_rest', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('giftmessage:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY',
         fqn='GiftMessage\\Api\\GuestCartRepositoryInterface::save',
         file='app/code/Magento/GiftMessage/Model/GuestCartRepository.php', line=1,
         module='Magento_GiftMessage', area='webapi_rest'),
    dict(node_id=nd('giftmessage:MODEL_SETTER:setMessage'),
         node_type='MODEL_SETTER', fqn='Message::setMessage',
         module='Magento_GiftMessage', area='webapi_rest'),
    dict(node_id=nd('giftmessage:PERSISTENCE_WRITE:sender'),
         node_type='PERSISTENCE_WRITE', fqn='gift_message.sender',
         module='Magento_GiftMessage', area='webapi_rest', sink_kind='SK_DB_WRITE'),
    dict(node_id=nd('giftmessage:PERSISTENCE_WRITE:recipient'),
         node_type='PERSISTENCE_WRITE', fqn='gift_message.recipient',
         module='Magento_GiftMessage', area='webapi_rest', sink_kind='SK_DB_WRITE'),
    dict(node_id=nd('giftmessage:PERSISTENCE_WRITE:message'),
         node_type='PERSISTENCE_WRITE', fqn='gift_message.message',
         module='Magento_GiftMessage', area='webapi_rest', sink_kind='SK_DB_WRITE'),

    # ── Gift message — L2 render nodes ────────────────────────────────────────
    dict(node_id=nd('gift_message.message:REENTRY_POINT'),
         node_type='REENTRY_POINT', fqn='gift_message.message (cart re-entry)',
         module='Magento_GiftMessage', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('gift_message.message:PERSISTENCE_READ'),
         node_type='PERSISTENCE_READ', fqn='gift_message.message',
         module='Magento_GiftMessage', area='frontend'),
    dict(node_id=nd('gift_message.message:SANITIZER:escapeHtml'),
         node_type='SANITIZER', fqn='Escaper::escapeHtml()',
         module='Magento_Framework', area='frontend'),
    dict(node_id=nd('gift_message.message:OUTPUT_CALL:inline.phtml'),
         node_type='OUTPUT_CALL',
         fqn='GiftMessage/inline.phtml: $escaper->escapeHtml(getMessage()->getMessage())',
         file='app/code/Magento/GiftMessage/view/frontend/templates/inline.phtml', line=0,
         module='Magento_GiftMessage', area='frontend', sink_kind='SK_HTTP_RESPONSE'),
    dict(node_id=nd('gift_message.sender:REENTRY_POINT'),
         node_type='REENTRY_POINT', fqn='gift_message.sender (cart re-entry)',
         module='Magento_GiftMessage', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('gift_message.sender:PERSISTENCE_READ'),
         node_type='PERSISTENCE_READ', fqn='gift_message.sender',
         module='Magento_GiftMessage', area='frontend'),
    dict(node_id=nd('gift_message.sender:OUTPUT_CALL:inline.phtml'),
         node_type='OUTPUT_CALL',
         fqn='GiftMessage/inline.phtml: $block->getEscaped(getSender()) in value= attr',
         file='app/code/Magento/GiftMessage/view/frontend/templates/inline.phtml', line=0,
         module='Magento_GiftMessage', area='frontend', sink_kind='SK_HTTP_RESPONSE'),
    dict(node_id=nd('gift_message.recipient:REENTRY_POINT'),
         node_type='REENTRY_POINT', fqn='gift_message.recipient (cart re-entry)',
         module='Magento_GiftMessage', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('gift_message.recipient:PERSISTENCE_READ'),
         node_type='PERSISTENCE_READ', fqn='gift_message.recipient',
         module='Magento_GiftMessage', area='frontend'),
    dict(node_id=nd('gift_message.recipient:OUTPUT_CALL:inline.phtml'),
         node_type='OUTPUT_CALL',
         fqn='GiftMessage/inline.phtml: $block->getEscaped(getRecipient()) in value= attr',
         file='app/code/Magento/GiftMessage/view/frontend/templates/inline.phtml', line=0,
         module='Magento_GiftMessage', area='frontend', sink_kind='SK_HTTP_RESPONSE'),

    # ── CMS block — L1 ───────────────────────────────────────────────────────
    dict(node_id=nd('cms/adminhtml/block/save:HTTP_PARAM:content'),
         node_type='HTTP_PARAM', fqn='/cms/adminhtml/block/save?content',
         module='Magento_Cms', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('cms/adminhtml/block/save:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='Cms\\Controller\\Adminhtml\\Block\\Save::execute',
         file='vendor/magento/module-cms/Controller/Adminhtml/Block/Save.php', line=1,
         module='Magento_Cms', area='adminhtml'),
    dict(node_id=nd('cms/adminhtml/block/save:MODEL_SETTER:setContent'),
         node_type='MODEL_SETTER', fqn='Block::setContent',
         module='Magento_Cms', area='adminhtml'),
    dict(node_id=nd('cms/adminhtml/block/save:PERSISTENCE_WRITE:content'),
         node_type='PERSISTENCE_WRITE', fqn='cms_block.content',
         module='Magento_Cms', area='adminhtml', sink_kind='SK_DB_WRITE'),

    # ── CMS block — L2 (raw HTML render via BlockFilter) ─────────────────────
    dict(node_id=nd('cms_block.content:REENTRY_POINT'),
         node_type='REENTRY_POINT', fqn='cms_block.content (storefront re-entry)',
         module='Magento_Cms', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('cms_block.content:PERSISTENCE_READ'),
         node_type='PERSISTENCE_READ', fqn='cms_block.content',
         module='Magento_Cms', area='frontend'),
    dict(node_id=nd('cms_block.content:FUNCTION_CALL:BlockFilter'),
         node_type='FUNCTION_CALL',
         fqn='FilterProvider::getBlockFilter()->filter($block->getContent())',
         file='vendor/magento/module-cms/Block/Block.php', line=1,
         module='Magento_Cms', area='frontend'),
    dict(node_id=nd('cms_block.content:OUTPUT_CALL:block_render'),
         node_type='OUTPUT_CALL',
         fqn='Cms\\Block\\Block: /* @noEscape */ BlockFilter->filter(getContent())',
         file='vendor/magento/module-cms/Block/Block.php', line=1,
         module='Magento_Cms', area='frontend', sink_kind='SK_HTTP_RESPONSE'),

    # ── Admin customer create — L1 ────────────────────────────────────────────
    dict(node_id=nd('customer/adminhtml/index/save:HTTP_PARAM:firstname'),
         node_type='HTTP_PARAM', fqn='/customer/adminhtml/index/save?firstname',
         module='Magento_Customer', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('customer/adminhtml/index/save:HTTP_PARAM:lastname'),
         node_type='HTTP_PARAM', fqn='/customer/adminhtml/index/save?lastname',
         module='Magento_Customer', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('customer/adminhtml/index/save:HTTP_PARAM:email'),
         node_type='HTTP_PARAM', fqn='/customer/adminhtml/index/save?email',
         module='Magento_Customer', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('customer/adminhtml/index/save:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='Customer\\Controller\\Adminhtml\\Index\\Save::execute',
         file='vendor/magento/module-customer/Controller/Adminhtml/Index/Save.php', line=1,
         module='Magento_Customer', area='adminhtml'),
    dict(node_id=nd('customer/adminhtml/index/save:MODEL_SETTER:setData'),
         node_type='MODEL_SETTER', fqn='Customer::setData',
         module='Magento_Customer', area='adminhtml'),
    dict(node_id=nd('customer/adminhtml/index/save:PERSISTENCE_WRITE:firstname'),
         node_type='PERSISTENCE_WRITE', fqn='customer_entity.firstname',
         module='Magento_Customer', area='adminhtml', sink_kind='SK_DB_WRITE'),
    dict(node_id=nd('customer/adminhtml/index/save:PERSISTENCE_WRITE:lastname'),
         node_type='PERSISTENCE_WRITE', fqn='customer_entity.lastname',
         module='Magento_Customer', area='adminhtml', sink_kind='SK_DB_WRITE'),
    dict(node_id=nd('customer/adminhtml/index/save:PERSISTENCE_WRITE:email'),
         node_type='PERSISTENCE_WRITE', fqn='customer_entity.email',
         module='Magento_Customer', area='adminhtml', sink_kind='SK_DB_WRITE'),

    # ── Newsletter template — L1 ──────────────────────────────────────────────
    dict(node_id=nd('newsletter/adminhtml/template/save:HTTP_PARAM:template_text'),
         node_type='HTTP_PARAM', fqn='/newsletter/adminhtml/template/save?template_text',
         module='Magento_Newsletter', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('newsletter/adminhtml/template/save:HTTP_PARAM:template_subject'),
         node_type='HTTP_PARAM', fqn='/newsletter/adminhtml/template/save?template_subject',
         module='Magento_Newsletter', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('newsletter/adminhtml/template/save:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='Newsletter\\Controller\\Adminhtml\\Template\\Save::execute',
         file='vendor/magento/module-newsletter/Controller/Adminhtml/Template/Save.php', line=1,
         module='Magento_Newsletter', area='adminhtml'),
    dict(node_id=nd('newsletter/adminhtml/template/save:MODEL_SETTER:setData'),
         node_type='MODEL_SETTER', fqn='Template::setData',
         module='Magento_Newsletter', area='adminhtml'),
    dict(node_id=nd('newsletter/adminhtml/template/save:PERSISTENCE_WRITE:template_text'),
         node_type='PERSISTENCE_WRITE', fqn='newsletter_template.template_text',
         module='Magento_Newsletter', area='adminhtml', sink_kind='SK_DB_WRITE'),
    dict(node_id=nd('newsletter/adminhtml/template/save:PERSISTENCE_WRITE:template_subject'),
         node_type='PERSISTENCE_WRITE', fqn='newsletter_template.template_subject',
         module='Magento_Newsletter', area='adminhtml', sink_kind='SK_DB_WRITE'),

    # ── Newsletter template — L2 (email send sink) ────────────────────────────
    dict(node_id=nd('newsletter_template.template_text:REENTRY_POINT'),
         node_type='REENTRY_POINT', fqn='newsletter_template.template_text (send re-entry)',
         module='Magento_Newsletter', area='any', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('newsletter_template.template_text:PERSISTENCE_READ'),
         node_type='PERSISTENCE_READ', fqn='newsletter_template.template_text',
         module='Magento_Newsletter', area='any'),
    dict(node_id=nd('newsletter_template.template_text:OUTPUT_CALL:email_send'),
         node_type='OUTPUT_CALL',
         fqn='Newsletter\\Model\\Queue::sendPerSubscriber: template_text rendered into email body',
         file='vendor/magento/module-newsletter/Model/Queue.php', line=1,
         module='Magento_Newsletter', area='any', sink_kind='SK_EMAIL_RENDER'),

    # ── Order status history comment — L1 ─────────────────────────────────────
    dict(node_id=nd('sales/adminhtml/order/addcomment:HTTP_PARAM:comment'),
         node_type='HTTP_PARAM', fqn='/sales/adminhtml/order/addcomment?comment',
         module='Magento_Sales', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('sales/adminhtml/order/addcomment:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='Sales\\Controller\\Adminhtml\\Order\\AddComment::execute',
         file='vendor/magento/module-sales/Controller/Adminhtml/Order/AddComment.php', line=1,
         module='Magento_Sales', area='adminhtml'),
    dict(node_id=nd('sales/adminhtml/order/addcomment:MODEL_SETTER:setComment'),
         node_type='MODEL_SETTER', fqn='Order\\Status\\History::setComment',
         module='Magento_Sales', area='adminhtml'),
    dict(node_id=nd('sales/adminhtml/order/addcomment:PERSISTENCE_WRITE:comment'),
         node_type='PERSISTENCE_WRITE', fqn='sales_order_status_history.comment',
         module='Magento_Sales', area='adminhtml', sink_kind='SK_DB_WRITE'),

    # ── Order comment — L2: admin order view (partial HTML allowed) ───────────
    dict(node_id=nd('sales_order_status_history.comment:REENTRY_POINT:admin'),
         node_type='REENTRY_POINT', fqn='sales_order_status_history.comment (admin re-entry)',
         module='Magento_Sales', area='adminhtml', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('sales_order_status_history.comment:PERSISTENCE_READ:admin'),
         node_type='PERSISTENCE_READ', fqn='sales_order_status_history.comment',
         module='Magento_Sales', area='adminhtml'),
    dict(node_id=nd('sales_order_status_history.comment:OUTPUT_CALL:admin_history'),
         node_type='OUTPUT_CALL',
         fqn='order/view/history.phtml: escapeHtml(getComment(), [b,br,strong,i,u,a])',
         file='vendor/magento/module-sales/view/adminhtml/templates/order/view/history.phtml',
         line=0, module='Magento_Sales', area='adminhtml', sink_kind='SK_HTTP_RESPONSE'),

    # ── Order comment — L2: storefront order view (same partial HTML) ─────────
    dict(node_id=nd('sales_order_status_history.comment:REENTRY_POINT:frontend'),
         node_type='REENTRY_POINT', fqn='sales_order_status_history.comment (frontend re-entry)',
         module='Magento_Sales', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('sales_order_status_history.comment:PERSISTENCE_READ:frontend'),
         node_type='PERSISTENCE_READ', fqn='sales_order_status_history.comment',
         module='Magento_Sales', area='frontend'),
    dict(node_id=nd('sales_order_status_history.comment:OUTPUT_CALL:order_comments'),
         node_type='OUTPUT_CALL',
         fqn='order/order_comments.phtml: escapeHtml(getComment(), [b,br,strong,i,u,a])',
         file='vendor/magento/module-sales/view/frontend/templates/order/order_comments.phtml',
         line=0, module='Magento_Sales', area='frontend', sink_kind='SK_HTTP_RESPONSE'),

    # ── Wishlist send — L1 (email sink, no DB write) ──────────────────────────
    dict(node_id=nd('wishlist/index/send:HTTP_PARAM:emails'),
         node_type='HTTP_PARAM', fqn='/wishlist/index/send?emails',
         module='Magento_Wishlist', area='frontend', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('wishlist/index/send:HTTP_PARAM:message'),
         node_type='HTTP_PARAM', fqn='/wishlist/index/send?message',
         module='Magento_Wishlist', area='frontend', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('wishlist/index/send:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='Wishlist\\Controller\\Index\\Send::execute',
         file='vendor/magento/module-wishlist/Controller/Index/Send.php', line=1,
         module='Magento_Wishlist', area='frontend'),
    dict(node_id=nd('wishlist/index/send:OUTPUT_CALL:email'),
         node_type='OUTPUT_CALL',
         fqn='Wishlist email: message and recipient email sent via TransportBuilder',
         file='vendor/magento/module-wishlist/Controller/Index/Send.php', line=1,
         module='Magento_Wishlist', area='frontend', sink_kind='SK_EMAIL_RENDER'),

    # ── Checkout agreement — L1 ───────────────────────────────────────────────
    dict(node_id=nd('checkout/adminhtml/agreement/save:HTTP_PARAM:content'),
         node_type='HTTP_PARAM', fqn='/checkout/adminhtml/agreement/save?content',
         module='Magento_CheckoutAgreements', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('checkout/adminhtml/agreement/save:HTTP_PARAM:name'),
         node_type='HTTP_PARAM', fqn='/checkout/adminhtml/agreement/save?name',
         module='Magento_CheckoutAgreements', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('checkout/adminhtml/agreement/save:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY',
         fqn='CheckoutAgreements\\Controller\\Adminhtml\\Agreement\\Save::execute',
         file='vendor/magento/module-checkout-agreements/Controller/Adminhtml/Agreement/Save.php',
         line=1, module='Magento_CheckoutAgreements', area='adminhtml'),
    dict(node_id=nd('checkout/adminhtml/agreement/save:MODEL_SETTER:setData'),
         node_type='MODEL_SETTER', fqn='Agreement::setData',
         module='Magento_CheckoutAgreements', area='adminhtml'),
    dict(node_id=nd('checkout/adminhtml/agreement/save:PERSISTENCE_WRITE:content'),
         node_type='PERSISTENCE_WRITE', fqn='checkout_agreement.content',
         module='Magento_CheckoutAgreements', area='adminhtml', sink_kind='SK_DB_WRITE'),

    # ── Checkout agreement — L2 (checkout page raw HTML render) ──────────────
    dict(node_id=nd('checkout_agreement.content:REENTRY_POINT'),
         node_type='REENTRY_POINT', fqn='checkout_agreement.content (checkout re-entry)',
         module='Magento_CheckoutAgreements', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('checkout_agreement.content:PERSISTENCE_READ'),
         node_type='PERSISTENCE_READ', fqn='checkout_agreement.content',
         module='Magento_CheckoutAgreements', area='frontend'),
    dict(node_id=nd('checkout_agreement.content:OUTPUT_CALL:checkout'),
         node_type='OUTPUT_CALL',
         fqn='checkout/index/index: agreement content rendered raw in modal (admin-trusted HTML)',
         file='vendor/magento/module-checkout-agreements/view/frontend/web/js/model/agreement-validator.js',
         line=0, module='Magento_CheckoutAgreements', area='frontend', sink_kind='SK_HTTP_RESPONSE'),

    # ── Custom variable — L1 ─────────────────────────────────────────────────
    dict(node_id=nd('variable/save:HTTP_PARAM:html_value'),
         node_type='HTTP_PARAM', fqn='/adminhtml/adminhtml/system/variable/save?html_value',
         module='Magento_Variable', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('variable/save:HTTP_PARAM:plain_value'),
         node_type='HTTP_PARAM', fqn='/adminhtml/adminhtml/system/variable/save?plain_value',
         module='Magento_Variable', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('variable/save:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='Variable\\Controller\\Adminhtml\\System\\Variable\\Save::execute',
         file='vendor/magento/module-variable/Controller/Adminhtml/System/Variable/Save.php',
         line=1, module='Magento_Variable', area='adminhtml'),
    dict(node_id=nd('variable/save:MODEL_SETTER:setData'),
         node_type='MODEL_SETTER', fqn='Variable::setData',
         module='Magento_Variable', area='adminhtml'),
    dict(node_id=nd('variable/save:PERSISTENCE_WRITE:html_value'),
         node_type='PERSISTENCE_WRITE', fqn='variable.html_value',
         module='Magento_Variable', area='adminhtml', sink_kind='SK_DB_WRITE'),

    # ── Custom variable — L2 (raw HTML via CMS directive) ────────────────────
    dict(node_id=nd('variable.html_value:REENTRY_POINT'),
         node_type='REENTRY_POINT', fqn='variable.html_value (CMS directive re-entry)',
         module='Magento_Variable', area='frontend', provenance='PV_DB_REENTRY'),
    dict(node_id=nd('variable.html_value:PERSISTENCE_READ'),
         node_type='PERSISTENCE_READ', fqn='variable.html_value',
         module='Magento_Variable', area='frontend'),
    dict(node_id=nd('variable.html_value:OUTPUT_CALL:cms_render'),
         node_type='OUTPUT_CALL',
         fqn='Variable\\Model\\Variable::getValue: html_value returned raw via {{customVar code=...}}',
         file='vendor/magento/module-variable/Model/Variable.php', line=1,
         module='Magento_Variable', area='frontend', sink_kind='SK_HTTP_RESPONSE'),

    # ── Admin search term — L1 ────────────────────────────────────────────────
    dict(node_id=nd('search/adminhtml/term/save:HTTP_PARAM:query_text'),
         node_type='HTTP_PARAM', fqn='/search/adminhtml/term/save?query_text',
         module='Magento_Search', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('search/adminhtml/term/save:HTTP_PARAM:redirect'),
         node_type='HTTP_PARAM', fqn='/search/adminhtml/term/save?redirect',
         module='Magento_Search', area='adminhtml', provenance='PV_HTTP_BODY'),
    dict(node_id=nd('search/adminhtml/term/save:ROUTE_ENTRY'),
         node_type='ROUTE_ENTRY', fqn='Search\\Controller\\Adminhtml\\Term\\Save::execute',
         file='vendor/magento/module-search/Controller/Adminhtml/Term/Save.php', line=1,
         module='Magento_Search', area='adminhtml'),
    dict(node_id=nd('search/adminhtml/term/save:MODEL_SETTER:setData'),
         node_type='MODEL_SETTER', fqn='Query::setData',
         module='Magento_Search', area='adminhtml'),
    dict(node_id=nd('search/adminhtml/term/save:PERSISTENCE_WRITE:query_text'),
         node_type='PERSISTENCE_WRITE', fqn='search_query.query_text',
         module='Magento_Search', area='adminhtml', sink_kind='SK_DB_WRITE'),
    dict(node_id=nd('search/adminhtml/term/save:PERSISTENCE_WRITE:redirect'),
         node_type='PERSISTENCE_WRITE', fqn='search_query.redirect_url',
         module='Magento_Search', area='adminhtml', sink_kind='SK_DB_WRITE'),
]


# ── Hop builder ───────────────────────────────────────────────────────────────

def build_hops(lid, specs):
    """specs: [(node_id, is_boundary, boundary_kind, store_kind, store_id)]"""
    hops, edges = [], []
    prev = None
    for seq, (nid, ib, bk, sk, si) in enumerate(specs):
        eid = None
        if prev:
            eid = ed(f'{prev}->{nid}:{lid}')
            edges.append((eid, prev, nid))
        hops.append(dict(hop_id=lh(f'{lid}:hop:{seq}'), lineage_id=lid,
                         hop_sequence=seq, node_id=nid, edge_from_prev=eid,
                         is_boundary=ib, boundary_kind=bk,
                         store_kind=sk, store_identifier=si))
        prev = nid
    return hops, edges


def make_lin(lid, order_num, route_id, src, snk, hops, **kw):
    return dict(lineage_id=lid, order_num=order_num, route_id=route_id,
                source_node=src, sink_node=snk, hop_count=len(hops) - 1,
                flags_emitted=kw.get('flags_emitted', '[]'),
                flags_required='[]', flags_missing='[]',
                upstream_lineage=kw.get('upstream_lineage'),
                downstream_lineage=None,
                analysis_method='static',
                confidence=kw.get('confidence', 0.9),
                run_id=RUN_ID, notes=kw.get('notes'))


# ── Chain builders ────────────────────────────────────────────────────────────

def build_gift_message_chains():
    lins, hops_all, edges_all = [], [], []

    for field, pw in [
        ('sender',    nd('giftmessage:PERSISTENCE_WRITE:sender')),
        ('recipient', nd('giftmessage:PERSISTENCE_WRITE:recipient')),
        ('message',   nd('giftmessage:PERSISTENCE_WRITE:message')),
    ]:
        src = nd(f'giftmessage:HTTP_PARAM:{field}')
        lid = ln(f'giftmessage:{field}:L1')
        specs = [
            (src,                             0, None, None, None),
            (nd('giftmessage:ROUTE_ENTRY'),   0, None, None, None),
            (nd('giftmessage:MODEL_SETTER:setMessage'), 0, None, None, None),
            (pw,                              1, 'BD_DB_WRITE', 'db', f'gift_message.{field}'),
        ]
        h, e = build_hops(lid, specs)
        lins.append(make_lin(lid, 1, 'rt-gift-guest-rest', src, pw, h,
            flags_emitted='["BD_DB_WRITE"]',
            notes=f'L1: guest sets cart gift message {field} via REST → gift_message.{field}. '
                  f'MFTF: StorefrontFillGiftMessageAtOrderLevelActionGroup / '
                  f'StorefrontFieldGiftMessageCartFormActionGroup.'))
        hops_all += h; edges_all += e

    # L2 for each field
    l2_data = [
        ('message',   nd('gift_message.message:REENTRY_POINT'),
                      nd('gift_message.message:PERSISTENCE_READ'),
                      nd('gift_message.message:SANITIZER:escapeHtml'),
                      nd('gift_message.message:OUTPUT_CALL:inline.phtml'),
                      'escapeHtml applied — SAFE'),
        ('sender',    nd('gift_message.sender:REENTRY_POINT'),
                      nd('gift_message.sender:PERSISTENCE_READ'),
                      None,
                      nd('gift_message.sender:OUTPUT_CALL:inline.phtml'),
                      'getEscaped() in value= attr context — check for attr injection'),
        ('recipient', nd('gift_message.recipient:REENTRY_POINT'),
                      nd('gift_message.recipient:PERSISTENCE_READ'),
                      None,
                      nd('gift_message.recipient:OUTPUT_CALL:inline.phtml'),
                      'getEscaped() in value= attr context — check for attr injection'),
    ]
    write_lids = {f: ln(f'giftmessage:{f}:L1') for f in ('sender', 'recipient', 'message')}

    for field, reentry, pread, sanitizer, output, note in l2_data:
        lid2 = ln(f'giftmessage:{field}:L2:cart')
        specs2 = [(reentry, 1, 'BD_DB_READ', 'db', f'gift_message.{field}'),
                  (pread,   0, None, None, None)]
        if sanitizer:
            specs2.append((sanitizer, 0, None, None, None))
        specs2.append((output, 0, None, None, None))
        h2, e2 = build_hops(lid2, specs2)
        lins.append(make_lin(lid2, 2, RT_CHECKOUT_CART, reentry, output, h2,
            upstream_lineage=write_lids[field],
            notes=f'L2: GET /checkout/cart/index → GiftMessage/inline.phtml. {note}'))
        hops_all += h2; edges_all += e2

    return lins, hops_all, edges_all


def build_cms_block_chains():
    lins, hops_all, edges_all = [], [], []

    # L1
    src  = nd('cms/adminhtml/block/save:HTTP_PARAM:content')
    sink = nd('cms/adminhtml/block/save:PERSISTENCE_WRITE:content')
    lid  = ln('cms/adminhtml/block/save:content:L1')
    specs = [
        (src,                                                  0, None, None, None),
        (nd('cms/adminhtml/block/save:ROUTE_ENTRY'),           0, None, None, None),
        (nd('cms/adminhtml/block/save:MODEL_SETTER:setContent'), 0, None, None, None),
        (sink,                                                 1, 'BD_DB_WRITE', 'db', 'cms_block.content'),
    ]
    h, e = build_hops(lid, specs)
    lins.append(make_lin(lid, 1, RT_CMS_BLOCK_SAVE, src, sink, h,
        flags_emitted='["BD_DB_WRITE"]',
        notes='L1: admin saves CMS block content → cms_block.content. '
              'MFTF: AdminFillCmsBlockFormActionGroup. '
              'Admin-authored HTML — trusted input in Magento security model.'))
    hops_all += h; edges_all += e

    # L2 — raw HTML render via BlockFilter (no escaping)
    src2  = nd('cms_block.content:REENTRY_POINT')
    sink2 = nd('cms_block.content:OUTPUT_CALL:block_render')
    lid2  = ln('cms_block.content:storefront:L2')
    specs2 = [
        (src2,                                      1, 'BD_DB_READ', 'db', 'cms_block.content'),
        (nd('cms_block.content:PERSISTENCE_READ'),  0, None, None, None),
        (nd('cms_block.content:FUNCTION_CALL:BlockFilter'), 0, None, None, None),
        (sink2,                                     0, None, None, None),
    ]
    h2, e2 = build_hops(lid2, specs2)
    lins.append(make_lin(lid2, 2, 'rt-07b9b4b7eb', src2, sink2, h2,
        upstream_lineage=lid,
        notes='L2: CMS block rendered via /* @noEscape */ BlockFilter->filter(getContent()). '
              'No HTML escaping — content is rendered verbatim. Admin-trusted path. '
              'Sink: any storefront page containing {{block id=...}} directive.'))
    hops_all += h2; edges_all += e2

    return lins, hops_all, edges_all, lid


def build_admin_customer_save_chains():
    lins, hops_all, edges_all = [], [], []
    for field, pw in [
        ('firstname', nd('customer/adminhtml/index/save:PERSISTENCE_WRITE:firstname')),
        ('lastname',  nd('customer/adminhtml/index/save:PERSISTENCE_WRITE:lastname')),
        ('email',     nd('customer/adminhtml/index/save:PERSISTENCE_WRITE:email')),
    ]:
        src = nd(f'customer/adminhtml/index/save:HTTP_PARAM:{field}')
        lid = ln(f'customer/adminhtml/index/save:{field}:L1')
        specs = [
            (src,                                                    0, None, None, None),
            (nd('customer/adminhtml/index/save:ROUTE_ENTRY'),        0, None, None, None),
            (nd('customer/adminhtml/index/save:MODEL_SETTER:setData'), 0, None, None, None),
            (pw,                                                     1, 'BD_DB_WRITE', 'db',
             f'customer_entity.{field}'),
        ]
        h, e = build_hops(lid, specs)
        lins.append(make_lin(lid, 1, RT_ADMIN_CUST_SAVE, src, pw, h,
            flags_emitted='["BD_DB_WRITE"]',
            notes=f'L1: admin creates/edits customer → customer_entity.{field}. '
                  f'MFTF: AdminFillCustomerMainDataActionGroup. Admin path — same store as '
                  f'storefront createpost/editPost L1 chains. L2 readbacks already mapped.'))
        hops_all += h; edges_all += e

    return lins, hops_all, edges_all


def build_newsletter_template_chains():
    lins, hops_all, edges_all = [], [], []
    for field, pw in [
        ('template_text',    nd('newsletter/adminhtml/template/save:PERSISTENCE_WRITE:template_text')),
        ('template_subject', nd('newsletter/adminhtml/template/save:PERSISTENCE_WRITE:template_subject')),
    ]:
        src = nd(f'newsletter/adminhtml/template/save:HTTP_PARAM:{field}')
        lid = ln(f'newsletter/adminhtml/template/save:{field}:L1')
        specs = [
            (src,                                                        0, None, None, None),
            (nd('newsletter/adminhtml/template/save:ROUTE_ENTRY'),       0, None, None, None),
            (nd('newsletter/adminhtml/template/save:MODEL_SETTER:setData'), 0, None, None, None),
            (pw,                                                         1, 'BD_DB_WRITE', 'db',
             f'newsletter_template.{field}'),
        ]
        h, e = build_hops(lid, specs)
        lins.append(make_lin(lid, 1, RT_NL_TEMPLATE_SAVE, src, pw, h,
            flags_emitted='["BD_DB_WRITE"]',
            notes=f'L1: admin saves newsletter template → newsletter_template.{field}. '
                  f'MFTF: AdminMarketingCreateNewsletterTemplateActionGroup.'))
        hops_all += h; edges_all += e

    # L2 for template_text → email send
    write_lid = ln('newsletter/adminhtml/template/save:template_text:L1')
    src2  = nd('newsletter_template.template_text:REENTRY_POINT')
    sink2 = nd('newsletter_template.template_text:OUTPUT_CALL:email_send')
    lid2  = ln('newsletter_template.template_text:email:L2')
    specs2 = [
        (src2,                                                      1, 'BD_DB_READ', 'db',
         'newsletter_template.template_text'),
        (nd('newsletter_template.template_text:PERSISTENCE_READ'), 0, None, None, None),
        (sink2,                                                    0, None, None, None),
    ]
    h2, e2 = build_hops(lid2, specs2)
    lins.append(make_lin(lid2, 2, RT_NL_TEMPLATE_SAVE, src2, sink2, h2,
        upstream_lineage=write_lid,
        notes='L2: newsletter_template.template_text → email body rendered per subscriber. '
              'Sink type SK_EMAIL_RENDER. Admin-authored content — trusted in Magento model.'))
    hops_all += h2; edges_all += e2

    return lins, hops_all, edges_all


def build_order_comment_chains():
    lins, hops_all, edges_all = [], [], []

    # L1
    src  = nd('sales/adminhtml/order/addcomment:HTTP_PARAM:comment')
    sink = nd('sales/adminhtml/order/addcomment:PERSISTENCE_WRITE:comment')
    lid  = ln('sales/adminhtml/order/addcomment:comment:L1')
    specs = [
        (src,                                                         0, None, None, None),
        (nd('sales/adminhtml/order/addcomment:ROUTE_ENTRY'),          0, None, None, None),
        (nd('sales/adminhtml/order/addcomment:MODEL_SETTER:setComment'), 0, None, None, None),
        (sink,                                                        1, 'BD_DB_WRITE', 'db',
         'sales_order_status_history.comment'),
    ]
    h, e = build_hops(lid, specs)
    lins.append(make_lin(lid, 1, RT_ORDER_ADDCOMMENT, src, sink, h,
        flags_emitted='["BD_DB_WRITE"]',
        notes='L1: admin adds order comment → sales_order_status_history.comment. '
              'MFTF: AdminAddCommentOnCreateOrderPageActionGroup.'))
    hops_all += h; edges_all += e

    # L2 — admin order history (partial escape: allows b,br,strong,i,u,a)
    src2  = nd('sales_order_status_history.comment:REENTRY_POINT:admin')
    sink2 = nd('sales_order_status_history.comment:OUTPUT_CALL:admin_history')
    lid2  = ln('sales_order_status_history.comment:admin:L2')
    specs2 = [
        (src2,                                                               1, 'BD_DB_READ', 'db',
         'sales_order_status_history.comment'),
        (nd('sales_order_status_history.comment:PERSISTENCE_READ:admin'),   0, None, None, None),
        (sink2,                                                              0, None, None, None),
    ]
    h2, e2 = build_hops(lid2, specs2)
    lins.append(make_lin(lid2, 2, RT_ORDER_ADDCOMMENT, src2, sink2, h2,
        upstream_lineage=lid,
        notes='L2: admin order history → order/view/history.phtml. '
              'escapeHtml(getComment(), [b,br,strong,i,u,a]) — partial HTML allowed. '
              'Admin-entered comment, admin-only view.'))
    hops_all += h2; edges_all += e2

    # L2 — storefront order view (same partial escape, customer-visible)
    src3  = nd('sales_order_status_history.comment:REENTRY_POINT:frontend')
    sink3 = nd('sales_order_status_history.comment:OUTPUT_CALL:order_comments')
    lid3  = ln('sales_order_status_history.comment:frontend:L2')
    specs3 = [
        (src3,                                                                1, 'BD_DB_READ', 'db',
         'sales_order_status_history.comment'),
        (nd('sales_order_status_history.comment:PERSISTENCE_READ:frontend'), 0, None, None, None),
        (sink3,                                                               0, None, None, None),
    ]
    h3, e3 = build_hops(lid3, specs3)
    lins.append(make_lin(lid3, 2, RT_ORDER_VIEW_FE, src3, sink3, h3,
        upstream_lineage=lid, confidence=0.85,
        notes='L2: storefront order/order_comments.phtml. '
              'escapeHtml(getComment(), [b,br,strong,i,u,a]) — partial HTML escaping. '
              'Admin comment visible to customer. Allowed tags include <a> — '
              'href attribute not scrubbed in all Magento versions.'))
    hops_all += h3; edges_all += e3

    return lins, hops_all, edges_all


def build_wishlist_send_chain():
    lins, hops_all, edges_all = [], [], []
    for field in ('emails', 'message'):
        src  = nd(f'wishlist/index/send:HTTP_PARAM:{field}')
        sink = nd('wishlist/index/send:OUTPUT_CALL:email')
        lid  = ln(f'wishlist/index/send:{field}:L1')
        specs = [
            (src,                                0, None, None, None),
            (nd('wishlist/index/send:ROUTE_ENTRY'), 0, None, None, None),
            (sink,                               0, None, None, None),
        ]
        h, e = build_hops(lid, specs)
        lins.append(make_lin(lid, 1, RT_WISHLIST_SEND, src, sink, h,
            notes=f'L1: customer shares wishlist → {field} sent via TransportBuilder email. '
                  f'MFTF: StorefrontShareCustomerWishlistActionGroup. '
                  f'Sink: SK_EMAIL_RENDER — no DB write, direct to outgoing email.'))
        hops_all += h; edges_all += e
    return lins, hops_all, edges_all


def build_agreement_chains():
    lins, hops_all, edges_all = [], [], []

    # L1
    src  = nd('checkout/adminhtml/agreement/save:HTTP_PARAM:content')
    sink = nd('checkout/adminhtml/agreement/save:PERSISTENCE_WRITE:content')
    lid  = ln('checkout/adminhtml/agreement/save:content:L1')
    specs = [
        (src,                                                           0, None, None, None),
        (nd('checkout/adminhtml/agreement/save:ROUTE_ENTRY'),          0, None, None, None),
        (nd('checkout/adminhtml/agreement/save:MODEL_SETTER:setData'), 0, None, None, None),
        (sink,                                                         1, 'BD_DB_WRITE', 'db',
         'checkout_agreement.content'),
    ]
    h, e = build_hops(lid, specs)
    lins.append(make_lin(lid, 1, RT_AGREEMENT_SAVE, src, sink, h,
        flags_emitted='["BD_DB_WRITE"]',
        notes='L1: admin saves checkout T&C content → checkout_agreement.content. '
              'MFTF: AdminTermsConditionsFillTermEditFormActionGroup.'))
    hops_all += h; edges_all += e

    # L2 — checkout page render (raw HTML)
    src2  = nd('checkout_agreement.content:REENTRY_POINT')
    sink2 = nd('checkout_agreement.content:OUTPUT_CALL:checkout')
    lid2  = ln('checkout_agreement.content:checkout:L2')
    specs2 = [
        (src2,                                                   1, 'BD_DB_READ', 'db',
         'checkout_agreement.content'),
        (nd('checkout_agreement.content:PERSISTENCE_READ'),     0, None, None, None),
        (sink2,                                                  0, None, None, None),
    ]
    h2, e2 = build_hops(lid2, specs2)
    lins.append(make_lin(lid2, 2, RT_CHECKOUT_INDEX, src2, sink2, h2,
        upstream_lineage=lid,
        notes='L2: /checkout/index/index renders checkout_agreement.content raw in modal. '
              'Admin-trusted HTML. No escaping applied to content field.'))
    hops_all += h2; edges_all += e2

    return lins, hops_all, edges_all


def build_variable_chains():
    lins, hops_all, edges_all = [], [], []

    # L1
    src  = nd('variable/save:HTTP_PARAM:html_value')
    sink = nd('variable/save:PERSISTENCE_WRITE:html_value')
    lid  = ln('variable/save:html_value:L1')
    specs = [
        (src,                                        0, None, None, None),
        (nd('variable/save:ROUTE_ENTRY'),            0, None, None, None),
        (nd('variable/save:MODEL_SETTER:setData'),   0, None, None, None),
        (sink,                                       1, 'BD_DB_WRITE', 'db', 'variable.html_value'),
    ]
    h, e = build_hops(lid, specs)
    lins.append(make_lin(lid, 1, RT_VARIABLE_SAVE, src, sink, h,
        flags_emitted='["BD_DB_WRITE"]',
        notes='L1: admin saves custom variable html_value → variable.html_value. '
              'MFTF: AdminFillVariableFormActionGroup.'))
    hops_all += h; edges_all += e

    # L2 — raw HTML via {{customVar code=...}} in any CMS page
    src2  = nd('variable.html_value:REENTRY_POINT')
    sink2 = nd('variable.html_value:OUTPUT_CALL:cms_render')
    lid2  = ln('variable.html_value:cms:L2')
    specs2 = [
        (src2,                                        1, 'BD_DB_READ', 'db', 'variable.html_value'),
        (nd('variable.html_value:PERSISTENCE_READ'),  0, None, None, None),
        (sink2,                                       0, None, None, None),
    ]
    h2, e2 = build_hops(lid2, specs2)
    lins.append(make_lin(lid2, 2, 'rt-222693c4', src2, sink2, h2,
        upstream_lineage=lid,
        notes='L2: variable.html_value rendered raw via {{customVar code=...}} directive '
              'in any CMS page or block. Variable::getValue() returns html_value unescaped. '
              'Admin-trusted input. Sink: SK_HTTP_RESPONSE, no escaping.'))
    hops_all += h2; edges_all += e2

    return lins, hops_all, edges_all


def build_search_term_admin_chains():
    lins, hops_all, edges_all = [], [], []

    for field, pw in [
        ('query_text',   nd('search/adminhtml/term/save:PERSISTENCE_WRITE:query_text')),
        ('redirect',     nd('search/adminhtml/term/save:PERSISTENCE_WRITE:redirect')),
    ]:
        src = nd(f'search/adminhtml/term/save:HTTP_PARAM:{field}')
        lid = ln(f'search/adminhtml/term/save:{field}:L1')
        db_col = 'search_query.query_text' if field == 'query_text' else 'search_query.redirect_url'
        specs = [
            (src,                                                 0, None, None, None),
            (nd('search/adminhtml/term/save:ROUTE_ENTRY'),       0, None, None, None),
            (nd('search/adminhtml/term/save:MODEL_SETTER:setData'), 0, None, None, None),
            (pw,                                                  1, 'BD_DB_WRITE', 'db', db_col),
        ]
        h, e = build_hops(lid, specs)
        lins.append(make_lin(lid, 1, RT_SEARCH_TERM_SAVE, src, pw, h,
            flags_emitted='["BD_DB_WRITE"]',
            notes=f'L1: admin saves search term → {db_col}. '
                  f'MFTF: AdminCreateNewSearchTermEntityActionGroup / '
                  f'AdminFillAllSearchTermFieldsActionGroup. '
                  f'Same store as frontend searchtermslog/save chain (L1 already mapped).'))
        hops_all += h; edges_all += e

    return lins, hops_all, edges_all


# ── DB helpers ────────────────────────────────────────────────────────────────

EDGE_MAP = {
    ('HTTP_PARAM',       'ROUTE_ENTRY'):       'PASSES_TO',
    ('ROUTE_ENTRY',      'MODEL_SETTER'):      'ASSIGNS_TO',
    ('ROUTE_ENTRY',      'OUTPUT_CALL'):       'RENDERS_IN',
    ('MODEL_SETTER',     'PERSISTENCE_WRITE'): 'PERSISTS_TO',
    ('REENTRY_POINT',    'PERSISTENCE_READ'):  'READS_FROM',
    ('PERSISTENCE_READ', 'FUNCTION_CALL'):     'PASSES_TO',
    ('PERSISTENCE_READ', 'SANITIZER'):         'PASSES_TO',
    ('PERSISTENCE_READ', 'OUTPUT_CALL'):       'RENDERS_IN',
    ('FUNCTION_CALL',    'OUTPUT_CALL'):       'RENDERS_IN',
    ('SANITIZER',        'OUTPUT_CALL'):       'RENDERS_IN',
}


def insert_nodes(cur, nodes):
    ins = 0
    for n in nodes:
        cur.execute('''
            INSERT OR IGNORE INTO nodes
              (node_id, node_type, fqn, file, line, module, area, provenance, sink_kind)
            VALUES (:node_id,:node_type,:fqn,:file,:line,:module,:area,:provenance,:sink_kind)
        ''', {'file': None, 'line': None, 'provenance': None, 'sink_kind': None,
               'module': None, 'area': None, **n})
        if cur.rowcount: ins += 1
    return ins


def insert_routes(cur, routes):
    ins = 0
    for r in routes:
        cur.execute('''
            INSERT OR IGNORE INTO routes
              (route_id, http_method, url_pattern, area, module, controller, action, notes)
            VALUES (:route_id,:http_method,:url_pattern,:area,:module,:controller,:action,:notes)
        ''', {'module': None, 'controller': None, 'action': None, 'notes': None, **r})
        if cur.rowcount: ins += 1
    return ins


def insert_all(cur, con, lins, hops, edges):
    li = ho = he = 0
    for eid, fn, tn in edges:
        ft = con.execute("SELECT node_type FROM nodes WHERE node_id=?", (fn,)).fetchone()
        tt = con.execute("SELECT node_type FROM nodes WHERE node_id=?", (tn,)).fetchone()
        etype = EDGE_MAP.get((ft[0] if ft else '', tt[0] if tt else ''), 'PASSES_TO')
        cur.execute(
            'INSERT OR IGNORE INTO edges'
            ' (edge_id,edge_type,from_node,to_node,confidence,evidence)'
            ' VALUES (?,?,?,?,0.9,"static")', (eid, etype, fn, tn))
        if cur.rowcount: he += 1
    for row in lins:
        cur.execute('''
            INSERT OR IGNORE INTO lineages
              (lineage_id,order_num,route_id,source_node,sink_node,hop_count,
               flags_emitted,flags_required,flags_missing,
               upstream_lineage,downstream_lineage,
               analysis_method,confidence,run_id,notes)
            VALUES
              (:lineage_id,:order_num,:route_id,:source_node,:sink_node,:hop_count,
               :flags_emitted,:flags_required,:flags_missing,
               :upstream_lineage,:downstream_lineage,
               :analysis_method,:confidence,:run_id,:notes)
        ''', {'notes': None, **row})
        if cur.rowcount: li += 1
    for h in hops:
        cur.execute('''
            INSERT OR IGNORE INTO lineage_hops
              (hop_id,lineage_id,hop_sequence,node_id,edge_from_prev,
               is_boundary,boundary_kind,store_kind,store_identifier)
            VALUES
              (:hop_id,:lineage_id,:hop_sequence,:node_id,:edge_from_prev,
               :is_boundary,:boundary_kind,:store_kind,:store_identifier)
        ''', h)
        if cur.rowcount: ho += 1
    return li, ho, he


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    rt_ins = insert_routes(cur, NEW_ROUTES)
    print(f'Routes inserted: {rt_ins}')

    n_ins = insert_nodes(cur, NODES)
    print(f'Nodes inserted: {n_ins}')

    results = []

    l, h, e = build_gift_message_chains()
    li, ho, he = insert_all(cur, con, l, h, e)
    results.append(('gift_message L1+L2', li, ho, he))

    l, h, e, _ = build_cms_block_chains()
    li, ho, he = insert_all(cur, con, l, h, e)
    results.append(('cms_block L1+L2', li, ho, he))

    l, h, e = build_admin_customer_save_chains()
    li, ho, he = insert_all(cur, con, l, h, e)
    results.append(('admin customer save L1', li, ho, he))

    l, h, e = build_newsletter_template_chains()
    li, ho, he = insert_all(cur, con, l, h, e)
    results.append(('newsletter_template L1+L2', li, ho, he))

    l, h, e = build_order_comment_chains()
    li, ho, he = insert_all(cur, con, l, h, e)
    results.append(('order_comment L1+L2', li, ho, he))

    l, h, e = build_wishlist_send_chain()
    li, ho, he = insert_all(cur, con, l, h, e)
    results.append(('wishlist_send L1', li, ho, he))

    l, h, e = build_agreement_chains()
    li, ho, he = insert_all(cur, con, l, h, e)
    results.append(('checkout_agreement L1+L2', li, ho, he))

    l, h, e = build_variable_chains()
    li, ho, he = insert_all(cur, con, l, h, e)
    results.append(('variable L1+L2', li, ho, he))

    l, h, e = build_search_term_admin_chains()
    li, ho, he = insert_all(cur, con, l, h, e)
    results.append(('search_term_admin L1', li, ho, he))

    con.commit()

    print('\nResults:')
    for name, li, ho, he in results:
        print(f'  {name}: {li} lineages, {ho} hops, {he} edges')

    rows = con.execute(
        'SELECT order_num, COUNT(*) FROM lineages GROUP BY order_num ORDER BY order_num'
    ).fetchall()
    print('\nFinal lineage counts:')
    total = 0
    for order_num, cnt in rows:
        label = {1: 'L1', 2: 'L2', 3: 'L3'}.get(order_num, f'L{order_num}')
        print(f'  {label}: {cnt}')
        total += cnt
    print(f'  Total: {total}')

    # Distinct persistence stores covered
    stores = con.execute(
        "SELECT DISTINCT store_identifier FROM lineage_hops "
        "WHERE is_boundary=1 AND store_identifier IS NOT NULL ORDER BY store_identifier"
    ).fetchall()
    print(f'\nDistinct stores mapped: {len(stores)}')
    for (s,) in stores:
        print(f'  {s}')

    con.close()


if __name__ == '__main__':
    main()
