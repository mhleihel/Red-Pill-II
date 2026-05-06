# Lineage Map — 2026-05-05

88 lineages across 32 persistence stores. Generated from `results/appmap.db`.

## L1 Lineages (45) — HTTP Input → First DB Write

| Lineage ID | Route | Parameter | Store | Confidence | Notes |
|---|---|---|---|---|---|
| ln-33a0f8a3 | POST /review/product/post | nickname | review_detail.nickname | 1.0 | runtime+static |
| ln-f00c6092 | POST /review/product/post | title | review_detail.title | 1.0 | runtime+static |
| ln-2bc4c862 | POST /review/product/post | detail | review_detail.detail | 1.0 | runtime+static |
| ln-7a43c266 | POST /newsletter/subscriber/newaction | email | newsletter_subscriber.subscriber_email | 1.0 | runtime+static |
| ln-497c6c7f | POST /customer/account/editPost | firstname | customer_entity.firstname | 1.0 | |
| ln-342a5d72 | POST /wishlist/index/add | description | wishlist_item.description | 1.0 | |
| ln-2b242df0 | POST /contact/index/post | name | submitted_form.html | 1.0 | SK_EMAIL_RENDER, unescaped |
| ln-4daa6f39 | POST /contact/index/post | email | submitted_form.html | 1.0 | SK_EMAIL_RENDER, unescaped |
| ln-1320d27a | POST /contact/index/post | telephone | submitted_form.html | 1.0 | SK_EMAIL_RENDER, unescaped |
| ln-8d43008a | POST /contact/index/post | comment | submitted_form.html | 1.0 | SK_EMAIL_RENDER, unescaped |
| ln-36817a3f | POST /customer/address/formPost | firstname | customer_address_entity.firstname | 1.0 | |
| ln-09ab46c9 | POST /catalog/adminhtml/product/save | product[description] | catalog_product_entity_text.description | 1.0 | WYSIWYG — admin |
| ln-364d71a9 | POST /catalog/adminhtml/category/save | description | catalog_category_entity_text.description | 1.0 | WYSIWYG — admin |
| ln-55403978 | POST /cms/adminhtml/page/save | content | cms_page.content | 1.0 | WYSIWYG — admin |
| ln-9faaaf8a | POST /customer/account/createpost | firstname | customer_entity.firstname | 0.9 | |
| ln-9b6c547d | POST /customer/account/createpost | lastname | customer_entity.lastname | 0.9 | |
| ln-95f25a41 | POST /customer/account/createpost | email | customer_entity.email | 0.9 | |
| ln-734157c3 | POST /catalogsearch/advanced/result | name | search_query.query_text | 0.9 | L2 read at /search/term/popular |
| ln-b59ad288 | GET /catalogsearch/result/index | q | search_query.query_text | 0.9 | L2 read at /search/term/popular |
| ln-99763325 | POST /catalogsearch/searchtermslog/save | q | search_query.query_text | 0.9 | Blocker: num_results required for popular terms |
| ln-cca8e8c2 | POST /checkout/cart/estimatepost | estimate_postcode | quote_address.postcode | 0.9 | Session-tied |
| ln-97aff9c1 | POST /checkout/cart/couponpost | coupon_code | quote.coupon_code | 0.9 | Session-tied |
| ln-aa257a4b | REST /rest/V1/guest-carts/{id}/shipping-information | shippingAddress.firstname | quote_address.firstname | 0.9 | |
| ln-74684ce9 | REST /rest/V1/guest-carts/{id}/shipping-information | shippingAddress.lastname | quote_address.lastname | 0.9 | |
| ln-9bb59827 | REST /rest/V1/guest-carts/{id}/shipping-information | shippingAddress.street | quote_address.street | 0.9 | |
| ln-5f66ac0b | REST /rest/V1/guest-carts/{id}/shipping-information | shippingAddress.city | quote_address.city | 0.9 | |
| ln-440dbc51 | REST /rest/V1/guest-carts/{id}/shipping-information | shippingAddress.email | quote_address.email | 0.9 | |
| ln-45544d59 | REST /rest/V1/guest-carts/{id}/payment-information | billingAddress.firstname | sales_order_address.firstname | 0.9 | |
| ln-3ebc1177 | REST /rest/V1/guest-carts/{id}/gift-message | sender | gift_message.sender | 0.9 | MFTF |
| ln-a9377256 | REST /rest/V1/guest-carts/{id}/gift-message | recipient | gift_message.recipient | 0.9 | MFTF |
| ln-c05d8161 | REST /rest/V1/guest-carts/{id}/gift-message | message | gift_message.message | 0.9 | MFTF |
| ln-56e89d17 | POST /cms/adminhtml/block/save | content | cms_block.content | 0.9 | MFTF — admin-trusted |
| ln-4172e2f8 | POST /checkout/adminhtml/agreement/save | content | checkout_agreement.content | 0.9 | MFTF — admin |
| ln-0b8ad895 | POST /customer/adminhtml/index/save | firstname | customer_entity.firstname | 0.9 | MFTF — admin |
| ln-96703e23 | POST /customer/adminhtml/index/save | lastname | customer_entity.lastname | 0.9 | MFTF — admin |
| ln-1aee4050 | POST /customer/adminhtml/index/save | email | customer_entity.email | 0.9 | MFTF — admin |
| ln-ea9be58f | POST /search/adminhtml/term/save | query_text | search_query.query_text | 0.9 | MFTF — admin |
| ln-5c0deefb | POST /search/adminhtml/term/save | redirect | search_query.redirect_url | 0.9 | MFTF — admin |
| ln-5f36f574 | POST /newsletter/adminhtml/template/save | template_text | newsletter_template.template_text | 0.9 | MFTF — admin |
| ln-948926f5 | POST /newsletter/adminhtml/template/save | template_subject | newsletter_template.template_subject | 0.9 | MFTF — admin |
| ln-28caf633 | POST /sales/adminhtml/order/addcomment | comment | sales_order_status_history.comment | 0.9 | MFTF — admin |
| ln-e92839d8 | POST /adminhtml/system/variable/save | html_value | variable.html_value | 0.9 | MFTF — admin |
| ln-07fe6912 | POST /contact/index/post | comment | SK_EMAIL_RENDER | 0.9 | default escape=html — SAFE |
| ln-2c3f5d00 | POST /wishlist/index/send | emails | SK_EMAIL_RENDER | 0.9 | TransportBuilder |
| ln-99bf2ae5 | POST /wishlist/index/send | message | SK_EMAIL_RENDER | 0.9 | TransportBuilder |

---

## L2 Lineages (41) — DB Read-Back → HTTP Response

| Lineage ID | Read Route | Store | Sink | Confidence | Escaping | Notes |
|---|---|---|---|---|---|---|
| ln-f1ff7afa | /review/product/listajax | review_detail.nickname | SK_HTTP_RESPONSE | 1.0 | escapeHtml | SAFE |
| ln-013cd2f2 | /review/product/listajax | review_detail.title | SK_HTTP_RESPONSE | 1.0 | escapeHtml | SAFE |
| ln-886c335b | /review/product/listajax | review_detail.detail | SK_HTTP_RESPONSE | 1.0 | escapeHtml | SAFE |
| ln-07d3071ae0 | /review/product/listaction | review_detail.nickname | SK_HTTP_RESPONSE | 1.0 | escapeHtml | SAFE |
| ln-18982d71ff | /review/product/listaction | review_detail.title | SK_HTTP_RESPONSE | 1.0 | escapeHtml | SAFE |
| ln-3f51fffa2d | /review/product/listaction | review_detail.detail | SK_HTTP_RESPONSE | 1.0 | escapeHtml | SAFE |
| ln-41df4bef | /review/product/view/id/1 | review_detail.detail | SK_HTTP_RESPONSE | 1.0 | escapeHtml | SAFE |
| ln-af1a16e5 | /customer/account/index | customer_entity.firstname | SK_HTTP_RESPONSE | 1.0 | escapeHtml | SAFE |
| ln-a1ea6930 | /review/customer/index | review_detail.nickname | SK_HTTP_RESPONSE | 1.0 | escapeHtml | SAFE |
| ln-f70fa8bf | /wishlist/index/index | wishlist_item.description | SK_HTTP_RESPONSE | 1.0 | escapeHtml | SAFE |
| ln-271bd489 | /catalog/category/view | catalog_category_entity_text.description | SK_HTTP_RESPONSE | 1.0 | **/* @noEscape */** | **RAW — admin→guest vector** |
| ln-08908789 | /catalog/product/view | catalog_product_entity_text.description | SK_HTTP_RESPONSE | 1.0 | **/* @noEscape */** | **RAW — admin→guest vector** |
| ln-222693c4 | /cms/page/view | cms_page.content | SK_HTTP_RESPONSE | 1.0 | **/* @noEscape */** | **RAW — admin→guest vector** |
| ln-b12634fb | any storefront page | cms_block.content | SK_HTTP_RESPONSE | 0.9 | **/* @noEscape */** | **RAW — BlockFilter renders verbatim** |
| ln-b53df249 | any CMS page/block | variable.html_value | SK_HTTP_RESPONSE | 0.9 | **/* @noEscape */** | **RAW — {{customVar code=...}} directive** |
| ln-a951d6ae | /checkout/cart/index | quote.coupon_code | SK_HTTP_RESPONSE | 0.9 | escapeHtmlAttr | SAFE |
| ln-82c6c954 | /checkout/index/index | quote_address.postcode | SK_HTTP_RESPONSE | 0.9 | escapeHtml | SAFE |
| ln-0c908afd | /rest/V1/guest-carts/{id}/totals | quote_address.firstname | SK_HTTP_RESPONSE | 0.9 | JSON encoded | REST — no HTML escaping |
| ln-58f350a8 | /rest/V1/guest-carts/{id}/totals | quote_address.lastname | SK_HTTP_RESPONSE | 0.9 | JSON encoded | REST — no HTML escaping |
| ln-45cf9441 | /rest/V1/guest-carts/{id}/totals | quote_address.street | SK_HTTP_RESPONSE | 0.9 | JSON encoded | REST — no HTML escaping |
| ln-2aabe9dd | /rest/V1/guest-carts/{id}/totals | quote_address.city | SK_HTTP_RESPONSE | 0.9 | JSON encoded | REST — no HTML escaping |
| ln-19ded5a6 | /rest/V1/guest-carts/{id}/totals | quote_address.email | SK_HTTP_RESPONSE | 0.9 | JSON encoded | REST — no HTML escaping |
| ln-72063ce1 | /checkout/cart/index | gift_message.message | SK_HTTP_RESPONSE | 0.9 | escapeHtml | SAFE |
| ln-81785309 | /checkout/cart/index | gift_message.sender | SK_HTTP_RESPONSE | 0.9 | getEscaped() in value= | **Needs attr injection check** |
| ln-14c1f55e | /checkout/cart/index | gift_message.recipient | SK_HTTP_RESPONSE | 0.9 | getEscaped() in value= | **Needs attr injection check** |
| ln-416b296b | /checkout/index/index | checkout_agreement.content | SK_HTTP_RESPONSE | 0.9 | **raw in modal** | **RAW — admin-trusted HTML** |
| ln-64e50661 | /checkout/onepage/success | sales_order_address.firstname | SK_HTTP_RESPONSE | 0.9 | escapeHtml via DefaultRenderer | SAFE |
| ln-b35ba579 | /sales/guest/view | sales_order_address.firstname | SK_HTTP_RESPONSE | 0.9 | escapeHtml via DefaultRenderer | SAFE |
| ln-9af9933f | /sales/order/view/order_id/{id} | sales_order_address.firstname | SK_HTTP_RESPONSE | 0.9 | escapeHtml | SAFE |
| ln-1be2488a | /sales/order/view/order_id/{id} | sales_order_status_history.comment | SK_HTTP_RESPONSE | 0.85 | **partial: [b,br,strong,i,u,a]** | **`<a>` href not scrubbed** |
| ln-52d9c65f | /sales/adminhtml/order/addcomment | sales_order_status_history.comment | SK_HTTP_RESPONSE | 0.9 | partial: [b,br,strong,i,u,a] | Admin-only view |
| ln-148edaa1 | /search/term/popular | search_query.query_text | SK_HTTP_RESPONSE | 0.9 | escapeHtml | SAFE |
| ln-e7fecd6b | /customer/adminhtml/index/edit | customer_entity.firstname | SK_HTTP_RESPONSE | 0.9 | escapeHtml | SAFE — admin only |
| ln-d6845bd4 | /customer/adminhtml/index/edit | customer_entity.email | SK_HTTP_RESPONSE | 0.9 | escapeHtml | SAFE — admin only |
| ln-1d159a4f | /customer/adminhtml/index/index | customer_entity.firstname | SK_HTTP_RESPONSE | 0.9 | escapeHtml | SAFE — admin only |
| ln-3c20400f | Newsletter send | newsletter_template.template_text | SK_EMAIL_RENDER | 0.9 | Magento template engine | Admin-authored |
| ln-13e8d237 | /wishlist/shared/index | wishlist_item.description | SK_HTTP_RESPONSE | 0.9 | escapeHtml | SAFE — shared link |
| ln-2e2dfb2d | /review/adminhtml/product/pending | review_detail.nickname | SK_HTTP_RESPONSE | 0.8 | escapeHtml | SAFE — admin only |
| ln-19279e2a | /search/adminhtml/term/index | search_query.query_text | SK_HTTP_RESPONSE | 0.8 | escapeHtml via UI grid | SAFE — admin only |
| ln-0643b0b5 | /newsletter/adminhtml/subscriber/index | newsletter_subscriber.subscriber_email | SK_HTTP_RESPONSE | 0.8 | escapeHtml | SAFE — admin only |
| ln-2ef05ebd | /newsletter/manage/index | newsletter_subscriber.subscriber_email | SK_HTTP_RESPONSE | 0.7 | not rendered as text | Low confidence |

---

## L3 Lineages (2) — Two Persistence Boundaries

| Lineage ID | Entry Route | Chain | Final Sink | Confidence | Notes |
|---|---|---|---|---|---|
| ln-6bb6cccb | POST /customer/account/createpost?firstname | customer_entity.firstname → sales_order_address.firstname | SK_HTTP_RESPONSE at /checkout/onepage/success | 0.85 | escapeHtml — SAFE |
| ln-89c79721 | POST /customer/account/createpost?email | customer_entity.email → sales_order_address.email | SK_HTTP_RESPONSE at /checkout/onepage/success | 0.85 | escapeHtml — SAFE |

---

## Stores With Raw / Partial HTML Rendering (priority targets)

| Store | Route | Escaping | Risk |
|---|---|---|---|
| catalog_product_entity_text.description | /catalog/product/view | `/* @noEscape */` | Admin→guest stored XSS |
| catalog_category_entity_text.description | /catalog/category/view | `/* @noEscape */` | Admin→guest stored XSS |
| cms_page.content | /cms/page/view | `/* @noEscape */` | Admin→guest stored XSS |
| cms_block.content | any page with {{block id=...}} | `/* @noEscape */` BlockFilter | Admin→guest stored XSS |
| variable.html_value | any CMS page with {{customVar code=...}} | raw via Variable::getValue() | Admin→guest stored XSS |
| checkout_agreement.content | /checkout/index/index | raw in modal | Admin→guest stored XSS |
| sales_order_status_history.comment | /sales/order/view, /checkout/onepage/success | partial [b,br,strong,i,u,a] | `<a href=...>` not scrubbed |
| gift_message.sender | /checkout/cart/index | getEscaped() in value= attr | Attr injection — needs verification |
| gift_message.recipient | /checkout/cart/index | getEscaped() in value= attr | Attr injection — needs verification |

---

## Coverage Summary

| Dimension | Value |
|---|---|
| Total lineages | 88 |
| Distinct HTTP entry routes with L1 | ~35 |
| Distinct persistence stores | 32 |
| Stores with raw/partial output | 9 |
| Stores confirmed SAFE at output | 23 |
| Deferred (non-string stores) | 1,013 |
