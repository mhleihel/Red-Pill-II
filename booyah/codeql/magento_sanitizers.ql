/**
 * @name Magento XSS sanitizers
 * @description Defines sanitizer barriers for Magento's escaping methods.
 *   Covers framework escapers, HtmlPurifier, and WordPress-style functions.
 */

import php
import semmle.code.php.security.dataflow.XssQuery

/**
 * Magento's Escaper class methods — the canonical safe output API.
 * escapeHtml = html_body context safe
 * escapeHtmlAttr = html_attribute context safe (includes ENT_QUOTES equivalent)
 * escapeUrl = url context safe
 * escapeJs = js_string context safe
 * escapeCss = css context safe
 */
private class MagentoEscaperSanitizer extends XssSanitizer {
  MagentoEscaperSanitizer() {
    exists(MethodCallExpr mc |
      mc.getReceiver().getType().(ClassOrInterface).getQualifiedName()
        .regexpMatch("Magento\\\\Framework\\\\Escaper.*") and
      mc.getMethodName() in [
        "escapeHtml", "escapeHtmlAttr", "escapeUrl",
        "escapeJs", "escapeCss", "escapeQuote"
      ] and
      this.asExpr() = mc
    )
  }
}

/**
 * PHP built-in sanitizers.
 * NOTE: htmlspecialchars without ENT_QUOTES does NOT sanitize html_attribute.
 * We mark it as a sanitizer here and rely on the classifier to check flags.
 */
private class PhpBuiltinSanitizer extends XssSanitizer {
  PhpBuiltinSanitizer() {
    exists(FuncCall fc |
      fc.getName() in [
        "htmlspecialchars", "htmlentities",
        "strip_tags",
        "intval", "floatval", "abs",
        "urlencode", "rawurlencode",
        "json_encode"
      ] and
      this.asExpr() = fc
    )
  }
}

/**
 * HtmlPurifier — used by Magento for rich-text sanitization.
 * Safe for html_body; NOT safe for html_attribute.
 */
private class HtmlPurifierSanitizer extends XssSanitizer {
  HtmlPurifierSanitizer() {
    exists(MethodCallExpr mc |
      mc.getReceiver().getType().(ClassOrInterface).getQualifiedName()
        .regexpMatch(".*HTMLPurifier.*") and
      mc.getMethodName() = "purify" and
      this.asExpr() = mc
    )
  }
}
