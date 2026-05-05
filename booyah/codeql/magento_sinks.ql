/**
 * @name Magento XSS output sinks
 * @description Extends XssSink with Magento template and block output methods.
 *   Covers both unescaped (dangerous) and escaped sinks for classification.
 */

import php
import semmle.code.php.security.dataflow.XssQuery

/**
 * Magento block toHtml() — the primary rendering path.
 * Any return value that reaches the HTTP response body.
 */
private class MagentoBlockOutputSink extends XssSink {
  MagentoBlockOutputSink() {
    exists(MethodCallExpr mc |
      mc.getMethodName() in ["_toHtml", "toHtml", "getChildHtml", "getChildChildHtml"] and
      this.asExpr() = mc.getAnArgument()
    )
  }
}

/**
 * Direct PHP output functions — always sinks.
 */
private class PhpOutputSink extends XssSink {
  PhpOutputSink() {
    exists(EchoStatement es | this.asExpr() = es.getAnExpr())
    or
    exists(PrintIntrinsic pi | this.asExpr() = pi.getExpr())
    or
    exists(FuncCall fc |
      fc.getName() in ["printf", "fprintf", "vprintf"] and
      this.asExpr() = fc.getAnArgument()
    )
  }
}

/**
 * header() Location redirect — URL injection sink.
 */
private class HeaderLocationSink extends XssSink {
  HeaderLocationSink() {
    exists(FuncCall fc |
      fc.getName() = "header" and
      fc.getArgument(0).(StringLiteral).getValue().regexpMatch("(?i)location:.*") and
      this.asExpr() = fc.getArgument(0)
    )
  }
}

/**
 * Magento JSON result — output goes to HTTP response body as JSON,
 * which may be reflected into DOM by client JS.
 */
private class MagentoJsonResultSink extends XssSink {
  MagentoJsonResultSink() {
    exists(MethodCallExpr mc |
      mc.getReceiver().getType().(ClassOrInterface).getQualifiedName()
        .regexpMatch("Magento\\\\Framework\\\\Controller\\\\Result\\\\Json.*") and
      mc.getMethodName() = "setData" and
      this.asExpr() = mc.getAnArgument()
    )
  }
}
