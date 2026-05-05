/**
 * @name Magento HTTP input sources
 * @description Extends RemoteFlowSource with Magento framework request methods.
 *   Works for any class implementing RequestInterface — covers custom subclasses
 *   and virtual types without listing concrete class names.
 */

import php
import semmle.code.php.dataflow.TaintTracking
import semmle.code.php.security.dataflow.RemoteFlowSources

/**
 * Any method call on a receiver whose declared type (or any ancestor)
 * implements Magento\Framework\App\RequestInterface.
 */
private class MagentoRequestInterface extends Interface {
  MagentoRequestInterface() {
    this.getQualifiedName() = "Magento\\Framework\\App\\RequestInterface"
  }
}

private class MagentoRequestSource extends RemoteFlowSource {
  MagentoRequestSource() {
    exists(MethodCallExpr mc |
      // The receiver implements RequestInterface (directly or via inheritance)
      mc.getReceiver().getType().(ClassOrInterface).getAnAncestor() instanceof MagentoRequestInterface and
      // Any of the data-returning methods
      mc.getMethodName() in [
        "getParam", "getParams",
        "getPost", "getQuery",
        "getContent", "getBodyParams",
        "getHeader", "getHeaders",
        "getCookie",
        "getPathInfo", "getRequestUri",
        "getServer"
      ] and
      this.asExpr() = mc
    )
  }

  override string getSourceType() { result = "Magento HTTP request parameter" }
}

/**
 * Also cover the $_REQUEST, $_GET, $_POST superglobal array access patterns
 * used in legacy Magento code and third-party modules.
 */
private class PhpSuperglobalSource extends RemoteFlowSource {
  PhpSuperglobalSource() {
    exists(VariableAccess va |
      va.getName() in ["_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER"] and
      this.asExpr() = va
    )
  }

  override string getSourceType() { result = "PHP superglobal" }
}

/**
 * REST API input: Magento\Framework\Webapi\Rest\Request
 * These arrive as JSON body or query string params in REST/GraphQL calls.
 */
private class MagentoWebapiRequestSource extends RemoteFlowSource {
  MagentoWebapiRequestSource() {
    exists(MethodCallExpr mc |
      mc.getReceiver().getType().(ClassOrInterface).getQualifiedName()
        .regexpMatch("Magento\\\\Framework\\\\Webapi\\\\.*Request.*") and
      mc.getMethodName() in ["getBodyParams", "getParam", "getContent", "getRequestData"] and
      this.asExpr() = mc
    )
  }

  override string getSourceType() { result = "Magento Webapi REST request" }
}
