<?php
declare(strict_types=1);

namespace Booyah\Tracer\Observer;

use Booyah\Tracer\Model\TaintRegistry;
use Magento\Backend\Model\Auth\Session as BackendSession;
use Magento\Customer\Model\Session as CustomerSession;
use Magento\Framework\Event\Observer;
use Magento\Framework\Event\ObserverInterface;

/**
 * Detects the current request role and sets it in TaintRegistry so all taint
 * events are labelled correctly.
 *
 * Role resolution order (first match wins):
 *   1. BOOYAH_ROLE env var — explicit override for automated crawl sessions.
 *      Do NOT set this at the container level; it will mask all dynamic detection.
 *   2. Backend admin session active → "admin"
 *      (covers ALL adminhtml routes regardless of routeId; cms, catalog, sales,
 *       customer, etc. all have their own routeIds that do NOT start with "admin")
 *   3. Route name prefix "adminhtml"/"admin" → "admin"
 *      (fast path for Backend module routes before session is loaded)
 *   4. Frontend + logged-in Magento customer session → "authenticated"
 *   5. Frontend + no session → "anonymous"
 *
 * Triggered on controller_action_predispatch (fires before every controller).
 */
class SetRoleObserver implements ObserverInterface
{
    private CustomerSession $customerSession;
    private BackendSession $backendSession;

    public function __construct(
        CustomerSession\Proxy $customerSession,
        BackendSession\Proxy $backendSession
    ) {
        // Proxies break circular DI: both sessions depend on the request,
        // which is available by predispatch time but not at construction time.
        $this->customerSession = $customerSession;
        $this->backendSession  = $backendSession;
    }

    public function execute(Observer $observer): void
    {
        try {
            // 1. Explicit env override (automated crawl sessions only)
            $envRole = getenv('BOOYAH_ROLE');
            if ($envRole !== false && $envRole !== '') {
                TaintRegistry::setRole($envRole);
                return;
            }

            $request = $observer->getEvent()->getRequest();
            if (!$request) {
                return;
            }

            // 2. Route name fast path — catches Backend module routes (routeId=adminhtml)
            //    without loading the backend session object.
            $routeName = $request->getRouteName() ?? '';
            if (str_starts_with($routeName, 'adminhtml') || str_starts_with($routeName, 'admin')) {
                TaintRegistry::setRole('admin');
                return;
            }

            // 3. Backend session check — catches ALL other adminhtml routes (cms, catalog,
            //    sales, customer, review, etc.) whose routeIds do NOT start with "admin".
            //    isLoggedIn() is cheap after the session is already loaded by the auth layer.
            if ($this->backendSession->isLoggedIn()) {
                TaintRegistry::setRole('admin');
                return;
            }

            // 4. Authenticated frontend customer
            if ($this->customerSession->isLoggedIn()) {
                TaintRegistry::setRole('authenticated');
                return;
            }

            // 5. Anonymous frontend
            TaintRegistry::setRole('anonymous');

        } catch (\Throwable $e) {
            // Never let role detection crash the application.
            TaintRegistry::setRole('anonymous');
        }
    }
}
