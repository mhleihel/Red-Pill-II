<?php
declare(strict_types=1);

namespace Booyah\Tracer\Observer;

use Booyah\Tracer\Model\TaintRegistry;
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
 *   2. adminhtml/admin route prefix → "admin"
 *   3. Frontend + logged-in Magento customer session → "authenticated"
 *   4. Frontend + no session → "anonymous"
 *
 * Triggered on controller_action_predispatch (fires before every controller).
 */
class SetRoleObserver implements ObserverInterface
{
    private CustomerSession $customerSession;

    public function __construct(CustomerSession\Proxy $customerSession)
    {
        // Proxy breaks circular DI: CustomerSession depends on the request,
        // which is available by predispatch time but not at construction time.
        $this->customerSession = $customerSession;
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

            // 2. Admin area detection
            $routeName = $request->getRouteName() ?? '';
            if (str_starts_with($routeName, 'adminhtml') || str_starts_with($routeName, 'admin')) {
                TaintRegistry::setRole('admin');
                return;
            }

            // 3. Authenticated frontend customer
            if ($this->customerSession->isLoggedIn()) {
                TaintRegistry::setRole('authenticated');
                return;
            }

            // 4. Anonymous frontend
            TaintRegistry::setRole('anonymous');

        } catch (\Throwable $e) {
            // Never let role detection crash the application.
            // Fall back to anonymous so taint events are still recorded.
            TaintRegistry::setRole('anonymous');
        }
    }
}
