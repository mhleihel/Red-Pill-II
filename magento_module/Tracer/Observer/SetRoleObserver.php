<?php
declare(strict_types=1);

namespace Booyah\Tracer\Observer;

use Booyah\Tracer\Model\TaintRegistry;
use Magento\Framework\Event\Observer;
use Magento\Framework\Event\ObserverInterface;

/**
 * Detects the current request role (anonymous / customer / admin_*) and
 * sets it in TaintRegistry so all taint events are labelled correctly.
 *
 * Triggered on controller_action_predispatch (fires before every controller).
 */
class SetRoleObserver implements ObserverInterface
{
    public function execute(Observer $observer): void
    {
        try {
            // BOOYAH_ROLE env var set by the crawl script per-session
            $envRole = getenv('BOOYAH_ROLE');
            if ($envRole) {
                TaintRegistry::setRole($envRole);
                return;
            }

            $request = $observer->getEvent()->getRequest();
            if (!$request) return;

            $areaCode = $request->getRouteName() ?? '';
            if (str_starts_with($areaCode, 'adminhtml') || str_starts_with($areaCode, 'admin')) {
                TaintRegistry::setRole('admin');
            } else {
                TaintRegistry::setRole('anonymous');
            }
        } catch (\Throwable $e) {
            // Never crash the application
        }
    }
}
