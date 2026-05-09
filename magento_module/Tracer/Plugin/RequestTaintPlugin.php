<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Booyah\Tracer\Model\TaintRegistry;
use Magento\Framework\App\FrontController;
use Magento\Framework\App\RequestInterface;

/**
 * Registers Booyah probe values arriving in HTTP request params into TaintRegistry.
 *
 * This replaces the AST instrumentation layer for crawl purposes:
 * probe values (bSRC_* prefix) injected by multi_order_crawl.py are registered
 * as taint sources so the session plugin can detect when they propagate.
 *
 * Only active when BOOYAH_TAINT_ENABLED=1.
 * Only registers values starting with the probe prefix — not all parameters.
 */
class RequestTaintPlugin
{
    private const PROBE_PREFIXES = ['bSRC', 'BSYH'];

    public function beforeDispatch(FrontController $subject, RequestInterface $request): array
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') {
            return [$request];
        }

        foreach ($request->getParams() as $name => $value) {
            if (!is_string($value)) continue;
            $matched = false;
            foreach (self::PROBE_PREFIXES as $prefix) {
                if (str_starts_with($value, $prefix)) { $matched = true; break; }
            }
            if (!$matched) continue;
            TaintRegistry::register(
                $value,
                hash('sha256', $value),
                'http_param',
                (string)$name,
                '',
                0
            );
            \Booyah\Tracer\Probe::source('http_param::' . $name, $name, $value, '', 0);
        }

        // Role is set by SetRoleObserver on controller_action_predispatch — do not set it here.
        // Setting it here would stamp every request as 'anonymous' before the observer fires.

        return [$request];
    }
}
