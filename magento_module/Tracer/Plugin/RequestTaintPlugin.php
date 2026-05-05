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
    private const PROBE_PREFIX = 'bSRC';

    public function beforeDispatch(FrontController $subject, RequestInterface $request): array
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') {
            return [$request];
        }

        foreach ($request->getParams() as $name => $value) {
            if (!is_string($value)) continue;
            if (!str_starts_with($value, self::PROBE_PREFIX)) continue;
            TaintRegistry::register(
                $value,
                hash('sha256', $value),
                'http_param',
                (string)$name,
                '',
                0
            );
        }

        TaintRegistry::setRole(getenv('BOOYAH_ROLE') ?: 'anonymous');

        return [$request];
    }
}
