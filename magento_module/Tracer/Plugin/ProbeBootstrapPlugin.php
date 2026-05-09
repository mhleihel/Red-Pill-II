<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Booyah\Tracer\Probe;
use Magento\Framework\App\FrontController;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\App\ResponseInterface;

/**
 * Wires Probe lifecycle into each HTTP request.
 *
 * beforeDispatch → Probe::startup() (idempotent) + Probe::initRequest()
 * finalizeRequest is deferred to register_shutdown_function so it fires
 * AFTER layout rendering completes (rendering happens after dispatch returns).
 *
 * Only active when BOOYAH_TAINT_ENABLED=1.
 */
class ProbeBootstrapPlugin
{
    private static bool $started      = false;
    private static bool $shutdownHooked = false;

    public function beforeDispatch(FrontController $subject, RequestInterface $request): array
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') {
            return [$request];
        }

        if (!self::$started) {
            Probe::startup();
            self::$started = true;
        }

        $actor = getenv('BOOYAH_ROLE') ?: 'unknown';

        Probe::initRequest(
            $request->getMethod(),
            (string) $request->getRequestUri(),
            $actor
        );

        if (!self::$shutdownHooked) {
            register_shutdown_function(static function () {
                Probe::finalizeRequest(200);
            });
            self::$shutdownHooked = true;
        }

        return [$request];
    }

    public function afterDispatch(FrontController $subject, $response)
    {
        return $response;
    }
}
