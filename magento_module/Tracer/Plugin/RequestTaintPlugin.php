<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Booyah\Tracer\Model\TaintRegistry;
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

    public function beforeDispatch(object $subject, RequestInterface $request): array
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') {
            return [$request];
        }

        // ── 1. Query string and form POST params ──────────────────────────────
        foreach ($request->getParams() as $name => $value) {
            if (!is_string($value)) continue;
            $this->maybeRegister($value, 'http_param::' . $name, (string)$name);
        }

        // ── 2. Raw JSON body (REST API calls send tainted values here) ────────
        // getContent() reads php://input; only available once per request but
        // Laminas caches it internally so multiple reads are safe.
        $body = '';
        if (method_exists($request, 'getContent')) {
            $body = (string)$request->getContent();
        }
        if ($body !== '') {
            $this->scanBodyForTaints($body);
        }

        // Role is set by SetRoleObserver on controller_action_predispatch — do not set it here.
        // Setting it here would stamp every request as 'anonymous' before the observer fires.

        return [$request];
    }

    /**
     * Register a single value if it starts with a probe prefix.
     */
    private function maybeRegister(string $value, string $source, string $paramName): void
    {
        foreach (self::PROBE_PREFIXES as $prefix) {
            if (str_starts_with($value, $prefix)) {
                TaintRegistry::register(
                    $value,
                    hash('sha256', $value),
                    'http_param',
                    $paramName,
                    '',
                    0
                );
                \Booyah\Tracer\Probe::source('http_param::' . $paramName, $paramName, $value, '', 0);
                return;
            }
        }
    }

    /**
     * Recursively walk a JSON-decoded body and register any bSRC_/BSYH values.
     * Falls back to regex scan on the raw string if JSON decode fails (form-encoded, multipart, etc.).
     */
    private function scanBodyForTaints(string $body): void
    {
        $decoded = json_decode($body, true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
            $this->walkArray($decoded, 'json_body');
        } else {
            // Raw body: extract any probe-prefixed tokens via regex
            $pattern = '/(' . implode('|', array_map('preg_quote', self::PROBE_PREFIXES)) . ')\S+/';
            if (preg_match_all($pattern, $body, $matches)) {
                foreach ($matches[0] as $value) {
                    $this->maybeRegister($value, 'http_body', 'http_body');
                }
            }
        }
    }

    /**
     * Recursively walk a decoded JSON array/object and register tainted string values.
     */
    private function walkArray(array $arr, string $path): void
    {
        foreach ($arr as $key => $value) {
            $childPath = $path . '.' . $key;
            if (is_string($value)) {
                $this->maybeRegister($value, $childPath, $childPath);
            } elseif (is_array($value)) {
                $this->walkArray($value, $childPath);
            }
        }
    }
}
