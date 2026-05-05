<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Booyah\Tracer\Model\TaintLogger;
use Booyah\Tracer\Model\TaintRegistry;
use Magento\Framework\Session\SessionManager;

/**
 * Intercepts session reads/writes to track tainted values through session storage.
 * Session is a key second-order channel for customer-facing flows (cart, checkout, forms).
 */
class SessionPlugin
{
    private TaintLogger $logger;

    public function __construct(TaintLogger $logger)
    {
        $this->logger = $logger;
    }

    // ---- WRITE side: setData ----

    public function beforeSetData(SessionManager $subject, $key, $value = null): array
    {
        if (!$this->isEnabled()) return [$key, $value];
        $this->scanForTaint($value, (string)$key);
        return [$key, $value];
    }

    // ---- READ side: getData ----

    public function afterGetData(SessionManager $subject, $result, $key = ''): mixed
    {
        if (!$this->isEnabled()) return $result;
        $this->propagateFromPersistence($result, (string)$key);
        return $result;
    }

    // ---- Internal helpers ----

    private function scanForTaint(mixed $value, string $key): void
    {
        foreach ($this->flatten($value) as $scalar) {
            if (!is_string($scalar) || $scalar === '') continue;
            $hash = hash('sha256', $scalar);
            $taintId = TaintRegistry::lookup($hash);
            if ($taintId !== null) {
                $this->logger->logWrite($taintId, 'session', 'session', $key, $key, '', 0);
            }
        }
    }

    private function propagateFromPersistence(mixed $value, string $key): void
    {
        foreach ($this->flatten($value) as $scalar) {
            if (!is_string($scalar) || $scalar === '') continue;
            $hash = hash('sha256', $scalar);
            $writes = $this->logger->lookupPersistedTaint($hash);
            foreach ($writes as $event) {
                TaintRegistry::propagate($event['taint_id'], $hash, 'session:' . $key);
                $this->logger->logRead($event['taint_id'], 'session', 'session', $key, $key);
            }
        }
    }

    private function flatten(mixed $value): array
    {
        if (is_scalar($value)) return [$value];
        if (!is_array($value)) return [];
        $result = [];
        array_walk_recursive($value, function ($v) use (&$result) { $result[] = $v; });
        return $result;
    }

    private function isEnabled(): bool
    {
        return (bool)(getenv('BOOYAH_TAINT_ENABLED') ?: true);
    }
}
