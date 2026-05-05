<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Booyah\Tracer\Model\TaintLogger;
use Booyah\Tracer\Model\TaintRegistry;
use Magento\Framework\Session\SessionManager;

/**
 * Intercepts session reads/writes to track tainted values through session storage.
 *
 * Recursion guard: $inPlugin prevents re-entry via lookupPersistedTaint's DB calls.
 * Activation: only active when BOOYAH_TAINT_ENABLED=1.
 */
class SessionPlugin
{
    private static bool $inPlugin = false;

    private TaintLogger $logger;

    public function __construct(TaintLogger $logger)
    {
        $this->logger = $logger;
    }

    public function beforeSetData(SessionManager $subject, $key, $value = null): array
    {
        if (self::$inPlugin || !$this->isEnabled() || empty(TaintRegistry::allTaintIds())) {
            return [$key, $value];
        }
        self::$inPlugin = true;
        try {
            $this->scanForTaint($value, (string)$key);
        } finally {
            self::$inPlugin = false;
        }
        return [$key, $value];
    }

    public function afterGetData(SessionManager $subject, $result, $key = ''): mixed
    {
        if (self::$inPlugin || !$this->isEnabled()) return $result;
        if (!TaintRegistry::hasCrossRequestTaints()) return $result;
        self::$inPlugin = true;
        try {
            $this->propagateFromPersistence($result, (string)$key);
        } finally {
            self::$inPlugin = false;
        }
        return $result;
    }

    private function scanForTaint(mixed $value, string $key): void
    {
        foreach ($this->flatten($value) as $scalar) {
            if (!is_string($scalar) || $scalar === '') continue;
            $taintId = TaintRegistry::lookup(hash('sha256', $scalar));
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
        return getenv('BOOYAH_TAINT_ENABLED') === '1';
    }
}
