<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Booyah\Tracer\Model\TaintLogger;
use Booyah\Tracer\Model\TaintRegistry;

/**
 * Intercepts Magento's cache frontend to track tainted values through cache.
 *
 * Recursion guard: $inPlugin prevents re-entry via lookupPersistedTaint's DB calls.
 * Activation: only active when BOOYAH_TAINT_ENABLED=1.
 */
class CachePlugin
{
    private static bool $inPlugin = false;

    private TaintLogger $logger;

    public function __construct(TaintLogger $logger)
    {
        $this->logger = $logger;
    }

    public function beforeSave(
        \Magento\Framework\Cache\Frontend\Adapter\Zend $subject,
        string $data,
        string $identifier,
        array  $tags = [],
        ?int   $lifeTime = null
    ): array {
        if (self::$inPlugin || !$this->isEnabled() || empty(TaintRegistry::allTaintIds())) {
            return [$data, $identifier, $tags, $lifeTime];
        }
        self::$inPlugin = true;
        try {
            $hash = hash('sha256', $data);
            $taintId = TaintRegistry::lookup($hash);
            if ($taintId !== null) {
                $this->logger->logWrite($taintId, 'cache', 'cache', 'data', $identifier, '', 0);
            }
        } finally {
            self::$inPlugin = false;
        }
        return [$data, $identifier, $tags, $lifeTime];
    }

    public function afterLoad(
        \Magento\Framework\Cache\Frontend\Adapter\Zend $subject,
        $result,
        string $identifier
    ): mixed {
        if (self::$inPlugin || !$this->isEnabled() || !is_string($result) || $result === '') return $result;
        if (!TaintRegistry::hasCrossRequestTaints()) return $result;
        self::$inPlugin = true;
        try {
            $hash = hash('sha256', $result);
            $writeEvents = $this->logger->lookupPersistedTaint($hash);
            foreach ($writeEvents as $event) {
                TaintRegistry::propagate($event['taint_id'], $hash, 'cache:' . $identifier);
                $this->logger->logRead($event['taint_id'], 'cache', 'cache', 'data', $identifier);
            }
        } finally {
            self::$inPlugin = false;
        }
        return $result;
    }

    private function isEnabled(): bool
    {
        return getenv('BOOYAH_TAINT_ENABLED') === '1';
    }
}
