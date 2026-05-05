<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Booyah\Tracer\Model\TaintLogger;
use Booyah\Tracer\Model\TaintRegistry;
use Zend_Cache_Backend;

/**
 * Intercepts Magento's cache frontend to track tainted values through cache.
 * Cache is a major second-order channel: data is written with one request,
 * served to thousands of subsequent requests from cache.
 */
class CachePlugin
{
    private TaintLogger $logger;

    public function __construct(TaintLogger $logger)
    {
        $this->logger = $logger;
    }

    // ---- WRITE side ----

    public function beforeSave(
        \Magento\Framework\Cache\Frontend\Adapter\Zend $subject,
        string $data,
        string $identifier,
        array  $tags = [],
        ?int   $lifeTime = null
    ): array {
        if (!$this->isEnabled()) return [$data, $identifier, $tags, $lifeTime];
        $hash = $this->hash($data);
        $taintId = TaintRegistry::lookup($hash);
        if ($taintId !== null) {
            $this->logger->logWrite($taintId, 'cache', 'cache', 'data', $identifier, '', 0);
        }
        return [$data, $identifier, $tags, $lifeTime];
    }

    // ---- READ side ----

    public function afterLoad(
        \Magento\Framework\Cache\Frontend\Adapter\Zend $subject,
        $result,
        string $identifier
    ): mixed {
        if (!$this->isEnabled() || !is_string($result) || $result === '') return $result;
        $hash = $this->hash($result);
        $writeEvents = $this->logger->lookupPersistedTaint($hash);
        foreach ($writeEvents as $event) {
            TaintRegistry::propagate($event['taint_id'], $hash, 'cache:' . $identifier);
            $this->logger->logRead($event['taint_id'], 'cache', 'cache', 'data', $identifier);
        }
        return $result;
    }

    private function hash(string $value): string
    {
        return hash('sha256', $value);
    }

    private function isEnabled(): bool
    {
        return (bool)(getenv('BOOYAH_TAINT_ENABLED') ?: true);
    }
}
