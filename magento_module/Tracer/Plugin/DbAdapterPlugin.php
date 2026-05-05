<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Booyah\Tracer\Model\TaintLogger;
use Booyah\Tracer\Model\TaintRegistry;
use Magento\Framework\DB\Adapter\Pdo\Mysql;

/**
 * Intercepts Magento's DB adapter to detect tainted values crossing the persistence boundary.
 *
 * Recursion guard: all methods set $inPlugin = true before doing any work that touches the DB,
 * so re-entrant calls from lookupPersistedTaint / logWrite are silently ignored.
 *
 * Activation: only active when BOOYAH_TAINT_ENABLED=1 is set in the environment.
 * The crawl script sets this env var per-request via FastCGI params.
 */
class DbAdapterPlugin
{
    private const SKIP_TABLES = ['booyah_taint_map', 'booyah_confirmed_paths', 'booyah_unconfirmed_paths'];

    /** Re-entry guard — prevents plugin from triggering itself through lookupPersistedTaint */
    private static bool $inPlugin = false;

    private TaintLogger $logger;

    public function __construct(TaintLogger $logger)
    {
        $this->logger = $logger;
    }

    // ---- WRITE side ----

    public function beforeInsert(Mysql $subject, string $table, array $data): array
    {
        if (self::$inPlugin || !$this->isEnabled() || in_array($table, self::SKIP_TABLES, true)) {
            return [$table, $data];
        }
        // Only check if there are active taint IDs — skips all overhead on unprobed requests
        if (empty(TaintRegistry::allTaintIds())) {
            return [$table, $data];
        }
        self::$inPlugin = true;
        try {
            foreach ($data as $column => $value) {
                if (!is_string($value) || $value === '') continue;
                $taintId = TaintRegistry::lookup($this->hash($value));
                if ($taintId !== null) {
                    $this->logger->logWrite($taintId, 'db', $table, (string)$column, '', '', 0);
                }
            }
        } finally {
            self::$inPlugin = false;
        }
        return [$table, $data];
    }

    public function beforeUpdate(Mysql $subject, string $table, array $bind, $where = ''): array
    {
        if (self::$inPlugin || !$this->isEnabled() || in_array($table, self::SKIP_TABLES, true)) {
            return [$table, $bind, $where];
        }
        if (empty(TaintRegistry::allTaintIds())) {
            return [$table, $bind, $where];
        }
        self::$inPlugin = true;
        try {
            foreach ($bind as $column => $value) {
                if (!is_string($value) || $value === '') continue;
                $taintId = TaintRegistry::lookup($this->hash($value));
                if ($taintId !== null) {
                    $rowKey = is_string($where) ? substr($where, 0, 128) : '';
                    $this->logger->logWrite($taintId, 'db', $table, (string)$column, $rowKey, '', 0);
                }
            }
        } finally {
            self::$inPlugin = false;
        }
        return [$table, $bind, $where];
    }

    // ---- READ side ----

    public function afterFetchAll(Mysql $subject, array $result): array
    {
        if (self::$inPlugin || !$this->isEnabled()) return $result;
        // Skip if no cross-request taints have been registered (nothing to match against)
        if (!TaintRegistry::hasCrossRequestTaints()) return $result;
        self::$inPlugin = true;
        try {
            $this->checkReadResult($result);
        } finally {
            self::$inPlugin = false;
        }
        return $result;
    }

    public function afterFetchRow(Mysql $subject, $result): mixed
    {
        if (self::$inPlugin || !$this->isEnabled() || !is_array($result)) return $result;
        if (!TaintRegistry::hasCrossRequestTaints()) return $result;
        self::$inPlugin = true;
        try {
            $this->checkReadResult([$result]);
        } finally {
            self::$inPlugin = false;
        }
        return $result;
    }

    public function afterFetchOne(Mysql $subject, $result): mixed
    {
        if (self::$inPlugin || !$this->isEnabled() || !is_string($result) || $result === '') return $result;
        if (!TaintRegistry::hasCrossRequestTaints()) return $result;
        self::$inPlugin = true;
        try {
            $this->checkSingleValue($result, '', '', '');
        } finally {
            self::$inPlugin = false;
        }
        return $result;
    }

    public function afterFetchCol(Mysql $subject, array $result): array
    {
        if (self::$inPlugin || !$this->isEnabled()) return $result;
        if (!TaintRegistry::hasCrossRequestTaints()) return $result;
        self::$inPlugin = true;
        try {
            foreach ($result as $value) {
                if (is_string($value) && $value !== '') {
                    $this->checkSingleValue($value, '', '', '');
                }
            }
        } finally {
            self::$inPlugin = false;
        }
        return $result;
    }

    // ---- Helpers ----

    private function checkReadResult(array $rows): void
    {
        foreach ($rows as $row) {
            if (!is_array($row)) continue;
            foreach ($row as $column => $value) {
                if (!is_string($value) || $value === '') continue;
                $this->checkSingleValue($value, '', (string)$column, '');
            }
        }
    }

    private function checkSingleValue(string $value, string $table, string $column, string $rowKey): void
    {
        $hash = $this->hash($value);
        $writeEvents = $this->logger->lookupPersistedTaint($hash);
        foreach ($writeEvents as $event) {
            $taintId = $event['taint_id'];
            TaintRegistry::propagate($taintId, $hash, 'db:' . $event['db_table'] . '.' . $event['db_column']);
            $this->logger->logRead($taintId, 'db', $table ?: $event['db_table'], $column, $rowKey);
        }
    }

    private function hash(mixed $value): string
    {
        return hash('sha256', (string)$value);
    }

    /**
     * Only active when BOOYAH_TAINT_ENABLED=1 is explicitly set.
     * The crawl script injects this via FastCGI env or sets it on the PHP-FPM pool.
     */
    private function isEnabled(): bool
    {
        return getenv('BOOYAH_TAINT_ENABLED') === '1';
    }
}
