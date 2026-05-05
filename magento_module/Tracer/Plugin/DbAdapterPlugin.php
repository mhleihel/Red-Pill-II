<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Booyah\Tracer\Model\TaintLogger;
use Booyah\Tracer\Model\TaintRegistry;
use Magento\Framework\DB\Adapter\Pdo\Mysql;

/**
 * Intercepts Magento's DB adapter to:
 *   - WRITE side: detect tainted values being persisted and log them
 *   - READ side:  detect if returned values were previously tainted, propagate into TaintRegistry
 *
 * Skips all booyah_* tables to prevent recursion.
 * Never throws — all failures are silently swallowed to keep the application running.
 */
class DbAdapterPlugin
{
    private const SKIP_TABLES = ['booyah_taint_map', 'booyah_confirmed_paths', 'booyah_unconfirmed_paths'];

    private TaintLogger $logger;

    public function __construct(TaintLogger $logger)
    {
        $this->logger = $logger;
    }

    // ---- WRITE side: insert() ----

    public function beforeInsert(Mysql $subject, string $table, array $data): array
    {
        if (!$this->isEnabled() || in_array($table, self::SKIP_TABLES, true)) {
            return [$table, $data];
        }
        foreach ($data as $column => $value) {
            if (!is_string($value) || $value === '') continue;
            $hash = $this->hash($value);
            $taintId = TaintRegistry::lookup($hash);
            if ($taintId !== null) {
                $this->logger->logWrite($taintId, 'db', $table, (string)$column, '', '', 0);
            }
        }
        return [$table, $data];
    }

    public function beforeUpdate(Mysql $subject, string $table, array $bind, $where = ''): array
    {
        if (!$this->isEnabled() || in_array($table, self::SKIP_TABLES, true)) {
            return [$table, $bind, $where];
        }
        foreach ($bind as $column => $value) {
            if (!is_string($value) || $value === '') continue;
            $hash = $this->hash($value);
            $taintId = TaintRegistry::lookup($hash);
            if ($taintId !== null) {
                $rowKey = is_string($where) ? substr($where, 0, 128) : '';
                $this->logger->logWrite($taintId, 'db', $table, (string)$column, $rowKey, '', 0);
            }
        }
        return [$table, $bind, $where];
    }

    // ---- READ side: fetchAll / fetchRow / fetchOne ----

    public function afterFetchAll(Mysql $subject, array $result): array
    {
        if (!$this->isEnabled()) return $result;
        $this->checkReadResult($result);
        return $result;
    }

    public function afterFetchRow(Mysql $subject, $result): mixed
    {
        if (!$this->isEnabled() || !is_array($result)) return $result;
        $this->checkReadResult([$result]);
        return $result;
    }

    public function afterFetchOne(Mysql $subject, $result): mixed
    {
        if (!$this->isEnabled() || !is_string($result) || $result === '') return $result;
        $this->checkSingleValue($result, '', '', '');
        return $result;
    }

    public function afterFetchCol(Mysql $subject, array $result): array
    {
        if (!$this->isEnabled()) return $result;
        foreach ($result as $value) {
            if (is_string($value) && $value !== '') {
                $this->checkSingleValue($value, '', '', '');
            }
        }
        return $result;
    }

    // ---- Internal helpers ----

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

        // Check if this hash was seen as a write event in any prior request
        $writeEvents = $this->logger->lookupPersistedTaint($hash);
        foreach ($writeEvents as $event) {
            $taintId = $event['taint_id'];
            // Propagate into current request's registry
            TaintRegistry::propagate($taintId, $hash, 'db:' . $event['db_table'] . '.' . $event['db_column']);
            $this->logger->logRead($taintId, 'db', $table ?: $event['db_table'], $column, $rowKey);
        }
    }

    private function hash(mixed $value): string
    {
        return hash('sha256', (string)$value);
    }

    private function isEnabled(): bool
    {
        return (bool)(getenv('BOOYAH_TAINT_ENABLED') ?: true);
    }
}
