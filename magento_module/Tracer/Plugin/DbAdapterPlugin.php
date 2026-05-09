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
        if (empty(TaintRegistry::allTaintIds())) {
            return [$table, $data];
        }
        self::$inPlugin = true;
        try {
            $this->scanRow($data, $table);
        } finally {
            self::$inPlugin = false;
        }
        return [$table, $data];
    }

    /**
     * insertOnDuplicate($table, $data, $fields) — used by Sales, EAV flat tables, order addresses.
     * Same column→value scan as beforeInsert.
     */
    public function beforeInsertOnDuplicate(
        Mysql $subject,
        string $table,
        array $data,
        array $fields = []
    ): array {
        if (self::$inPlugin || !$this->isEnabled() || in_array($table, self::SKIP_TABLES, true)) {
            return [$table, $data, $fields];
        }
        if (empty(TaintRegistry::allTaintIds())) {
            return [$table, $data, $fields];
        }
        self::$inPlugin = true;
        try {
            // $data may be a single row (assoc) or an array of rows
            if (isset($data[0]) && is_array($data[0])) {
                foreach ($data as $row) {
                    $this->scanRow($row, $table);
                }
            } else {
                $this->scanRow($data, $table);
            }
        } finally {
            self::$inPlugin = false;
        }
        return [$table, $data, $fields];
    }

    /**
     * insertForce($table, $data) — REPLACE INTO variant, same structure as insert.
     */
    public function beforeInsertForce(Mysql $subject, string $table, array $data): array
    {
        if (self::$inPlugin || !$this->isEnabled() || in_array($table, self::SKIP_TABLES, true)) {
            return [$table, $data];
        }
        if (empty(TaintRegistry::allTaintIds())) {
            return [$table, $data];
        }
        self::$inPlugin = true;
        try {
            $this->scanRow($data, $table);
        } finally {
            self::$inPlugin = false;
        }
        return [$table, $data];
    }

    /**
     * insertArray($table, $columns, $data) — bulk insert, rows are positional arrays.
     */
    public function beforeInsertArray(
        Mysql $subject,
        string $table,
        array $columns,
        array $data
    ): array {
        if (self::$inPlugin || !$this->isEnabled() || in_array($table, self::SKIP_TABLES, true)) {
            return [$table, $columns, $data];
        }
        if (empty(TaintRegistry::allTaintIds())) {
            return [$table, $columns, $data];
        }
        self::$inPlugin = true;
        try {
            foreach ($data as $row) {
                if (!is_array($row)) continue;
                $assoc = array_combine($columns, $row);
                if ($assoc) $this->scanRow($assoc, $table);
            }
        } finally {
            self::$inPlugin = false;
        }
        return [$table, $columns, $data];
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
            $this->scanRow($bind, $table);
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

    /**
     * Scan a column→value row for tainted values and log each hit.
     * Called by all write-side interceptors (insert, insertOnDuplicate, insertForce, insertArray, update).
     */
    private function scanRow(array $row, string $table): void
    {
        foreach ($row as $column => $value) {
            if (!is_string($value) || $value === '') continue;
            $taintId = TaintRegistry::lookup($this->hash($value));
            if ($taintId !== null) {
                $this->logger->logWrite($taintId, 'db', $table, (string)$column, '', '', 0);
            }
        }
    }

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
