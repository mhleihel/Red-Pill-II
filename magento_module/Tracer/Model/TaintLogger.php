<?php
declare(strict_types=1);

namespace Booyah\Tracer\Model;

use Magento\Framework\App\ResourceConnection;

/**
 * Persists taint events to booyah_taint_map (MySQL).
 * Also looks up whether a value hash was previously seen in a write event.
 *
 * Only stores event metadata — never stores the actual value.
 */
class TaintLogger
{
    private ResourceConnection $resource;
    private static bool $schemaReady = false;

    public function __construct(ResourceConnection $resource)
    {
        $this->resource = $resource;
    }

    /**
     * Log a persistence write event: tainted data entered the persistence layer.
     */
    public function logWrite(
        string $taintId,
        string $persistence,
        string $table,
        string $column,
        string $rowKey,
        string $file,
        int    $line
    ): void {
        if (!$this->ensureReady()) return;
        try {
            $this->resource->getConnection()->insert('booyah_taint_map', [
                'taint_id'   => $taintId,
                'event_type' => 'write',
                'persistence'=> $persistence,
                'db_table'   => $table,
                'db_column'  => $column,
                'row_key'    => substr($rowKey, 0, 256),
                'request_id' => TaintRegistry::requestId(),
                'role'       => TaintRegistry::role(),
                'file'       => substr($file, 0, 512),
                'line'       => $line,
                'run_id'     => TaintRegistry::runId(),
                'ts'         => time(),
            ]);
        } catch (\Throwable $e) {
            // Never let taint logging crash the application
        }
    }

    /**
     * Log a persistence read event: tainted data left the persistence layer.
     */
    public function logRead(
        string $taintId,
        string $persistence,
        string $table,
        string $column,
        string $rowKey
    ): void {
        if (!$this->ensureReady()) return;
        try {
            $this->resource->getConnection()->insert('booyah_taint_map', [
                'taint_id'   => $taintId,
                'event_type' => 'read',
                'persistence'=> $persistence,
                'db_table'   => $table,
                'db_column'  => $column,
                'row_key'    => substr($rowKey, 0, 256),
                'request_id' => TaintRegistry::requestId(),
                'role'       => TaintRegistry::role(),
                'file'       => '',
                'line'       => 0,
                'run_id'     => TaintRegistry::runId(),
                'ts'         => time(),
            ]);
        } catch (\Throwable $e) {
        }
    }

    /**
     * Look up all write events for a given value hash across all previous requests.
     * Returns array of {taint_id, persistence, db_table, db_column, row_key, request_id}.
     */
    public function lookupPersistedTaint(string $valueHash): array
    {
        if (!$this->ensureReady()) return [];
        try {
            $conn = $this->resource->getConnection();
            $select = $conn->select()
                ->from('booyah_taint_map', ['taint_id', 'persistence', 'db_table', 'db_column', 'row_key', 'request_id'])
                ->where('taint_id = ?', $valueHash)
                ->where('event_type = ?', 'write')
                ->limit(10);
            return $conn->fetchAll($select);
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function ensureReady(): bool
    {
        if (self::$schemaReady) return true;
        try {
            $conn = $this->resource->getConnection();
            if ($conn->isTableExists('booyah_taint_map')) {
                self::$schemaReady = true;
                return true;
            }
        } catch (\Throwable $e) {}
        return false;
    }
}
