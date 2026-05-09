<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Magento\Review\Model\Review;

/**
 * Traces the data-flow lineage through the Review model.
 *
 * Logs a structured JSON line to var/log/booyah_lineage.log for every
 * setter, save(), load(), and getter call that touches a tainted value.
 *
 * Only fires when BOOYAH_TAINT_ENABLED=1.
 *
 * Log format (one JSON object per line):
 *   {"ts":…, "req":…, "order":…, "step":…, "method":…, "field":…, "value":…, "file":…, "line":…}
 *
 * order=1 → same-request write path (source→DB)
 * order=2 → same-request read path  (DB→response) — different request from order=1
 */
class ReviewFlowPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];

    /** Reuse the request-id from TaintRegistry so hops in the same request share an ID. */
    private static function reqId(): string
    {
        return \Booyah\Tracer\Model\TaintRegistry::requestId();
    }

    private static function isTainted(string $value): bool
    {
        foreach (self::PREFIXES as $p) {
            if (str_starts_with($value, $p)) return true;
        }
        return false;
    }

    private static function log(string $step, string $method, string $field, string $value): void
    {
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 5);
        $caller = ['file' => '', 'line' => 0];
        foreach ($trace as $frame) {
            if (isset($frame['file']) && !str_contains($frame['file'], 'ReviewFlowPlugin')) {
                $caller = $frame;
                break;
            }
        }

        $file = $caller['file'] ?? '';
        $line = (int)($caller['line'] ?? 0);

        // Write to Probe (runtime_trace.db) based on step type
        if ($step === 'setter') {
            \Booyah\Tracer\Probe::source($method, $field, $value, $file, $line);
        } elseif ($step === 'db_write') {
            \Booyah\Tracer\Probe::boundary('WRITE', 'db', 'review_detail', $value, $file, $line);
        } elseif ($step === 'db_read') {
            \Booyah\Tracer\Probe::boundary('READ', 'db', 'review_detail', $value, $file, $line);
        } elseif ($step === 'getter') {
            \Booyah\Tracer\Probe::enter($method, [$value], $file, $line);
        }
    }

    // ── WRITE PATH: setter intercept via setData ─────────────────────────
    // getNickname/setNickname are magic __call() methods — plugins cannot
    // intercept them. setData() IS an explicit method and all magic setters
    // route through it.

    /**
     * @param Review $subject
     * @param string|array $key
     * @param mixed $value
     * @return array
     */
    public function beforeSetData(Review $subject, $key, $value = null): array
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return [$key, $value];
        $fields = ['nickname', 'title', 'detail'];
        if (is_string($key) && in_array($key, $fields, true) && is_string($value) && self::isTainted($value)) {
            self::log('setter', 'Magento\Review\Model\Review::setData(' . $key . ')', $key, $value);
        } elseif (is_array($key)) {
            foreach ($fields as $f) {
                if (isset($key[$f]) && is_string($key[$f]) && self::isTainted($key[$f])) {
                    self::log('setter', 'Magento\Review\Model\Review::setData[' . $f . ']', $f, $key[$f]);
                }
            }
        }
        return [$key, $value];
    }

    // ── WRITE PATH: save intercept ────────────────────────────────────────

    public function beforeSave(Review $subject): array
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return [];
        foreach (['nickname', 'title', 'detail'] as $field) {
            $val = (string)($subject->getData($field) ?? '');
            if (self::isTainted($val)) {
                self::log('db_write', 'Magento\Review\Model\Review::save→review_detail.' . $field, $field, $val);
            }
        }
        return [];
    }

    // ── READ PATH: afterLoad intercept ────────────────────────────────────

    public function afterLoad(Review $subject, Review $result): Review
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        foreach (['nickname', 'title', 'detail'] as $field) {
            $val = (string)($result->getData($field) ?? '');
            if (self::isTainted($val)) {
                self::log('db_read', 'Magento\Review\Model\Review::load←review_detail.' . $field, $field, $val);
            }
        }
        return $result;
    }

    // ── READ PATH: getter intercept via getData ───────────────────────────
    // getNickname/getTitle/getDetail are magic __call() methods that route
    // through getData(). Hook getData() directly and filter for our fields.

    /**
     * @param Review $subject
     * @param mixed $result
     * @param string $key
     * @param mixed $index
     * @return mixed
     */
    public function afterGetData(Review $subject, $result, string $key = '', $index = null)
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        $fields = ['nickname', 'title', 'detail'];
        if (in_array($key, $fields, true) && is_string($result) && self::isTainted($result)) {
            self::log('getter', 'Magento\Review\Model\Review::getData(' . $key . ')', $key, $result);
        }
        return $result;
    }
}
