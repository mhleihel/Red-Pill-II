<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Magento\Framework\Model\AbstractModel;

/**
 * Generic taint tracer for ALL Magento models (Catalog, CMS, Customer, etc.).
 * Fires on any model whose setData/save/load/getData touches a bSRC_* value.
 * Only active when BOOYAH_TAINT_ENABLED=1.
 */
class GenericModelPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];

    private static function isTainted(mixed $value): bool
    {
        if (!is_string($value)) return false;
        foreach (self::PREFIXES as $p) {
            if (str_starts_with($value, $p)) return true;
        }
        return false;
    }

    private static function modelId(AbstractModel $model): string
    {
        $cls = get_class($model);
        $parts = explode('\\', $cls);
        return implode('\\', array_slice($parts, 0, 3)); // Vendor\Module\Model
    }

    public function beforeSetData(AbstractModel $subject, $key, $value = null): array
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return [$key, $value];
        $mid = self::modelId($subject);
        if (is_string($key) && self::isTainted($value)) {
            \Booyah\Tracer\Probe::source(
                $mid . '::setData(' . $key . ')', $key, (string)$value, '', 0
            );
        } elseif (is_array($key)) {
            foreach ($key as $k => $v) {
                if (is_string($k) && self::isTainted($v)) {
                    \Booyah\Tracer\Probe::source(
                        $mid . '::setData[' . $k . ']', $k, (string)$v, '', 0
                    );
                }
            }
        }
        return [$key, $value];
    }

    private static function modelTable(AbstractModel $model): string
    {
        try {
            $res = $model->getResource();
            return ($res && method_exists($res, 'getMainTable')) ? (string)$res->getMainTable() : 'unknown';
        } catch (\Throwable $e) {
            return 'unknown';
        }
    }

    public function beforeSave(AbstractModel $subject): array
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return [];
        $table = self::modelTable($subject);
        foreach ($subject->getData() as $k => $v) {
            if (is_string($k) && self::isTainted($v)) {
                \Booyah\Tracer\Probe::boundary('WRITE', 'db', $table, (string)$v, '', 0);
            }
        }
        return [];
    }

    public function afterLoad(AbstractModel $subject, AbstractModel $result): AbstractModel
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        $table = self::modelTable($result);
        foreach ($result->getData() as $k => $v) {
            if (is_string($k) && self::isTainted($v)) {
                \Booyah\Tracer\Probe::boundary('READ', 'db', $table, (string)$v, '', 0);
            }
        }
        return $result;
    }

    public function afterGetData(AbstractModel $subject, $result, string $key = '', $index = null)
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        if (is_string($result) && self::isTainted($result)) {
            $mid = self::modelId($subject);
            \Booyah\Tracer\Probe::enter($mid . '::getData(' . $key . ')', [$result], '', 0);
        }
        return $result;
    }
}
