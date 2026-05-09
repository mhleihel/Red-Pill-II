<?php
declare(strict_types=1);
namespace Booyah\Tracer\Plugin;
use Magento\Catalog\Ui\DataProvider\Product\Form\Modifier\CustomOptions;

class CatalogCustomOptionsPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];
    public function afterModifyData(CustomOptions $subject, array $result): array
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        $encoded = json_encode($result);
        foreach (self::PREFIXES as $p) {
            if (preg_match('/(' . preg_quote($p, '/') . '[a-zA-Z0-9_]+)/', $encoded, $m)) {
                \Booyah\Tracer\Probe::source(
                    'Magento\Catalog\Ui\DataProvider\Product\Form\Modifier\CustomOptions::modifyData',
                    'option_data', $m[1], '', 0
                );
                break;
            }
        }
        return $result;
    }
}
