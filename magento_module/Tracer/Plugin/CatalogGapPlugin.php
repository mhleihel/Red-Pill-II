<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

/**
 * Gap-closure plugins for Catalog Block/Helper/UI paths missed by GenericModelPlugin.
 * Three plugins in one file — registered separately in di.xml.
 */

use Magento\Catalog\Block\Navigation;
use Magento\Catalog\Helper\Category as CategoryHelper;
use Magento\Catalog\Ui\DataProvider\Product\Form\Modifier\CustomOptions;

class CatalogNavigationPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];

    public function afterToHtml(Navigation $subject, string $result): string
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        foreach (self::PREFIXES as $p) {
            if (str_contains($result, $p)) {
                \Booyah\Tracer\Probe::sink(
                    'Magento\Catalog\Block\Navigation::toHtml',
                    $result, 'HTML_BODY', '', 0
                );
                break;
            }
        }
        return $result;
    }
}

class CatalogCategoryHelperPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];

    public function afterGetCategoryUrl(CategoryHelper $subject, string $result): string
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        foreach (self::PREFIXES as $p) {
            if (str_contains($result, $p)) {
                \Booyah\Tracer\Probe::enter(
                    'Magento\Catalog\Helper\Category::getCategoryUrl',
                    [$result], '', 0
                );
                break;
            }
        }
        return $result;
    }
}

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
