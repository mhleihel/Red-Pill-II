<?php
declare(strict_types=1);
namespace Booyah\Tracer\Plugin;
use Magento\Catalog\Helper\Category as CategoryHelper;

class CatalogCategoryHelperPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];
    public function afterGetCategoryUrl(CategoryHelper $subject, string $result): string
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        foreach (self::PREFIXES as $p) {
            if (str_contains($result, $p)) {
                // Extract full token including file extension from URL (e.g., bSRC_FOO.html)
                // so the taint hash matches what embedded-taint SINK extraction sees.
                if (preg_match('/(' . preg_quote($p, '/') . '[^\s"\'<>&;?#]+)/', $result, $m)) {
                    $token = $m[1];
                } else {
                    $token = $p;
                }
                \Booyah\Tracer\Probe::source(
                    'Magento\Catalog\Helper\Category::getCategoryUrl',
                    'category_url', $token, '', 0
                );
                break;
            }
        }
        return $result;
    }
}
