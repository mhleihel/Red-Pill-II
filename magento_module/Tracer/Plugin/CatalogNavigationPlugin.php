<?php
declare(strict_types=1);
namespace Booyah\Tracer\Plugin;
use Magento\Catalog\Block\Navigation;

class CatalogNavigationPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];

    public function afterGetCategoryUrl(Navigation $subject, string $result): string
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        foreach (self::PREFIXES as $p) {
            if (str_contains($result, $p)) {
                if (preg_match('/(' . preg_quote($p, '/') . '[^\s"\'<>&;?#]+)/', $result, $m)) {
                    $token = $m[1];
                } else {
                    $token = $p;
                }
                \Booyah\Tracer\Probe::source(
                    'Magento\Catalog\Block\Navigation::getCategoryUrl',
                    'category_url', $token, '', 0
                );
                break;
            }
        }
        return $result;
    }

    public function afterToHtml(Navigation $subject, string $result): string
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        foreach (self::PREFIXES as $p) {
            if (str_contains($result, $p)) {
                \Booyah\Tracer\Probe::sink('Magento\Catalog\Block\Navigation::toHtml', $result, 'HTML_BODY', '', 0);
                break;
            }
        }
        return $result;
    }
}
