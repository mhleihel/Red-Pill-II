<?php
declare(strict_types=1);
namespace Booyah\Tracer\Plugin;

use Magento\Sales\Block\Items\AbstractItems;

class SalesItemsPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];

    public function afterToHtml(AbstractItems $subject, string $result): string
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        foreach (self::PREFIXES as $p) {
            if (str_contains($result, $p)) {
                \Booyah\Tracer\Probe::sink(
                    'Magento\Sales\Block\Items\AbstractItems::toHtml',
                    $result, 'HTML_BODY', '', 0
                );
                break;
            }
        }
        return $result;
    }
}
