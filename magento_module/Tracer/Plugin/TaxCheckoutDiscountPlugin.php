<?php
declare(strict_types=1);
namespace Booyah\Tracer\Plugin;

use Magento\Tax\Block\Checkout\Discount;

class TaxCheckoutDiscountPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];

    public function afterToHtml(Discount $subject, string $result): string
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        foreach (self::PREFIXES as $p) {
            if (str_contains($result, $p)) {
                \Booyah\Tracer\Probe::sink(
                    'Magento\Tax\Block\Checkout\Discount::toHtml',
                    $result, 'HTML_BODY', '', 0
                );
                break;
            }
        }
        return $result;
    }
}
