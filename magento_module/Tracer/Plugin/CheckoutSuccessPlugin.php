<?php
declare(strict_types=1);
namespace Booyah\Tracer\Plugin;

use Magento\Checkout\Block\Onepage\Success;

class CheckoutSuccessPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];

    public function afterToHtml(Success $subject, string $result): string
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        foreach (self::PREFIXES as $p) {
            if (str_contains($result, $p)) {
                \Booyah\Tracer\Probe::sink(
                    'Magento\Checkout\Block\Onepage\Success::toHtml',
                    $result, 'HTML_BODY', '', 0
                );
                break;
            }
        }
        return $result;
    }
}
