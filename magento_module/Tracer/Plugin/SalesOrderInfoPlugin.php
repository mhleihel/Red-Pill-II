<?php
declare(strict_types=1);
namespace Booyah\Tracer\Plugin;

use Magento\Sales\Block\Order\Info;

class SalesOrderInfoPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];

    public function afterToHtml(Info $subject, string $result): string
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        foreach (self::PREFIXES as $p) {
            if (str_contains($result, $p)) {
                \Booyah\Tracer\Probe::sink(
                    'Magento\Sales\Block\Order\Info::toHtml',
                    $result, 'HTML_BODY', '', 0
                );
                break;
            }
        }
        return $result;
    }
}
