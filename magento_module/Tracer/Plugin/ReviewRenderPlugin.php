<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Magento\Review\Block\Product\View\ListView;

/**
 * Sink plugin: confirms tainted review data reached the HTML render layer.
 * Fires after ListView::toHtml() and scans the output for bSRC_/BSYH_ values.
 */
class ReviewRenderPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];

    public function afterToHtml(ListView $subject, string $result): string
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        foreach (self::PREFIXES as $p) {
            if (str_contains($result, $p)) {
                \Booyah\Tracer\Probe::sink(
                    'Magento\Review\Block\Product\View\ListView::toHtml',
                    $result,
                    'HTML_BODY',
                    '',
                    0
                );
                break;
            }
        }
        return $result;
    }
}
