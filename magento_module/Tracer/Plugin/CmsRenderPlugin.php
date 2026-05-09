<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Magento\Cms\Block\Page as CmsPageBlock;

/**
 * Sink plugin: confirms tainted CMS page content reached the HTML render layer.
 */
class CmsRenderPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];

    public function afterToHtml(CmsPageBlock $subject, string $result): string
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        foreach (self::PREFIXES as $p) {
            if (str_contains($result, $p)) {
                \Booyah\Tracer\Probe::sink(
                    'Magento\Cms\Block\Page::toHtml',
                    $result, 'HTML_BODY', '', 0
                );
                break;
            }
        }
        return $result;
    }
}
