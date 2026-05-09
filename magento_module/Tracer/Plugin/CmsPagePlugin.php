<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Magento\Cms\Controller\Adminhtml\Page\Save as PageSave;
use Magento\Cms\Controller\Adminhtml\Block\Save as BlockSave;
use Magento\Framework\App\RequestInterface;

/**
 * Source plugin: records tainted POST params entering the CMS Page/Block save controllers.
 * Render plugin: confirms tainted CMS content reached the HTML output layer.
 */
class CmsPagePlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];

    private static function isTainted(mixed $value): bool
    {
        if (!is_string($value)) return false;
        foreach (self::PREFIXES as $p) {
            if (str_starts_with($value, $p)) return true;
        }
        return false;
    }

    public function beforeExecute(PageSave $subject): void
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return;
        foreach ($subject->getRequest()->getPostValue() as $field => $value) {
            if (self::isTainted($value)) {
                \Booyah\Tracer\Probe::source(
                    'Magento\Cms\Controller\Adminhtml\Page\Save::execute',
                    (string)$field, (string)$value, '', 0
                );
            }
        }
    }
}
