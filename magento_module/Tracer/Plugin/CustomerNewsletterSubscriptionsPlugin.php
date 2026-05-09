<?php
declare(strict_types=1);
namespace Booyah\Tracer\Plugin;

use Magento\Customer\Block\Adminhtml\Form\Element\Newsletter\Subscriptions;

class CustomerNewsletterSubscriptionsPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];

    public function afterGetElementHtml(Subscriptions $subject, string $result): string
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return $result;
        foreach (self::PREFIXES as $p) {
            if (str_contains($result, $p)) {
                \Booyah\Tracer\Probe::sink(
                    'Magento\Customer\Block\Adminhtml\Form\Element\Newsletter\Subscriptions::getElementHtml',
                    $result, 'HTML_BODY', '', 0
                );
                break;
            }
        }
        return $result;
    }
}
