<?php
declare(strict_types=1);

namespace Booyah\Tracer\Plugin;

use Magento\Review\Controller\Product\Post;
use Magento\Framework\App\RequestInterface;

/**
 * Logs the HTTP source for the review submission lineage.
 * This is always HOP-0 / SOURCE for the write lineage.
 */
class ReviewPostPlugin
{
    private const PREFIXES = ['bSRC', 'BSYH'];
    private const FIELDS   = ['nickname', 'title', 'detail'];

    public function beforeExecute(Post $subject): array
    {
        if (getenv('BOOYAH_TAINT_ENABLED') !== '1') return [];

        $request = $subject->getRequest();
        foreach (self::FIELDS as $field) {
            $val = (string)($request->getParam($field) ?? '');
            if ($val === '') continue;
            foreach (self::PREFIXES as $p) {
                if (str_starts_with($val, $p)) {
                    \Booyah\Tracer\Probe::source(
                        'Magento\Review\Controller\Product\Post::execute',
                        $field,
                        $val,
                        'HTTP POST /review/product/post',
                        0
                    );
                    break;
                }
            }
        }
        return [];
    }
}
