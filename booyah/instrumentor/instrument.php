#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Booyah AST Instrumentation Tool
 *
 * Injects \Booyah\Tracer\Probe::enter() / exit() calls into every
 * function and method body in the target source tree.
 *
 * Also injects targeted hooks at known framework chokepoints:
 *   - Magento\Framework\Escaper   → transform() with SAN_* marks
 *   - AbstractBlock::toHtml       → sink() with HTML_BODY
 *   - Response::setBody           → sink() with HTML_BODY
 *   - TransportBuilder::setBody   → sink() with EMAIL_BODY
 *
 * Usage:
 *   php instrument.php \
 *     --source /path/to/magento \
 *     --output /path/to/instrumented-magento \
 *     --scope  app/code/Magento/Review \
 *     [--chokepoints]   (add framework chokepoint hooks)
 *     [--dry-run]       (print files that would be changed, do not write)
 *
 * The output tree is a copy of the source tree. Only PHP files under
 * --scope are modified. All other files are symlinked or copied as-is.
 */

// ── Bootstrap php-parser from Magento vendor ──────────────────────────────

$autoloader = null;
foreach ([
    __DIR__ . '/../../vendor/autoload.php',   // Booyah project
    '/Users/mhleihel/Desktop/magento2-2.4.8-p4/vendor/autoload.php',
] as $candidate) {
    if (file_exists($candidate)) {
        $autoloader = $candidate;
        break;
    }
}
if (!$autoloader) {
    fwrite(STDERR, "Cannot find vendor/autoload.php\n");
    exit(1);
}
require $autoloader;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\Node\Expr;
use PhpParser\NodeVisitorAbstract;
use PhpParser\NodeTraverser;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard as PrettyPrinter;
use PhpParser\Error as ParseError;

// ── CLI options ────────────────────────────────────────────────────────────

$opts = getopt('', ['source:', 'output:', 'scope:', 'chokepoints', 'dry-run']);

$sourceRoot  = rtrim($opts['source'] ?? '', '/');
$outputRoot  = rtrim($opts['output'] ?? '', '/');
$scope       = rtrim($opts['scope'] ?? '', '/');
$doChokepoints = isset($opts['chokepoints']);
$dryRun      = isset($opts['dry-run']);

if (!$sourceRoot || !$outputRoot || !$scope) {
    fwrite(STDERR, "Usage: php instrument.php --source DIR --output DIR --scope RELATIVE_PATH [--chokepoints] [--dry-run]\n");
    exit(1);
}

if (!is_dir($sourceRoot)) {
    fwrite(STDERR, "Source not found: $sourceRoot\n");
    exit(1);
}

// ── Known framework chokepoints ────────────────────────────────────────────

/**
 * Maps a relative file path pattern to a list of method hooks.
 * Each hook: [method_name, hook_type, extra_args]
 * hook_type: 'transform' | 'sink'
 */
const CHOKEPOINTS = [
    'lib/internal/Magento/Framework/Escaper.php' => [
        ['escapeHtml',     'transform', 'SAN_ESCAPE_HTML'],
        ['escapeHtmlAttr', 'transform', 'SAN_ESCAPE_HTML_ATTR'],
        ['escapeJs',       'transform', 'SAN_ESCAPE_JS'],
        ['escapeUrl',      'transform', 'SAN_ESCAPE_URL'],
        ['escapeCss',      'transform', 'SAN_ESCAPE_CSS'],
    ],
    'lib/internal/Magento/Framework/View/Element/AbstractBlock.php' => [
        ['toHtml', 'sink', 'HTML_BODY'],
    ],
    'lib/internal/Magento/Framework/HTTP/PhpEnvironment/Response.php' => [
        ['setBody', 'sink', 'HTML_BODY'],
    ],
    'lib/internal/Magento/Framework/Mail/Template/TransportBuilder.php' => [
        ['setTemplateVars', 'sink', 'EMAIL_BODY'],
    ],
];

// ── AST visitor: inject generic enter/exit probes ─────────────────────────

class ProbeInjector extends NodeVisitorAbstract
{
    public int $injected = 0;

    public function leaveNode(Node $node)
    {
        if (!($node instanceof Stmt\Function_) &&
            !($node instanceof Stmt\ClassMethod)) {
            return null;
        }

        // Skip abstract/interface methods with no body.
        if ($node->stmts === null) {
            return null;
        }

        $fqn  = $this->resolveFqn($node);
        $line = $node->getStartLine();

        // Prepend enter() call.
        $enterStmt = $this->buildEnterStmt($fqn, $line);
        array_unshift($node->stmts, $enterStmt);

        // Wrap every return statement so exit() sees the return value.
        $node->stmts = $this->wrapReturns($node->stmts, $fqn, $line);

        // If no explicit return, append exit() with null at end of body.
        $node->stmts[] = $this->buildExitStmt($fqn, $line, new Expr\ConstFetch(new Node\Name('null')));

        $this->injected++;
        return $node;
    }

    private function resolveFqn(Node $node): string
    {
        $name = $node->name->name ?? '?';
        // Class context is set by parent visitor if needed; use simple name here.
        return $name;
    }

    private function buildEnterStmt(string $fqn, int $line): Stmt\Expression
    {
        return new Stmt\Expression(
            new Expr\StaticCall(
                new Node\Name\FullyQualified('Booyah\\Tracer\\Probe'),
                'enter',
                [
                    new Node\Arg(new Node\Scalar\String_($fqn)),
                    new Node\Arg(new Expr\FuncCall(new Node\Name('func_get_args'))),
                    new Node\Arg(new Node\Scalar\MagicConst\File()),
                    new Node\Arg(new Node\Scalar\LNumber($line)),
                ]
            )
        );
    }

    private function buildExitStmt(string $fqn, int $line, Expr $retExpr): Stmt\Expression
    {
        return new Stmt\Expression(
            new Expr\StaticCall(
                new Node\Name\FullyQualified('Booyah\\Tracer\\Probe'),
                'exit',
                [
                    new Node\Arg(new Node\Scalar\String_($fqn)),
                    new Node\Arg($retExpr),
                    new Node\Arg(new Node\Scalar\MagicConst\File()),
                    new Node\Arg(new Node\Scalar\LNumber($line)),
                ]
            )
        );
    }

    private function wrapReturns(array $stmts, string $fqn, int $line): array
    {
        $result = [];
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Return_) {
                $retExpr = $stmt->expr ?? new Expr\ConstFetch(new Node\Name('null'));
                // Replace: return $expr;
                // With:    return \Booyah\Tracer\Probe::exit(__METHOD__, $expr, __FILE__, __LINE__);
                $wrapped = new Stmt\Return_(
                    new Expr\StaticCall(
                        new Node\Name\FullyQualified('Booyah\\Tracer\\Probe'),
                        'exit',
                        [
                            new Node\Arg(new Node\Scalar\String_($fqn)),
                            new Node\Arg($retExpr),
                            new Node\Arg(new Node\Scalar\MagicConst\File()),
                            new Node\Arg(new Node\Scalar\LNumber($stmt->getStartLine())),
                        ]
                    )
                );
                $result[] = $wrapped;
            } elseif (property_exists($stmt, 'stmts') && is_array($stmt->stmts)) {
                $stmt->stmts = $this->wrapReturns($stmt->stmts, $fqn, $line);
                $result[] = $stmt;
            } else {
                $result[] = $stmt;
            }
        }
        return $result;
    }
}

// ── AST visitor: inject targeted chokepoint hooks ─────────────────────────

class ChokepointInjector extends NodeVisitorAbstract
{
    private array $hooks; // method_name => [type, extra]
    public int $injected = 0;

    public function __construct(array $hooks)
    {
        // Index by method name for fast lookup.
        $this->hooks = [];
        foreach ($hooks as [$method, $type, $extra]) {
            $this->hooks[$method] = [$type, $extra];
        }
    }

    public function leaveNode(Node $node)
    {
        if (!($node instanceof Stmt\ClassMethod)) {
            return null;
        }
        if ($node->stmts === null) {
            return null;
        }

        $name = $node->name->name;
        if (!isset($this->hooks[$name])) {
            return null;
        }

        [$type, $extra] = $this->hooks[$name];
        $line = $node->getStartLine();

        if ($type === 'transform') {
            $node->stmts = $this->injectTransform($node->stmts, $name, $extra, $line);
        } elseif ($type === 'sink') {
            $node->stmts = $this->injectSink($node->stmts, $name, $extra, $line);
        }

        $this->injected++;
        return $node;
    }

    /**
     * For transform hooks: wrap every return to call Probe::transform($fqn, $input, $output, ...).
     * Prepend: capture first argument as $__booyah_input.
     */
    private function injectTransform(array $stmts, string $method, string $mark, int $line): array
    {
        // Prepend: $__booyah_in = func_get_arg(0);
        $captureInput = new Stmt\Expression(
            new Expr\Assign(
                new Expr\Variable('__booyah_in'),
                new Expr\FuncCall(new Node\Name('func_get_arg'), [new Node\Arg(new Node\Scalar\LNumber(0))])
            )
        );
        array_unshift($stmts, $captureInput);

        // Wrap returns: before returning $result, call Probe::transform($fqn, $in, $result, ..., $mark)
        $stmts = $this->wrapTransformReturns($stmts, $method, $mark, $line);
        return $stmts;
    }

    private function wrapTransformReturns(array $stmts, string $method, string $mark, int $line): array
    {
        $result = [];
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Return_) {
                $retExpr = $stmt->expr ?? new Expr\ConstFetch(new Node\Name('null'));
                // $__booyah_out = <original_return_expr>
                $assignOut = new Stmt\Expression(
                    new Expr\Assign(new Expr\Variable('__booyah_out'), $retExpr)
                );
                // Probe::transform($method, $__booyah_in, $__booyah_out, __FILE__, __LINE__, $mark)
                $probeCall = new Stmt\Expression(
                    new Expr\StaticCall(
                        new Node\Name\FullyQualified('Booyah\\Tracer\\Probe'),
                        'transform',
                        [
                            new Node\Arg(new Node\Scalar\String_($method)),
                            new Node\Arg(new Expr\Variable('__booyah_in')),
                            new Node\Arg(new Expr\Variable('__booyah_out')),
                            new Node\Arg(new Node\Scalar\MagicConst\File()),
                            new Node\Arg(new Node\Scalar\LNumber($stmt->getStartLine())),
                            new Node\Arg(new Node\Scalar\String_($mark)),
                        ]
                    )
                );
                $result[] = $assignOut;
                $result[] = $probeCall;
                $result[] = new Stmt\Return_(new Expr\Variable('__booyah_out'));
            } elseif (property_exists($stmt, 'stmts') && is_array($stmt->stmts)) {
                $stmt->stmts = $this->wrapTransformReturns($stmt->stmts, $method, $mark, $line);
                $result[] = $stmt;
            } else {
                $result[] = $stmt;
            }
        }
        return $result;
    }

    private function injectSink(array $stmts, string $method, string $sinkContext, int $line): array
    {
        return $this->wrapSinkReturns($stmts, $method, $sinkContext, $line);
    }

    private function wrapSinkReturns(array $stmts, string $method, string $sinkContext, int $line): array
    {
        $result = [];
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Return_) {
                $retExpr = $stmt->expr ?? new Expr\ConstFetch(new Node\Name('null'));
                $assignOut = new Stmt\Expression(
                    new Expr\Assign(new Expr\Variable('__booyah_sink_out'), $retExpr)
                );
                $probeCall = new Stmt\Expression(
                    new Expr\StaticCall(
                        new Node\Name\FullyQualified('Booyah\\Tracer\\Probe'),
                        'sink',
                        [
                            new Node\Arg(new Node\Scalar\String_($method)),
                            new Node\Arg(new Expr\Variable('__booyah_sink_out')),
                            new Node\Arg(new Node\Scalar\String_($sinkContext)),
                            new Node\Arg(new Node\Scalar\MagicConst\File()),
                            new Node\Arg(new Node\Scalar\LNumber($stmt->getStartLine())),
                        ]
                    )
                );
                $result[] = $assignOut;
                $result[] = $probeCall;
                $result[] = new Stmt\Return_(new Expr\Variable('__booyah_sink_out'));
            } elseif (property_exists($stmt, 'stmts') && is_array($stmt->stmts)) {
                $stmt->stmts = $this->wrapSinkReturns($stmt->stmts, $method, $sinkContext, $line);
                $result[] = $stmt;
            } else {
                $result[] = $stmt;
            }
        }
        return $result;
    }
}

// ── File processor ─────────────────────────────────────────────────────────

$parser  = (new ParserFactory())->createForHostVersion();
$printer = new PrettyPrinter(['shortArraySyntax' => true]);

function processFile(
    string $srcFile,
    string $dstFile,
    bool   $instrument,
    array  $chokepointHooks, // empty = no chokepoint injection
    $parser,
    $printer,
    bool   $dryRun
): array {
    $code = file_get_contents($srcFile);
    if ($code === false) {
        return ['skipped' => true, 'reason' => 'unreadable'];
    }

    if (!$instrument && empty($chokepointHooks)) {
        // No instrumentation needed — copy verbatim.
        if (!$dryRun) {
            $dir = dirname($dstFile);
            if (!is_dir($dir)) mkdir($dir, 0755, true);
            copy($srcFile, $dstFile);
        }
        return ['skipped' => false, 'instrumented' => false, 'injected' => 0];
    }

    try {
        $ast = $parser->parse($code);
    } catch (ParseError $e) {
        // Unparseable file — copy verbatim.
        if (!$dryRun) {
            $dir = dirname($dstFile);
            if (!is_dir($dir)) mkdir($dir, 0755, true);
            copy($srcFile, $dstFile);
        }
        return ['skipped' => false, 'instrumented' => false, 'injected' => 0, 'parse_error' => $e->getMessage()];
    }

    $traverser = new NodeTraverser();
    $probeVisitor = null;
    $chokeVisitor = null;

    if ($instrument) {
        $probeVisitor = new ProbeInjector();
        $traverser->addVisitor($probeVisitor);
    }

    if (!empty($chokepointHooks)) {
        $chokeVisitor = new ChokepointInjector($chokepointHooks);
        $traverser->addVisitor($chokeVisitor);
    }

    $modified = $traverser->traverse($ast);
    $newCode  = $printer->prettyPrintFile($modified);

    if (!$dryRun) {
        $dir = dirname($dstFile);
        if (!is_dir($dir)) mkdir($dir, 0755, true);
        file_put_contents($dstFile, $newCode);
    }

    $injected = ($probeVisitor?->injected ?? 0) + ($chokeVisitor?->injected ?? 0);
    return ['skipped' => false, 'instrumented' => true, 'injected' => $injected];
}

// ── Main: walk source tree ─────────────────────────────────────────────────

$scopeAbsolute = rtrim($sourceRoot . '/' . ltrim($scope, '/'), '/') . '/';
$stats = ['files' => 0, 'instrumented' => 0, 'injected' => 0, 'errors' => 0];

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($sourceRoot, RecursiveDirectoryIterator::SKIP_DOTS)
);

foreach ($iterator as $fileInfo) {
    $srcFile = $fileInfo->getPathname();
    $relPath = substr($srcFile, strlen($sourceRoot) + 1);
    $dstFile = $outputRoot . '/' . $relPath;

    if ($fileInfo->getExtension() !== 'php') {
        // Non-PHP file: copy verbatim (preserves nginx.conf.sample, .xml, .phtml, etc.)
        if (!$dryRun) {
            $dir = dirname($dstFile);
            if (!is_dir($dir)) mkdir($dir, 0755, true);
            if (!file_exists($dstFile)) {
                copy($srcFile, $dstFile);
            }
        }
        continue;
    }

    // Determine if this file is in the instrumentation scope.
    $inScope = str_starts_with($srcFile, $scopeAbsolute);

    // Determine if this file has a chokepoint hook (only when --chokepoints).
    $chokepointHooks = [];
    if ($doChokepoints) {
        foreach (CHOKEPOINTS as $pattern => $hooks) {
            if (str_ends_with($relPath, $pattern) || str_ends_with($srcFile, $pattern)) {
                $chokepointHooks = $hooks;
                break;
            }
        }
    }

    if (!$inScope && empty($chokepointHooks)) {
        // Outside scope — copy verbatim (skip if dry-run).
        if (!$dryRun) {
            $dir = dirname($dstFile);
            if (!is_dir($dir)) mkdir($dir, 0755, true);
            copy($srcFile, $dstFile);
        }
        $stats['files']++;
        continue;
    }

    if ($dryRun) {
        $type = $inScope ? 'PROBE' : 'CHOKEPOINT';
        echo "[$type] $relPath\n";
        $stats['files']++;
        $stats['instrumented']++;
        continue;
    }

    $result = processFile($srcFile, $dstFile, $inScope, $chokepointHooks, $parser, $printer, false);
    $stats['files']++;
    if ($result['instrumented'] ?? false) {
        $stats['instrumented']++;
        $stats['injected'] += $result['injected'] ?? 0;
    }
    if (isset($result['parse_error'])) {
        $stats['errors']++;
        fwrite(STDERR, "PARSE ERROR: $relPath — " . $result['parse_error'] . "\n");
    }
}

// ── Summary ────────────────────────────────────────────────────────────────

echo "\nInstrumentation complete.\n";
echo "  Files processed : " . $stats['files'] . "\n";
echo "  Files modified  : " . $stats['instrumented'] . "\n";
echo "  Probes injected : " . $stats['injected'] . "\n";
echo "  Parse errors    : " . $stats['errors'] . "\n";
echo "  Output root     : $outputRoot\n";
