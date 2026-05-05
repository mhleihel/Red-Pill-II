<?php

declare(strict_types=1);

namespace Booyah;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\Node\Scalar;
use PhpParser\NodeVisitorAbstract;
use PhpParser\BuilderFactory;
use PhpParser\NodeTraverser;

/**
 * AST visitor that inserts Booyah\Tracer calls at:
 *   - Source reads: method calls on request-like objects, superglobal reads
 *   - Sink writes: echo, print, <?=, function call sinks
 *   - Transforms: method/function calls that take and return a string (potential sanitizers)
 *   - Universal: method/function entry tracing (when $universalMode = true)
 */
class InstrumentVisitor extends NodeVisitorAbstract
{
    private BuilderFactory $factory;
    private string $currentFile;
    private array $injectionPoints = [];
    private bool $universalMode;
    private ?string $currentClass = null;
    private ?string $currentMethod = null;

    /** Method names that produce tainted values (HTTP input sources) */
    private const SOURCE_METHODS = [
        'getParam', 'getParams', 'getPost', 'getQuery', 'getContent',
        'getBodyParams', 'getHeader', 'getHeaders', 'getCookie',
        'getPathInfo', 'getRequestUri', 'getServer',
    ];

    /** Superglobal variable names */
    private const SUPERGLOBALS = ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES', '_SERVER'];

    /** Function/method calls that produce output (sinks) */
    private const SINK_FUNCTIONS = [
        'printf', 'fprintf', 'vprintf', 'header',
        'file_put_contents', 'fputs', 'fwrite',
    ];

    /** Methods that are known sanitizers / transforms worth tracing */
    private const TRANSFORM_METHODS = [
        'escapeHtml', 'escapeHtmlAttr', 'escapeUrl', 'escapeJs', 'escapeCss', 'escapeQuote',
        'htmlspecialchars', 'htmlentities', 'strip_tags',
        'urlencode', 'rawurlencode', 'intval', 'floatval', 'abs',
        'json_encode', 'addslashes', 'nl2br',
        'purify',
    ];

    public function __construct(string $currentFile, bool $universalMode = false)
    {
        $this->factory = new BuilderFactory();
        $this->currentFile = $currentFile;
        $this->universalMode = $universalMode;
    }

    public function getInjectionPoints(): array
    {
        return $this->injectionPoints;
    }

    /**
     * Pre-order: track current class/method context for universal tracing.
     */
    public function enterNode(Node $node): null
    {
        if ($node instanceof Stmt\Class_ && $node->name !== null) {
            $this->currentClass = $node->name->toString();
        } elseif ($node instanceof Stmt\ClassMethod && $node->name !== null) {
            $this->currentMethod = $node->name->toString();
        }
        return null;
    }

    public function leaveNode(Node $node): Node|null|int|array
    {
        // Track class/method context resets
        if ($node instanceof Stmt\Class_) {
            $this->currentClass = null;
        }

        // --- UNIVERSAL: instrument every class method body ---
        if ($this->universalMode && $node instanceof Stmt\ClassMethod && $node->stmts !== null) {
            return $this->instrumentMethodEntry($node);
        }
        // --- SOURCES: superglobal reads like $_GET['key'] or $_GET (whole array) ---
        if ($node instanceof Expr\ArrayDimFetch) {
            $var = $node->var;
            if ($var instanceof Expr\Variable && is_string($var->name)
                && in_array($var->name, self::SUPERGLOBALS, true)) {
                return $this->wrapSource($node, '$' . $var->name, 'superglobal');
            }
        }

        // --- SOURCES: bare superglobal variable reads like $data = $_GET ---
        // This detects assignment of the whole superglobal to a variable.
        if ($node instanceof Expr\Assign) {
            if ($node->expr instanceof Expr\Variable
                && is_string($node->expr->name)
                && in_array($node->expr->name, self::SUPERGLOBALS, true)) {
                $line = $node->getStartLine();
                $this->recordInjection('source', '$' . $node->expr->name, $line);
                $node->expr = $this->wrapSource($node->expr, '$' . $node->expr->name, 'superglobal_array');
                return $node;
            }
        }

        // --- SOURCES: request method calls like $request->getParam('foo') ---
        if ($node instanceof Expr\MethodCall) {
            $methodName = $this->getMethodName($node);
            if ($methodName !== null && in_array($methodName, self::SOURCE_METHODS, true)) {
                return $this->wrapSource($node, $this->extractParamName($node), $methodName);
            }

            // --- TRANSFORMS: known sanitizer methods ---
            if ($methodName !== null && in_array($methodName, self::TRANSFORM_METHODS, true)) {
                return $this->wrapTransform($node, $methodName);
            }
        }

        // --- SOURCES/TRANSFORMS: function call sanitizers (expression-level — return single expr) ---
        if ($node instanceof Expr\FuncCall) {
            $funcName = $this->getFuncName($node);
            if ($funcName !== null && in_array($funcName, self::TRANSFORM_METHODS, true)) {
                return $this->wrapTransform($node, $funcName);
            }
            // Sink function calls (printf, header, file_put_contents, etc.) are handled
            // at Stmt\Expression level below so we can legally return an array of statements.
        }

        // --- SINKS: echo statements (Stmt\Echo_ is a statement — array return is legal) ---
        if ($node instanceof Stmt\Echo_) {
            return $this->instrumentEcho($node);
        }

        // --- SINKS: Stmt\Expression wrapping a sink call or print() ---
        // We handle this at the statement level so returning an array is legal.
        if ($node instanceof Stmt\Expression) {
            $expr = $node->expr;

            // print($x) — Expr\Print_ is an expression, but its containing Stmt\Expression is a statement
            if ($expr instanceof Expr\Print_) {
                $line = $expr->getStartLine();
                $this->recordInjection('sink', 'print', $line);
                return [
                    new Stmt\Expression($this->makeSinkCall($expr->expr, 'print', $line)),
                    $node,
                ];
            }

            // Dangerous function calls: header(), file_put_contents(), printf(), etc.
            if ($expr instanceof Expr\FuncCall) {
                $funcName = $this->getFuncName($expr);
                if ($funcName !== null && in_array($funcName, self::SINK_FUNCTIONS, true)) {
                    $line = $expr->getStartLine();
                    $firstArg = $expr->args[0] ?? null;
                    if ($firstArg instanceof Node\Arg) {
                        $this->recordInjection('sink', $funcName, $line);
                        return [
                            new Stmt\Expression($this->makeSinkCall($firstArg->value, $funcName, $line)),
                            $node,
                        ];
                    }
                }
            }
        }

        return null;
    }

    /**
     * Prepend a Tracer::enter() call to every class method when in universal mode.
     * This captures (class::method, file, line, argument hashes) on every call.
     * The Tracer uses this to reconstruct the full call graph offline.
     */
    private function instrumentMethodEntry(Stmt\ClassMethod $method): Stmt\ClassMethod
    {
        $line = $method->getStartLine();
        $fqn  = ($this->currentClass ?? '?') . '::' . ($this->currentMethod ?? '?');
        $this->recordInjection('enter', $fqn, $line);

        // Build array of argument hashes: [\Booyah\Tracer::h($arg1), ...]
        $argHashes = [];
        foreach ($method->params as $param) {
            if ($param->var instanceof Expr\Variable && is_string($param->var->name)) {
                $argHashes[] = new Node\Arg(
                    new Expr\StaticCall(
                        new Node\Name\FullyQualified('Booyah\Tracer'),
                        'h',
                        [new Node\Arg(new Expr\Variable($param->var->name))]
                    )
                );
            }
        }

        $enterCall = new Stmt\Expression(
            new Expr\StaticCall(
                new Node\Name\FullyQualified('Booyah\Tracer'),
                'enter',
                [
                    new Node\Arg(new Scalar\String_($fqn)),
                    new Node\Arg(new Scalar\String_($this->currentFile)),
                    new Node\Arg(new Scalar\LNumber($line)),
                    new Node\Arg(new Expr\Array_(
                        array_map(fn($a) => new Node\ArrayItem($a->value), $argHashes)
                    )),
                    new Node\Arg(new Expr\StaticCall(
                        new Node\Name\FullyQualified('Booyah\Tracer'),
                        'requestId',
                        []
                    )),
                ]
            )
        );

        $method->stmts = array_merge([$enterCall], $method->stmts);
        return $method;
    }

    /**
     * Wrap a source expression:
     *   $x = EXPR  ->  ($tmp = EXPR, \Booyah\Tracer::source($tmp, ...), $tmp)
     */
    private function wrapSource(Expr $expr, string $paramName, string $funcName): Expr\StaticCall
    {
        $line = $expr->getStartLine();
        $this->recordInjection('source', $funcName, $line);

        // Use a comma expression trick via a static call that returns the value
        // We wrap the entire expression: \Booyah\Tracer::sourceWrap($expr, $paramName, $funcName, __FILE__, __LINE__)
        // sourceWrap() logs and returns the value unchanged.
        return new Expr\StaticCall(
            new Node\Name\FullyQualified('Booyah\Tracer'),
            'sourceWrap',
            [
                new Node\Arg($expr),
                new Node\Arg(new Scalar\String_($paramName)),
                new Node\Arg(new Scalar\String_($funcName)),
                new Node\Arg(new Scalar\String_($this->currentFile)),
                new Node\Arg(new Scalar\LNumber($line)),
                new Node\Arg(new Expr\StaticCall(
                    new Node\Name\FullyQualified('Booyah\Tracer'),
                    'requestId',
                    []
                )),
            ]
        );
    }

    /**
     * Wrap a transform expression:
     *   $clean = transform($dirty)
     * →  \Booyah\Tracer::transformWrap($dirty, transform($dirty), 'transform', __FILE__, __LINE__, requestId())
     *
     * PHP evaluates arguments left-to-right, so:
     *   arg0 ($dirty)         — input value, evaluated first
     *   arg1 (transform($dirty)) — PHP calls the transform, result is post-transform value
     * Both values arrive in transformWrap() with no double-evaluation side-effects on $dirty
     * because $dirty is a variable reference, not a method call.
     */
    private function wrapTransform(Expr $expr, string $funcName): Expr\StaticCall
    {
        $line = $expr->getStartLine();
        $this->recordInjection('transform', $funcName, $line);

        // Extract the pre-transform input: first argument of the method/function call
        $inputExpr = $this->extractFirstArg($expr);

        return new Expr\StaticCall(
            new Node\Name\FullyQualified('Booyah\Tracer'),
            'transformWrap',
            [
                new Node\Arg($inputExpr),  // pre-transform value (evaluated first by PHP)
                new Node\Arg($expr),        // post-transform value (transform runs here)
                new Node\Arg(new Scalar\String_($funcName)),
                new Node\Arg(new Scalar\String_($this->currentFile)),
                new Node\Arg(new Scalar\LNumber($line)),
                new Node\Arg(new Expr\StaticCall(
                    new Node\Name\FullyQualified('Booyah\Tracer'),
                    'requestId',
                    []
                )),
            ]
        );
    }

    private function extractFirstArg(Expr $expr): Expr
    {
        $args = null;
        if ($expr instanceof Expr\MethodCall) {
            $args = $expr->args;
        } elseif ($expr instanceof Expr\FuncCall) {
            $args = $expr->args;
        }
        if ($args !== null && !empty($args) && $args[0] instanceof Node\Arg) {
            return $args[0]->value;
        }
        return new Scalar\String_('');
    }

    /**
     * Instrument an echo statement to log each expression before outputting it.
     */
    private function instrumentEcho(Stmt\Echo_ $echo): array
    {
        $stmts = [];
        foreach ($echo->exprs as $expr) {
            $line = $expr->getStartLine();
            $this->recordInjection('sink', 'echo', $line);

            // Insert: \Booyah\Tracer::sink($expr, 'echo', __FILE__, __LINE__, requestId());
            $stmts[] = new Stmt\Expression(
                new Expr\StaticCall(
                    new Node\Name\FullyQualified('Booyah\Tracer'),
                    'sink',
                    [
                        new Node\Arg($expr),
                        new Node\Arg(new Scalar\String_('echo')),
                        new Node\Arg(new Scalar\String_($this->currentFile)),
                        new Node\Arg(new Scalar\LNumber($line)),
                        new Node\Arg(new Expr\StaticCall(
                            new Node\Name\FullyQualified('Booyah\Tracer'),
                            'requestId',
                            []
                        )),
                    ]
                )
            );
        }
        // Keep original echo
        $stmts[] = $echo;
        return $stmts;
    }

    private function makeSinkCall(Expr $valueExpr, string $sinkType, int $line): Expr\StaticCall
    {
        return new Expr\StaticCall(
            new Node\Name\FullyQualified('Booyah\Tracer'),
            'sink',
            [
                new Node\Arg($valueExpr),
                new Node\Arg(new Scalar\String_($sinkType)),
                new Node\Arg(new Scalar\String_($this->currentFile)),
                new Node\Arg(new Scalar\LNumber($line)),
                new Node\Arg(new Expr\StaticCall(
                    new Node\Name\FullyQualified('Booyah\Tracer'),
                    'requestId',
                    []
                )),
            ]
        );
    }

    private function getMethodName(Expr\MethodCall $call): ?string
    {
        if ($call->name instanceof Node\Identifier) {
            return $call->name->toString();
        }
        return null;
    }

    private function getFuncName(Expr\FuncCall $call): ?string
    {
        if ($call->name instanceof Node\Name) {
            return $call->name->getLast();
        }
        return null;
    }

    private function extractParamName(Expr\MethodCall $call): string
    {
        $firstArg = $call->args[0] ?? null;
        if ($firstArg instanceof Node\Arg && $firstArg->value instanceof Scalar\String_) {
            return $firstArg->value->value;
        }
        return '';
    }

    private function recordInjection(string $type, string $funcName, int $line): void
    {
        $this->injectionPoints[] = [
            'type' => $type,
            'function' => $funcName,
            'line' => $line,
        ];
    }
}
