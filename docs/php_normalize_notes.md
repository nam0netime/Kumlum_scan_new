# PHP Syntax Normalizer Notes

Kunlun-M's PHP parser (`phply`) only understands PHP 5.x syntax. Modern
plugins (GiveWP, Stripe SDK, Laravel-style code) use PHP 7+/8+ syntax
that phply rejects with `SyntaxError`, which causes the scanner to skip
those files entirely — and along with them any gadget-chain components
the files contain.

To avoid missing these files we rewrite modern PHP down to phply-
compatible syntax **before** parsing. The rewriting is done by
[`core/php_normalizer.py`](../core/php_normalizer.py) and is wired into
[`core/pretreatment.py`](../core/pretreatment.py) as a fallback: phply
runs first against the original source; only on `SyntaxError` does the
normalizer run and the file is re-parsed.

## Summary of results on GiveWP

| | before | after |
| --- | ---: | ---: |
| Failed files | 653 | 19 |
| Failed files containing magic methods | 166 | 0 |
| ValidGenerator.php parses (CVE-2024-5932 key file) | no | yes |

## How it works

The normalizer is a pipeline of small transforms. It first **masks** all
string literals, heredocs/nowdocs, single-line and block comments with
opaque placeholders so subsequent regex-based transforms can't mangle
their contents. After all transforms run, the placeholders are restored.

### Transforms (in pipeline order)

1. **Mask literals & comments** – `_mask_literals()` replaces strings,
   heredocs, nowdocs, `//` / `#` / `/* */` comments with sentinels.
2. **Strip PHP 8 attributes** – `#[Foo(...)]` → ``.
3. **Numeric separators** – `1_000_000` → `1000000`.
4. **Static closures & static arrow fns** – `static function () {}` and
   `static fn(...)` → drop the `static` keyword.
5. **Arrow functions** – `fn($x) => $x + 1` → `function ($x) { return $x + 1; }`.
   Run in a fix-point loop so nested arrow fns are fully expanded.
6. **Null-safe operator** – `?->` → `->`.
7. **Enums** – `enum Foo : string { case Red = 'r'; ... }` → `class Foo { }`.
8. **Match expressions** – `match($v) { 1,2 => 'a', default => 'b' }` →
   nested ternaries `((($v) === (1) ? ('a') : ...))`.
9. **Type declarations** – strip return types (anchored on `function`),
   parameter types, property types, nullable (`?T`), union (`A|B`),
   intersection (`A&B`), and constructor property promotion modifiers.
10. **Visibility on class constants** – `public const X = 1` → `const X = 1`.
11. **Named arguments** – `foo(name: "x")` → `foo("x")`.
12. **`use function` / `use const`** – drop the qualifier so it parses
    as a plain namespace import.
13. **Null coalescing** – `a ?? b` → `a ?: b` (Elvis); `??=` → `=`.
    Not semantically identical but preserves taint flow through the
    operands.
14. **Spread & variadic** – strip `...` before `$var` / expression /
    function call. Also strips `...` in variadic parameter declarations
    because phply doesn't support them either.
15. **Power operator `**`** – `a ** b` → `pow(a, b)`. Operand
    boundaries are found by walking a small set of token classes
    (identifiers, variables, `->`/`::`/`[]`/`(...)` chains).
16. **Reserved class-const names** – `Foo::NAMESPACE` / `::FINALLY` etc.
    → `Foo::_NAMESPACE`. Avoids collision with phply's reserved words
    when the keyword is used as a class constant.
17. **Reserved method names** – `function finally(...)` →
    `function _finally(...)`. Only renames the *definition*; call sites
    like `$x->finally(...)` are already accepted by phply.
18. **Array destructuring** – `[$a, $b] = $x` → `list($a, $b) = $x`.
    Keyed form `['k' => $a, 'j' => $b] = EXPR` is rewritten using a
    temp variable to sidestep phply's rejection of `(EXPR)[key]`:
    `$_km_destr_N = EXPR; $a = $_km_destr_N['k']; $b = $_km_destr_N['j'];`.
19. **Callable-on-call-result** – `expr()(args)` → `call_user_func(expr(), args)`.
    Run in a fix-point loop. `(int)$x` and other cast expressions are
    explicitly skipped. Rewrites are collected as non-overlapping
    `(start, end, replacement)` tuples and applied in one pass to
    avoid the index-drift bug that byte-by-byte rewriting introduces.
20. **First-class callables** – `strlen(...)` → `strlen()`.
21. **Leftover `readonly`** – strip any `readonly` token that survived
    earlier passes (e.g. `readonly` on plain promoted parameters).
22. **Unmask** – restore string / comment placeholders.

## Design choices

- **Regex + hand-rolled scanners, no AST**. A full PHP tokenizer in
  Python would be significantly bigger than the scanner we need and
  phply is already the AST parser downstream. We only need the input
  to be close enough to PHP 5 that phply doesn't bail on it.

- **Masking literals first is non-negotiable**. Without it, a simple
  rule like "replace `static function` with `function`" rewrites
  content inside docblocks and strings, which silently corrupts
  analysis.

- **Fix-point loops** for transforms that can expose more work:
  `_replace_arrow_fn` (nested arrow fns), and
  `_rewrite_callable_on_call_result` (chained `foo()()()`).

- **Rewrites as `(start, stop, replacement)` lists** instead of
  appending to a running buffer. Byte-by-byte append + truncate is
  what caused the `"...CustomFiecall_user_func(..."` corruption in
  an earlier iteration: once one rewrite lands, the buffer length
  diverges from the input index and subsequent truncation lands at
  the wrong boundary.

- **Lossy but sound for taint tracking**. We happily drop semantic
  information (`?->` vs `->`, `??` vs `?:`, spread fan-out, named
  argument positioning) whenever phply can't represent it. The goal
  is not to preserve runtime behavior but to keep every data-flow
  edge the gadget-chain scanner might need.

## Known limitations

- Not a PHP 8 parser — genuinely new constructs we haven't seen in
  real plugins may still fail. 19 GiveWP files still fail; none of
  them contain magic methods so they don't affect gadget-chain
  scanning.
- `??` → `?:` is a taint-preserving approximation, not a truth-
  preserving one. If you later add Boolean-flow analysis, revisit.
- `...expr()` spread loses the fan-out. If a rule ever needs to
  distinguish individual spread elements, this transform must be
  upgraded.
- `finally` renamed to `_finally` in method *definitions* means that
  `$x->finally(...)` at call sites will not match the rewritten
  method name — but call-site resolution in the taint tracker is
  string-based on the call expression, so this is consistent as long
  as both sides come from the same run. Mixed-run analyses would
  mismatch.

## Where the fix lives

- `core/php_normalizer.py` – all transforms.
- `core/pretreatment.py` lines ~118-135 – wiring: on `SyntaxError`,
  call `normalize()` and re-parse.

## Re-running the tests

The ad-hoc test scripts at repo root are temporary:

- `_test_normalizer.py` – shows the normalizer's output on synthetic
  samples. Sanity check for regressions.
- `_test_parse.py` – verifies phply can actually parse each normalized
  sample. Target: `ok=17, fail=0`.
- `_test_real.py` – runs the normalizer against every PHP file that
  failed in the last GiveWP scan (source: `logs/main.log`). Target:
  `STILL FAILING with magic methods: 0`.
- `_test_investigate.py` – prints the source context around the parse
  error for each named file. Useful when adding new transforms.

Delete these once the CVE-2024-5932 chain is confirmed detected by
the full scan.

## Outstanding work

1. Re-run the full scan against GiveWP and confirm the ValidGenerator
   chain shows up in `logs/main.log` as an unserialization gadget.
2. Remove the `_test_*.py` scripts.
3. If any new PHP syntax surfaces (PHP 8.3+ features, new SDKs),
   add a transform in `php_normalizer.py` and extend `_test_parse.py`
   with a new synthetic sample.
