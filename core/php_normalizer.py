"""
PHP source normalizer for Kunlun-M.

phply does not understand most PHP 7+/8+ syntax. This module rewrites
modern PHP source into a phply-compatible form BEFORE the AST parser
runs, so we keep the original AST node types (Option A).

Transforms are regex-based and applied only to "code zones" — string
literals, heredocs, nowdocs and comments are masked out first so their
content is never mangled.

Each transform is conservative: if the rewrite would be ambiguous the
original text is preserved and phply will still raise SyntaxError as
before. The goal is to cover the syntax that shows up in real plugins
(GiveWP, Stripe SDK, Laravel-style code), not to be a full PHP 8
compiler.

The list of transforms is documented in docs/php_normalize_notes.md.
"""

import re


# ---------------------------------------------------------------------------
# String / comment masking
# ---------------------------------------------------------------------------
# We replace every string literal, heredoc, nowdoc and comment with an
# opaque placeholder so regex transforms below cannot accidentally rewrite
# their contents (e.g. the literal 'static function' inside a docblock).

_PLACEHOLDER_FMT = '\x00KMSTR{}\x00'


def _mask_literals(code):
    """Return (masked_code, restore_map)."""
    restore = {}
    idx = [0]

    def stash(text):
        key = _PLACEHOLDER_FMT.format(idx[0])
        restore[key] = text
        idx[0] += 1
        return key

    # Order matters: heredocs/nowdocs first (they can contain ' and "),
    # then /* */, then // and #, then strings.
    i = 0
    out = []
    n = len(code)

    while i < n:
        ch = code[i]

        # Heredoc / Nowdoc: <<<LABEL ... LABEL;
        if ch == '<' and code.startswith('<<<', i):
            m = re.match(r"<<<\s*(?:'([A-Za-z_][A-Za-z0-9_]*)'|\"([A-Za-z_][A-Za-z0-9_]*)\"|([A-Za-z_][A-Za-z0-9_]*))\s*\n",
                         code[i:])
            if m:
                label = m.group(1) or m.group(2) or m.group(3)
                start = i
                body_start = i + m.end()
                end_pat = re.compile(r'\n[ \t]*' + re.escape(label) + r'(?=[;,\s)])')
                end_m = end_pat.search(code, body_start)
                if end_m:
                    stop = end_m.end()
                    out.append(stash(code[start:stop]))
                    i = stop
                    continue
                # unterminated — fall through and treat as plain text

        # /* ... */ comment (including docblocks)
        if ch == '/' and i + 1 < n and code[i + 1] == '*':
            end = code.find('*/', i + 2)
            if end == -1:
                out.append(code[i:])
                break
            end += 2
            out.append(stash(code[i:end]))
            i = end
            continue

        # // or # single-line comment
        if (ch == '/' and i + 1 < n and code[i + 1] == '/') or ch == '#':
            # `#[` is a PHP 8 attribute, not a comment — leave it.
            if ch == '#' and i + 1 < n and code[i + 1] == '[':
                out.append(ch)
                i += 1
                continue
            nl = code.find('\n', i)
            if nl == -1:
                out.append(stash(code[i:]))
                break
            out.append(stash(code[i:nl]))
            i = nl
            continue

        # Single-quoted string
        if ch == "'":
            j = i + 1
            while j < n:
                if code[j] == '\\' and j + 1 < n:
                    j += 2
                    continue
                if code[j] == "'":
                    j += 1
                    break
                j += 1
            out.append(stash(code[i:j]))
            i = j
            continue

        # Double-quoted string (may contain ${...} / {$...})
        if ch == '"':
            j = i + 1
            while j < n:
                if code[j] == '\\' and j + 1 < n:
                    j += 2
                    continue
                if code[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(stash(code[i:j]))
            i = j
            continue

        out.append(ch)
        i += 1

    return ''.join(out), restore


def _unmask(code, restore):
    # Iterate until fix-point in case placeholders contain placeholders
    # (heredoc nested in something, unlikely but safe).
    prev = None
    while prev != code:
        prev = code
        for key, val in restore.items():
            if key in code:
                code = code.replace(key, val)
    return code


# ---------------------------------------------------------------------------
# Individual transforms
# ---------------------------------------------------------------------------

def _strip_attributes(code):
    """Remove PHP 8 attributes: #[Foo], #[Foo(bar)], #[Foo, Bar]."""
    # Match `#[` up to the matching `]`, allowing one level of nested brackets.
    # Most attributes don't nest deeper than one level of args.
    pattern = re.compile(r'#\[(?:[^\[\]]|\[[^\[\]]*\])*\]')
    prev = None
    while prev != code:
        prev = code
        code = pattern.sub('', code)
    return code


def _replace_nullsafe(code):
    """Null-safe operator `?->` -> `->`."""
    return code.replace('?->', '->')


def _replace_static_closure(code):
    """`static function (...)` and `static fn(...)` -> without `static`.

    phply rejects the `static` keyword before anonymous functions.
    """
    code = re.sub(r'\bstatic\s+(function\s*(?:&\s*)?\()', r'\1', code)
    code = re.sub(r'\bstatic\s+(fn\s*\()', r'\1', code)
    return code


def _replace_arrow_fn(code):
    """`fn(params) => expr` -> `function(params) { return expr; }`.

    The tricky part is finding where `expr` ends. We match balanced
    parens/brackets/braces and stop at the first `,` or `;` or `)` / `]`
    that would close an enclosing construct.
    """
    pattern = re.compile(r'\bfn\s*\(')
    out = []
    i = 0
    n = len(code)

    while i < n:
        m = pattern.search(code, i)
        if not m:
            out.append(code[i:])
            break

        # Copy everything before the match
        out.append(code[i:m.start()])

        # Find end of the parameter list
        depth = 1
        j = m.end()
        while j < n and depth > 0:
            c = code[j]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            j += 1
        if depth != 0:
            # Malformed — give up, emit original
            out.append(code[m.start():])
            break

        params = code[m.end():j - 1]

        # Expect `=>` (allow whitespace)
        k = j
        while k < n and code[k] in ' \t\r\n':
            k += 1
        if code[k:k + 2] != '=>':
            # Not an arrow fn after all, emit original token and continue
            out.append(code[m.start():j])
            i = j
            continue
        k += 2
        while k < n and code[k] in ' \t\r\n':
            k += 1

        # Find end of expression: stop at top-level `,` `;` `)` `]` `}`
        depth_paren = 0
        depth_brack = 0
        depth_brace = 0
        e = k
        while e < n:
            c = code[e]
            if c == '(':
                depth_paren += 1
            elif c == ')':
                if depth_paren == 0 and depth_brack == 0 and depth_brace == 0:
                    break
                depth_paren -= 1
            elif c == '[':
                depth_brack += 1
            elif c == ']':
                if depth_paren == 0 and depth_brack == 0 and depth_brace == 0:
                    break
                depth_brack -= 1
            elif c == '{':
                depth_brace += 1
            elif c == '}':
                if depth_paren == 0 and depth_brack == 0 and depth_brace == 0:
                    break
                depth_brace -= 1
            elif c in ',;' and depth_paren == 0 and depth_brack == 0 and depth_brace == 0:
                break
            e += 1

        expr = code[k:e]
        out.append('function ({}) {{ return {}; }}'.format(params, expr))
        i = e

    return ''.join(out)


def _strip_type_declarations(code):
    """Remove parameter, return and property type hints.

    phply's grammar only accepts a small set of class-name type hints.
    Scalars (int/float/string/bool/void/mixed/iterable/never/self/static),
    nullable `?T`, union `A|B`, intersection `A&B` and generic class hints
    are all stripped — we just keep the variable.
    """
    code = _strip_return_types(code)
    code = _strip_param_types(code)
    code = _strip_property_types(code)
    return code


_SCALAR_TYPE = r'(?:\?\s*)?(?:\\?[A-Za-z_][A-Za-z0-9_\\]*)(?:\s*[|&]\s*(?:\\?[A-Za-z_][A-Za-z0-9_\\]*))*'


def _strip_return_types(code):
    """Strip return-type annotations only from real function signatures.

    A naive `(\\)\\s*):\\s*TYPE\\s*(?:\\{|;|=>)` regex matches ternary
    expressions like `foo() ? bar() : null;` and eats the `: null`.
    We anchor on `function` to stay inside real signatures.
    """
    pattern = re.compile(r'\bfunction\b\s*(?:&\s*)?(?:[A-Za-z_][A-Za-z0-9_]*\s*)?\(')
    out = []
    i = 0
    n = len(code)
    while i < n:
        m = pattern.search(code, i)
        if not m:
            out.append(code[i:])
            break
        out.append(code[i:m.end()])
        # Walk past the matching `)` of the param list
        depth = 1
        j = m.end()
        while j < n and depth > 0:
            c = code[j]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= n:
            out.append(code[m.end():])
            break
        out.append(code[m.end():j + 1])
        k = j + 1
        # Skip whitespace after `)`
        while k < n and code[k] in ' \t\r\n':
            k += 1
        # Only rewrite if we see `:` here (return type), not a brace/semi/=>
        if k < n and code[k] == ':':
            # Skip the `:` + whitespace
            p = k + 1
            while p < n and code[p] in ' \t\r\n':
                p += 1
            # Walk over the type, which can include `?`, scalars, union/intersection, \NS\Name
            type_pat = re.compile(_SCALAR_TYPE)
            tm = type_pat.match(code, p)
            if tm:
                # Stop once we hit `{`, `;`, or `=>`
                end_of_type = tm.end()
                out.append(' ')  # eat the `)<space>:type`
                # advance past type (but keep trailing whitespace)
                while end_of_type < n and code[end_of_type] in ' \t\r\n':
                    end_of_type += 1
                i = end_of_type
                continue
        # Otherwise nothing to strip; emit as-is
        i = k
    return ''.join(out)


def _strip_param_types(code):
    """Remove type hints inside function/method parameter lists.

    We walk `function (...)` / `fn (...)` / `__construct (...)` parameter
    lists and rewrite `[modifier] Type $var` -> `[modifier] $var`.
    Constructor property promotion (`public int $x`) is preserved as
    `public $x` so phply sees it as a property parameter it can skip.
    """
    pattern = re.compile(r'\bfunction\s*(?:&\s*)?(?:[A-Za-z_][A-Za-z0-9_]*\s*)?\(')
    out = []
    i = 0
    n = len(code)
    while i < n:
        m = pattern.search(code, i)
        if not m:
            out.append(code[i:])
            break
        out.append(code[i:m.end()])
        # Find matching close paren
        depth = 1
        j = m.end()
        while j < n and depth > 0:
            c = code[j]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        params = code[m.end():j]
        out.append(_rewrite_param_list(params))
        if j < n:
            out.append(code[j])  # the ')'
            i = j + 1
        else:
            i = j
    return ''.join(out)


def _rewrite_param_list(params):
    """Strip types from a single parameter list body.

    Split on top-level commas, rewrite each param, re-join.
    """
    parts = _split_top_level(params, ',')
    new_parts = []
    for p in parts:
        new_parts.append(_rewrite_single_param(p))
    return ','.join(new_parts)


def _split_top_level(text, sep):
    depth_paren = depth_brack = depth_brace = 0
    out = []
    start = 0
    for i, c in enumerate(text):
        if c == '(':
            depth_paren += 1
        elif c == ')':
            depth_paren -= 1
        elif c == '[':
            depth_brack += 1
        elif c == ']':
            depth_brack -= 1
        elif c == '{':
            depth_brace += 1
        elif c == '}':
            depth_brace -= 1
        elif c == sep and depth_paren == 0 and depth_brack == 0 and depth_brace == 0:
            out.append(text[start:i])
            start = i + 1
    out.append(text[start:])
    return out


_PROMO_MOD = r'(?:public|protected|private|readonly)'


def _rewrite_single_param(param):
    """Rewrite a single parameter: strip type, keep modifiers and $var."""
    if not param.strip():
        return param

    # Preserve leading whitespace / trailing whitespace
    lead = re.match(r'\s*', param).group(0)
    trail_m = re.search(r'\s*$', param)
    trail = trail_m.group(0) if trail_m else ''
    core = param[len(lead):len(param) - len(trail)] if trail else param[len(lead):]

    # Extract promotion modifiers (public/protected/private/readonly, repeatable)
    mods = []
    while True:
        m = re.match(r'(' + _PROMO_MOD + r')\b\s*', core)
        if not m:
            break
        mods.append(m.group(1))
        core = core[m.end():]

    # Drop leading type hint (anything before the first `$` or `&$` or `...$`)
    # but keep `&` and `...`.
    m = re.match(r'(&\s*|\.\.\.\s*|&\s*\.\.\.\s*|\.\.\.\s*&\s*)?', core)
    ref_or_spread = m.group(0) if m else ''
    rest = core[len(ref_or_spread):]

    # If `rest` starts with `$var`, no type to strip.
    if rest.startswith('$'):
        stripped = ref_or_spread + rest
    else:
        # Everything up to the next `$` is the type hint — drop it.
        dollar = rest.find('$')
        if dollar == -1:
            # no variable at all (e.g. just a type?) — leave param as-is
            stripped = ref_or_spread + rest
        else:
            stripped = ref_or_spread + rest[dollar:]

    # Drop modifiers entirely: phply doesn't accept public/protected/private
    # in parameter lists (constructor promotion). The property side of the
    # promotion is invisible to our taint analysis anyway.
    _ = mods
    return lead + stripped + trail


def _strip_property_types(code):
    """`public int $x;` -> `public $x;` (also for protected/private/static/readonly)."""
    pattern = re.compile(
        r'\b((?:public|protected|private)(?:\s+static)?(?:\s+readonly)?|'
        r'(?:static)(?:\s+(?:public|protected|private))?(?:\s+readonly)?|'
        r'readonly(?:\s+(?:public|protected|private))?)\s+'
        r'(?!function\b|const\b|static\b|readonly\b|abstract\b|final\b)'
        r'(?:\?\s*)?[\\A-Za-z_][\\A-Za-z0-9_]*(?:\s*[|&]\s*[\\A-Za-z_][\\A-Za-z0-9_]*)*'
        r'\s+(\$)'
    )
    return pattern.sub(r'\1 \2', code)


def _strip_readonly_keyword(code):
    """Remove bare `readonly ` modifier if it survived earlier passes."""
    return re.sub(r'\breadonly\s+(?=\$|public\b|protected\b|private\b|static\b)', '', code)


def _replace_numeric_separator(code):
    """`1_000_000` -> `1000000`."""
    return re.sub(r'\b(\d+(?:_\d+)+)\b',
                  lambda m: m.group(1).replace('_', ''),
                  code)


def _replace_match_expression(code):
    """Rewrite `match (expr) { ... }` into a ternary chain.

    Best-effort: only handles single-condition arms without commas in the
    match value. Multi-condition arms fall through to a simpler form.

    On anything that looks too complex we leave the original text and let
    phply fail — this is no worse than the status quo.
    """
    pattern = re.compile(r'\bmatch\s*\(')
    out = []
    i = 0
    n = len(code)
    while i < n:
        m = pattern.search(code, i)
        if not m:
            out.append(code[i:])
            break
        out.append(code[i:m.start()])

        # Find subject
        depth = 1
        j = m.end()
        while j < n and depth > 0:
            c = code[j]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            j += 1
        if depth != 0:
            out.append(code[m.start():])
            break
        subject = code[m.end():j - 1]

        # Skip whitespace
        k = j
        while k < n and code[k] in ' \t\r\n':
            k += 1
        if k >= n or code[k] != '{':
            out.append(code[m.start():k])
            i = k
            continue
        # Find matching }
        depth = 1
        e = k + 1
        while e < n and depth > 0:
            c = code[e]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    break
            e += 1
        if depth != 0:
            out.append(code[m.start():])
            break
        body = code[k + 1:e]

        try:
            ternary = _match_body_to_ternary(subject, body)
            out.append(ternary)
            i = e + 1
        except _MatchTooComplex:
            # leave original untouched
            out.append(code[m.start():e + 1])
            i = e + 1

    return ''.join(out)


class _MatchTooComplex(Exception):
    pass


def _match_body_to_ternary(subject, body):
    """Convert match arms into nested ternaries.

    Grammar we accept per arm:
        <expr>[, <expr>...] => <expr>
        default => <expr>
    Separated by `,`.
    """
    # Trim trailing comma
    body = body.strip()
    if body.endswith(','):
        body = body[:-1]
    arms = _split_top_level(body, ',')
    # `,` also separates arm conditions — we must re-group by `=>`.
    # Re-parse: walk arms, collecting until we see `=>`, then take value.
    # Simpler: split body into arms by finding `=> <value>,` boundaries
    # at top level.
    arms = _split_match_arms(body)
    default_expr = None
    pairs = []
    for conds, value in arms:
        conds = [c.strip() for c in conds]
        value = value.strip()
        if len(conds) == 1 and conds[0] == 'default':
            default_expr = value
            continue
        for c in conds:
            pairs.append((c, value))
    if default_expr is None:
        default_expr = 'null'
    expr = default_expr
    for cond, value in reversed(pairs):
        expr = '(({}) === ({}) ? ({}) : ({}))'.format(subject, cond, value, expr)
    return expr


def _split_match_arms(body):
    """Split `cond1, cond2 => value, cond3 => value2` into list of (conds, value)."""
    arms = []
    i = 0
    n = len(body)
    conds_buf = []
    cond_start = 0
    depth_paren = depth_brack = depth_brace = 0

    def at_top():
        return depth_paren == 0 and depth_brack == 0 and depth_brace == 0

    while i < n:
        c = body[i]
        if c == '(':
            depth_paren += 1
        elif c == ')':
            depth_paren -= 1
        elif c == '[':
            depth_brack += 1
        elif c == ']':
            depth_brack -= 1
        elif c == '{':
            depth_brace += 1
        elif c == '}':
            depth_brace -= 1
        elif c == ',' and at_top():
            conds_buf.append(body[cond_start:i])
            cond_start = i + 1
        elif c == '=' and i + 1 < n and body[i + 1] == '>' and at_top():
            conds_buf.append(body[cond_start:i])
            i += 2
            # Find end of value: top-level `,` or end
            val_start = i
            while i < n:
                c2 = body[i]
                if c2 == '(':
                    depth_paren += 1
                elif c2 == ')':
                    depth_paren -= 1
                elif c2 == '[':
                    depth_brack += 1
                elif c2 == ']':
                    depth_brack -= 1
                elif c2 == '{':
                    depth_brace += 1
                elif c2 == '}':
                    depth_brace -= 1
                elif c2 == ',' and at_top():
                    break
                i += 1
            value = body[val_start:i]
            arms.append((list(conds_buf), value))
            conds_buf = []
            cond_start = i + 1
        i += 1
    return arms


def _rewrite_power_operator(code):
    """`a ** b` -> `pow(a, b)`.

    phply does not recognise the `**` power operator (PHP 5.6+).
    We only handle simple operands: a literal number, a variable or a
    chained member/index access. If the operand is a complex expression
    we just wrap it in parens based on what the surrounding tokens hint
    at; worst case phply still rejects the file.
    """
    pattern = re.compile(r'(\*\*)(?!=)')  # `**=` is handled elsewhere
    rewrites = []
    for m in pattern.finditer(code):
        # Walk back to find start of left operand
        i = m.start() - 1
        while i >= 0 and code[i] in ' \t\r\n':
            i -= 1
        left_end = i + 1
        left_start = _walk_operand_back(code, i)
        # Walk forward to find end of right operand
        j = m.end()
        while j < len(code) and code[j] in ' \t\r\n':
            j += 1
        right_start = j
        right_end = _walk_operand_forward(code, j)
        left_text = code[left_start:left_end].strip()
        right_text = code[right_start:right_end].strip()
        if not left_text or not right_text:
            continue
        rewrites.append((left_start, right_end,
                         'pow({}, {})'.format(left_text, right_text)))

    if not rewrites:
        return code
    # Non-overlapping by left-to-right construction
    out = []
    pos = 0
    for start, stop, rep in rewrites:
        if start < pos:
            continue
        out.append(code[pos:start])
        out.append(rep)
        pos = stop
    out.append(code[pos:])
    return ''.join(out)


def _walk_operand_back(code, start):
    """Walk backward from `start` to find the beginning of an operand."""
    i = start
    # Could be inside parens
    if i >= 0 and code[i] == ')':
        depth = 1
        i -= 1
        while i >= 0 and depth > 0:
            if code[i] == ')':
                depth += 1
            elif code[i] == '(':
                depth -= 1
            i -= 1
        # Continue walking past any function name before the paren
        while i >= 0 and (code[i].isalnum() or code[i] in '_$\\'):
            i -= 1
        return i + 1
    # Plain identifier / number / variable
    while i >= 0:
        c = code[i]
        if c.isalnum() or c in '_$.\\':
            i -= 1
        elif c == ']':
            d = 1
            i -= 1
            while i >= 0 and d > 0:
                if code[i] == ']':
                    d += 1
                elif code[i] == '[':
                    d -= 1
                i -= 1
        elif c == '>' and i >= 1 and code[i - 1] == '-':
            i -= 2
        elif c == ':' and i >= 1 and code[i - 1] == ':':
            i -= 2
        else:
            break
    return i + 1


def _walk_operand_forward(code, start):
    """Walk forward from `start` to find the end of an operand."""
    i = start
    n = len(code)
    # Leading unary sign
    if i < n and code[i] in '+-':
        i += 1
    # Numeric literal or identifier/variable chain
    while i < n:
        c = code[i]
        if c.isalnum() or c in '_$.\\':
            i += 1
        elif c == '(':
            d = 1
            i += 1
            while i < n and d > 0:
                if code[i] == '(':
                    d += 1
                elif code[i] == ')':
                    d -= 1
                i += 1
        elif c == '[':
            d = 1
            i += 1
            while i < n and d > 0:
                if code[i] == '[':
                    d += 1
                elif code[i] == ']':
                    d -= 1
                i += 1
        elif c == '-' and i + 1 < n and code[i + 1] == '>':
            i += 2
        elif c == ':' and i + 1 < n and code[i + 1] == ':':
            i += 2
        else:
            break
    return i


def _rewrite_reserved_class_const(code):
    """`Foo::NAMESPACE` -> `Foo::_NAMESPACE` and similar for other
    PHP reserved words that can appear as class constants.

    phply's grammar treats these as keywords, so an identifier collision
    after `::` aborts the parse.
    """
    reserved = ('NAMESPACE', 'FUNCTION', 'CONST', 'ENDIF', 'ENDWHILE',
                'ENDFOREACH', 'ENDFOR', 'ENDSWITCH', 'FINALLY', 'MATCH',
                'READONLY', 'PRINT', 'ECHO', 'FN')
    for word in reserved:
        code = re.sub(r'(::)(' + word + r')\b', r'\1_\2', code)
    return code


def _rename_reserved_methods(code):
    """Rename `function finally` / `function match` etc. to `_finally`.

    phply's grammar rejects reserved keywords as method identifiers in
    definitions. Call sites like `$x->finally()` are fine. We only
    touch the definition site, so callers still resolve at runtime —
    they just won't match in taint tracking, which is acceptable for
    these rare method names.
    """
    reserved = ('finally', 'match', 'fn', 'readonly', 'new', 'print',
                'echo', 'use')
    for word in reserved:
        code = re.sub(r'(\bfunction\s+)' + word + r'(?=\s*\()',
                      r'\1_' + word,
                      code)
    return code


def _strip_use_function_const(code):
    """`use function foo;` -> `use foo;` and `use const BAR;` -> `use BAR;`.

    phply doesn't recognise the `function`/`const` qualifier on use
    imports (PHP 5.6+).
    """
    code = re.sub(r'(\buse\s+)function\s+', r'\1', code)
    code = re.sub(r'(\buse\s+)const\s+', r'\1', code)
    return code


def _replace_null_coalescing(code):
    """`a ?? b` -> `a ?: b` (Elvis).

    Not semantically identical (`??` tests null, `?:` tests truthy) but
    for taint-tracking both branches still carry the same flow. Also
    rewrites the assign form `??=`.
    """
    code = re.sub(r'\?\?=', '=', code)  # a ??= b  ->  a = b (approximation)
    code = code.replace('??', '?:')
    return code


def _strip_spread_in_args(code):
    """Strip `...` before args / variadic params.

    Covers both `foo(...$args)` / `foo(...expr())` (spread) and
    `function bar(...$args)` (variadic declaration). phply rejects both.
    Reference-variadic `&...$args` also stripped.
    """
    # Cover `...$v`, `...func(`, `...Foo::x`, `&...$v`, etc.
    return re.sub(r'(\(|,)\s*&?\s*\.\.\.\s*(?=[\w$\\])', r'\1', code)


def _rewrite_immediate_new_invoke(code):
    """`(new Foo(...))(args)` -> `call_user_func(new Foo(...), args)`.

    Immediate invocation of an object that implements __invoke was added
    in PHP 7.0; phply chokes on `)(`.
    """
    pattern = re.compile(r'\(\s*new\s+')
    out = []
    i = 0
    n = len(code)
    while i < n:
        m = pattern.search(code, i)
        if not m:
            out.append(code[i:])
            break
        out.append(code[i:m.start()])

        # Find matching outer ')'
        depth = 1
        j = m.end()
        while j < n and depth > 0:
            c = code[j]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if depth != 0 or j >= n:
            out.append(code[m.start():])
            break

        # Check what follows ')'
        k = j + 1
        while k < n and code[k] in ' \t\r\n':
            k += 1
        if k >= n or code[k] != '(':
            out.append(code[m.start():j + 1])
            i = j + 1
            continue

        # Find end of invocation arg list
        arg_start = k + 1
        depth = 1
        e = arg_start
        while e < n and depth > 0:
            c = code[e]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    break
            e += 1
        if depth != 0:
            out.append(code[m.start():])
            break

        new_expr = code[m.start() + 1:j]  # strip outer `(` but keep `new Foo(...)`
        # Actually m.start() is the outer `(`. m.start()+1 starts at whitespace.
        # We want `new Foo(...)` — everything between outer `(` and its `)`.
        inner_new = code[m.start() + 1:j].strip()
        call_args = code[arg_start:e]
        if call_args.strip():
            replacement = 'call_user_func({}, {})'.format(inner_new, call_args)
        else:
            replacement = 'call_user_func({})'.format(inner_new)
        out.append(replacement)
        i = e + 1

    return ''.join(out)


def _rewrite_array_destructuring(code):
    """Array destructuring rewrite.

    Positional: `[$a, $b] = $arr;` -> `list($a, $b) = $arr;`.
    Keyed:      `['k' => $a, 'j' => $b] = $arr;`
                -> `$a = $arr['k']; $b = $arr['j'];`
                (phply does not accept keyed `list()`).

    Only rewrites when `[` appears at the start of a statement AND the
    matching `]` is followed by `=` (not `==`/`===`/`=>`).
    """
    rewrites = []
    n = len(code)
    safe_prefix = set(';{}(,\n\t ')

    i = 0
    while i < n:
        if code[i] != '[':
            i += 1
            continue
        k = i - 1
        while k >= 0 and code[k] in ' \t\r\n':
            k -= 1
        prev = code[k] if k >= 0 else ''
        if prev not in safe_prefix and k >= 0:
            i += 1
            continue
        # Find matching `]`
        depth = 1
        j = i + 1
        while j < n and depth > 0:
            c = code[j]
            if c == '[':
                depth += 1
            elif c == ']':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if depth != 0:
            i += 1
            continue
        # Check `=` follows
        p = j + 1
        while p < n and code[p] in ' \t\r\n':
            p += 1
        if p >= n or code[p] != '=' or (p + 1 < n and code[p + 1] in '=>'):
            i += 1
            continue
        # Walk through RHS to find the statement terminator
        q = p + 1
        depth_p = depth_b = depth_c = 0
        while q < n:
            c = code[q]
            if c == '(':
                depth_p += 1
            elif c == ')':
                depth_p -= 1
            elif c == '[':
                depth_b += 1
            elif c == ']':
                depth_b -= 1
            elif c == '{':
                depth_c += 1
            elif c == '}':
                depth_c -= 1
            elif c == ';' and depth_p == 0 and depth_b == 0 and depth_c == 0:
                break
            q += 1
        if q >= n:
            i += 1
            continue

        inner = code[i + 1:j]
        rhs = code[p + 1:q].strip()

        # Detect keyed form (look for ` => ` at top level in inner)
        if _has_top_level_arrow(inner):
            # Use a temp var so we don't emit `(RHS)['key']` which phply
            # rejects. `$_km_d = RHS; $var = $_km_d[key];`
            pieces = _split_top_level(inner, ',')
            tmp = '$_km_destr_{}'.format(len(rewrites))
            assigns = ['{} = {}'.format(tmp, rhs)]
            for piece in pieces:
                piece = piece.strip()
                if not piece:
                    continue
                arrow_pos = _find_top_level_arrow(piece)
                if arrow_pos < 0:
                    assigns.append('{} = {}[0]'.format(piece, tmp))
                else:
                    key = piece[:arrow_pos].strip()
                    var = piece[arrow_pos + 2:].strip()
                    assigns.append('{} = {}[{}]'.format(var, tmp, key))
            replacement = '; '.join(assigns)
            rewrites.append((i, q, replacement))
            i = q + 1
        else:
            replacement = 'list({}) = {}'.format(inner, rhs)
            rewrites.append((i, q, replacement))
            i = q + 1

    if not rewrites:
        return code
    out = []
    pos = 0
    for start, stop, rep in rewrites:
        out.append(code[pos:start])
        out.append(rep)
        pos = stop
    out.append(code[pos:])
    return ''.join(out)


def _has_top_level_arrow(text):
    return _find_top_level_arrow(text) >= 0


def _find_top_level_arrow(text):
    depth_p = depth_b = depth_c = 0
    i = 0
    n = len(text)
    while i < n - 1:
        c = text[i]
        if c == '(':
            depth_p += 1
        elif c == ')':
            depth_p -= 1
        elif c == '[':
            depth_b += 1
        elif c == ']':
            depth_b -= 1
        elif c == '{':
            depth_c += 1
        elif c == '}':
            depth_c -= 1
        elif c == '=' and text[i + 1] == '>' and depth_p == 0 and depth_b == 0 and depth_c == 0:
            return i
        i += 1
    return -1


def _strip_visibility_on_class_const(code):
    """`public const X = 1;` -> `const X = 1;`.

    phply accepts bare `const` class constants but not PHP 7.1+ visibility
    modifiers on them.
    """
    return re.sub(r'\b(public|protected|private)\s+(const\b)', r'\2', code)


_CAST_KEYWORDS = {'int', 'integer', 'float', 'double', 'real', 'string',
                  'bool', 'boolean', 'array', 'object', 'unset', 'binary'}


def _rewrite_callable_on_call_result(code):
    """`expr()(args)` -> `call_user_func(expr(), args)`.

    Handles method/function-call-result invocation (PHP 7.0+) such as:
        $obj->get()($x)
        give(Foo::class)($x)
    Does NOT touch casts like `(int)$x`.

    The scan collects a list of (start, end, replacement) rewrites across
    the whole file, then applies them all at once to keep indices valid.
    """
    n = len(code)
    rewrites = []

    i = 0
    while i < n:
        if code[i] != ')':
            i += 1
            continue

        # Look ahead for `(`
        j = i + 1
        while j < n and code[j] in ' \t\r\n':
            j += 1
        if j >= n or code[j] != '(':
            i += 1
            continue

        # Balance back to the matching `(` of this call
        depth = 1
        k = i - 1
        while k >= 0 and depth > 0:
            c = code[k]
            if c == ')':
                depth += 1
            elif c == '(':
                depth -= 1
                if depth == 0:
                    break
            k -= 1
        if depth != 0:
            i += 1
            continue

        # Guard: is this `(xxx)` actually a type cast like `(int)`?
        inner = code[k + 1:i].strip()
        if inner.lower() in _CAST_KEYWORDS:
            i += 1
            continue

        # Walk further back to capture the whole receiver expression start
        s = k - 1
        while s >= 0:
            c = code[s]
            if c.isalnum() or c in '_$':
                s -= 1
            elif c == '\\':
                s -= 1
            elif c == '>' and s >= 1 and code[s - 1] == '-':
                s -= 2
            elif c == ':' and s >= 1 and code[s - 1] == ':':
                s -= 2
            elif c == ']':
                d = 1
                s -= 1
                while s >= 0 and d > 0:
                    if code[s] == ']':
                        d += 1
                    elif code[s] == '[':
                        d -= 1
                    s -= 1
            elif c == ')':
                d = 1
                s -= 1
                while s >= 0 and d > 0:
                    if code[s] == ')':
                        d += 1
                    elif code[s] == '(':
                        d -= 1
                    s -= 1
            else:
                break
        expr_start = s + 1
        expr_end = i + 1  # include the `)`
        callee = code[expr_start:expr_end].strip()
        if not callee:
            i += 1
            continue

        # Walk the invocation `(args)` block
        depth2 = 1
        e = j + 1
        while e < n and depth2 > 0:
            c = code[e]
            if c == '(':
                depth2 += 1
            elif c == ')':
                depth2 -= 1
                if depth2 == 0:
                    break
            e += 1
        if depth2 != 0:
            i += 1
            continue

        args = code[j + 1:e]
        if args.strip():
            replacement = 'call_user_func({}, {})'.format(callee, args)
        else:
            replacement = 'call_user_func({})'.format(callee)
        rewrites.append((expr_start, e + 1, replacement))
        i = e + 1

    if not rewrites:
        return code

    # Apply rewrites (non-overlapping by construction) in order
    out = []
    pos = 0
    for start, stop, rep in rewrites:
        if start < pos:
            continue  # shouldn't happen
        out.append(code[pos:start])
        out.append(rep)
        pos = stop
    out.append(code[pos:])
    return ''.join(out)


def _strip_first_class_callable(code):
    """`strlen(...)` first-class callable -> 'strlen' string literal.

    This is a lossy rewrite but prevents phply from choking on `(...)`.
    Only applied when the arg list is exactly `...`.
    """
    return re.sub(r'\(\s*\.\.\.\s*\)', '()', code)


def _strip_enum_declarations(code):
    """Replace `enum Foo ... {}` with an empty `class Foo {}` so the
    symbol table still records it. `case` inside enums becomes a const-like
    stub.
    """
    pattern = re.compile(r'\benum\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*:\s*[A-Za-z_][A-Za-z0-9_]*)?'
                         r'(?:\s+implements\s+[^\{]+)?\s*\{')
    out = []
    i = 0
    n = len(code)
    while i < n:
        m = pattern.search(code, i)
        if not m:
            out.append(code[i:])
            break
        out.append(code[i:m.start()])
        name = m.group(1)
        # find matching }
        depth = 1
        j = m.end()
        while j < n and depth > 0:
            c = code[j]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        # replace body, drop `case X;` entirely (phply has no enum concept)
        out.append('class {} {{ }}'.format(name))
        i = j + 1 if j < n else j
    return ''.join(out)


def _replace_named_args(code):
    """`foo(name: value)` -> `foo(value)` (drop the label).

    phply doesn't support named arguments. Losing the name is fine for
    taint tracking since we match by position too.
    """
    # Match `identifier :` but NOT inside `::` or `?:` or ternary `: x`
    # Applied only inside argument-list-looking contexts.
    # Regex: `( or , followed by space(s) followed by name: (not ::)`
    return re.sub(r'([(,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:(?!=|:)\s*',
                  r'\1', code)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def normalize(code):
    """Apply the full transform pipeline. Safe to call on already-valid code.

    Order matters:
      1. Mask strings / comments so we don't mangle their contents.
      2. Strip PHP 8 attributes (`#[...]`).
      3. Numeric separators (`1_000`).
      4. `static function` / `static fn` -> plain closures.
      5. Arrow functions (`fn()=>`).
      6. Null-safe `?->` -> `->`.
      7. Type declarations on return, params, properties.
      8. Enums -> empty classes (also swallows `case` lines).
      9. Match expressions -> nested ternaries.
     10. Named arguments -> positional.
     11. First-class callables `foo(...)` -> `foo()`.
     12. `readonly` leftovers.
     13. Unmask.
    """
    if not code:
        return code
    masked, restore = _mask_literals(code)
    masked = _strip_attributes(masked)
    masked = _replace_numeric_separator(masked)
    masked = _replace_static_closure(masked)
    prev = None
    while prev != masked:
        prev = masked
        masked = _replace_arrow_fn(masked)
    masked = _replace_nullsafe(masked)
    masked = _strip_enum_declarations(masked)
    masked = _replace_match_expression(masked)
    masked = _strip_type_declarations(masked)
    masked = _strip_visibility_on_class_const(masked)
    masked = _replace_named_args(masked)
    masked = _strip_use_function_const(masked)
    masked = _replace_null_coalescing(masked)
    masked = _strip_spread_in_args(masked)
    masked = _rewrite_power_operator(masked)
    masked = _rewrite_reserved_class_const(masked)
    masked = _rename_reserved_methods(masked)
    masked = _rewrite_array_destructuring(masked)
    # Apply callable-on-call rewrite until stable (may cascade)
    prev = None
    while prev != masked:
        prev = masked
        masked = _rewrite_callable_on_call_result(masked)
    masked = _strip_first_class_callable(masked)
    masked = _strip_readonly_keyword(masked)
    return _unmask(masked, restore)
